package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Taterbro/notagram-v2/internal/api"
	auth_service "github.com/Taterbro/notagram-v2/internal/auth"
	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/db/models"
	"github.com/Taterbro/notagram-v2/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	//"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type RedisClient interface {
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
}

type UserQuery interface {
	GetUserByEmail(ctx context.Context, email string) (models.User, error)
	CreateUser(ctx context.Context, arg models.CreateUserParams) (models.User, error)
	CreateEncryption(ctx context.Context, arg models.CreateEncryptionParams) (models.UserEncryption, error)
	DeleteUserByID(ctx context.Context, id uuid.UUID) error
}

type Handler struct {
	cfg   *config.Config
	q     UserQuery
	redis RedisClient
}

func NewHandler(cfg *config.Config, q UserQuery, redis RedisClient) *Handler {
	return &Handler{
		cfg:   cfg,
		q:     q,
		redis: redis,
	}
}

type CryptoParams struct {
	Memory      int `json:"memory"`
	Iterations  int `json:"iterations"`
	Parallelism int `json:"parallelism"`
	Version     int `json:"version"`
}

type SignupBody struct {
	Email                 string       `json:"email" binding:"required,email"`
	Moniker               string       `json:"moniker"`
	Password              string       `json:"password" binding:"required,min=8"`
	PasswordSalt          string       `json:"password_salt" binding:"required"`
	PasswordParams        CryptoParams `json:"password_params" binding:"required"`
	EncryptedMasterKeyPW  string       `json:"encrypted_master_key_pw" binding:"required"`
	RecoverySalt          string       `json:"recovery_salt" binding:"required"`
	RecoveryParams        CryptoParams `json:"recovery_params" binding:"required"`
	EncryptedMasterKeyRec string       `json:"encrypted_master_key_rec" binding:"required"`
}
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Moniker   string `json:"moniker"`
	CreatedAt string `json:"created_at"`
}

type SignupResponse struct {
	User          UserResponse `json:"user"`
	AccessToken   string       `json:"access_token"`
	RefreshToken  string       `json:"refresh_token"`
	AccountActive bool         `json:"account_active"`
}

func (h Handler) Signup(c *gin.Context) {
	var req SignupBody
	if err := c.ShouldBindJSON(&req); err != nil {
		errs := utils.FormatValidationErrors(err)
		api.Error(c, http.StatusBadRequest, "invalid body", errs)
		return
	}

	formattedEmail := strings.ToLower(req.Email)
	_, err := h.q.GetUserByEmail(c, formattedEmail)
	if err == nil {
		api.Error(c, http.StatusBadRequest, "email already exists; login instead", nil)
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		bytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			slog.Error("error while hashing user password", "bcryptError", err)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}
		createdUser, err := h.q.CreateUser(c, models.CreateUserParams{Email: req.Email, Moniker: sql.NullString{String: req.Moniker, Valid: true}, PasswordHash: string(bytes)})
		if err != nil {
			slog.Error("error while creating user account", "db_error", err, "user_email", req.Email, "user_moniker", req.Moniker, "password_hash", string(bytes))
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}
		j, err := json.Marshal(req.PasswordParams)
		if err != nil {
			slog.Error("error while marshalling user password params to json", "marshall_error", err)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}

		r, err := json.Marshal(req.RecoveryParams)
		if err != nil {
			slog.Error("error while marshalling user recovery params to json", "marshall_error", err)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}

		_, err = h.q.CreateEncryption(c, models.CreateEncryptionParams{UserID: createdUser.ID, PasswordSalt: req.PasswordSalt, PasswordParams: j, EncryptedMasterKeyPw: req.EncryptedMasterKeyPW, RecoverySalt: req.RecoverySalt, RecoveryParams: r, EncryptedMasterKeyRec: req.EncryptedMasterKeyRec})
		if err != nil {
			err = h.q.DeleteUserByID(c, createdUser.ID)
			if err != nil {
				slog.Error("failed to delete user data after encryption key failure", "err", err, "user_id", createdUser.ID)
			}
			slog.Error("error while creating user encryption keys", "db_error", err, "user_id", createdUser.ID)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}
		accessToken, err := auth_service.GenerateUserToken(createdUser.ID, *h.cfg, auth_service.Accesss)
		if err != nil {
			slog.Error("error while generating access token", "err", err, "user_id", createdUser.ID)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}

		refreshToken, err := auth_service.GenerateUserToken(createdUser.ID, *h.cfg, auth_service.Refresh)
		if err != nil {
			slog.Error("error while generating refresh token", "err", err, "user_id", createdUser.ID)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}

		moniker := ""
		if createdUser.Moniker.Valid {
			moniker = createdUser.Moniker.String
		}

		resp := SignupResponse{
			User: UserResponse{
				ID:        createdUser.ID.String(),
				Email:     createdUser.Email,
				Moniker:   moniker,
				CreatedAt: createdUser.CreatedAt.Format(time.RFC3339),
			},
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			AccountActive: createdUser.AccountActive,
		}

		api.Success(c, http.StatusCreated, resp)
		return
	}

	slog.Error("unexpected error while checking for existing user", "err", err)
	api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
}

func (h Handler) Login(c *gin.Context) {
	api.Success(c, http.StatusOK, map[string]string{"url": "some random bs fr", "message": "open the url in your browser"})
}

type TokenValidator interface {
	ValidateToken(tokenString string, cfg config.Config) (*jwt.Token, error)
}
type LogoutBody struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h Handler) Logout(c *gin.Context) {
	exp := c.GetFloat64("exp")
	jti := c.GetString("jti")
	ttl := time.Until(time.Unix(int64(exp), 0))

	if err := h.redis.Set(c.Request.Context(), jti, "revoked", ttl).Err(); err != nil {
		slog.Error("failed to revoke token in redis", "err", err, "jti", jti)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	api.Success(c, http.StatusOK, nil)
}
