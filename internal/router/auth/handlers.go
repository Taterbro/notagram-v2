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
	GetUserByID(ctx context.Context, id uuid.UUID) (models.User, error)
	CreateUser(ctx context.Context, arg models.CreateUserParams) (models.User, error)
	CreateEncryption(ctx context.Context, arg models.CreateEncryptionParams) (models.UserEncryption, error)
	UpdateUserPassword(ctx context.Context, arg models.UpdateUserPasswordParams) error
	UpdateEncryption(ctx context.Context, arg models.UpdateEncryptionParams) error
	DeleteUserByID(ctx context.Context, id uuid.UUID) error
	GetEncryptionByID(ctx context.Context, id uuid.UUID) (models.UserEncryption, error)
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
	RecoveryPhrase        string       `json:"recovery_phrase" binding:"required"`
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
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
}

type SigninResponse struct {
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	MasterKey    string       `json:"master_key"`
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
		recoveryHash, err := bcrypt.GenerateFromPassword([]byte(req.RecoveryPhrase), 12)
		if err != nil {
			slog.Error("error while hashing recovery phrase", "bcryptError", err)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}
		createdUser, err := h.q.CreateUser(c, models.CreateUserParams{Email: strings.ToLower(req.Email), Moniker: sql.NullString{String: req.Moniker, Valid: true}, PasswordHash: string(bytes)})
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

		_, err = h.q.CreateEncryption(c, models.CreateEncryptionParams{UserID: createdUser.ID, PasswordSalt: req.PasswordSalt, PasswordParams: j, EncryptedMasterKeyPw: req.EncryptedMasterKeyPW, RecoverySalt: req.RecoverySalt, RecoveryParams: r, EncryptedMasterKeyRec: req.EncryptedMasterKeyRec, RecoveryHash: string(recoveryHash)})
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
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		api.Success(c, http.StatusCreated, resp)
		return
	}

	slog.Error("unexpected error while checking for existing user", "err", err)
	api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
}

type SigninBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h Handler) Signin(c *gin.Context) {
	var req SigninBody
	if err := c.ShouldBindJSON(&req); err != nil {
		errs := utils.FormatValidationErrors(err)
		api.Error(c, http.StatusBadRequest, "invalid body", errs)
		return
	}

	user, err := h.q.GetUserByEmail(c, strings.ToLower(req.Email))
	if errors.Is(err, sql.ErrNoRows) {
		api.Error(c, http.StatusUnauthorized, "invalid email or password", nil)
		return
	}
	if err != nil {
		slog.Error("unexpected error while fetching user for signin", "err", err, "user_email", strings.ToLower(req.Email))
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}
	encryption, err := h.q.GetEncryptionByID(c, user.ID)
	if err != nil {
		slog.Error("error getting user encryption", "err", err, "user_id", user.ID)
		api.Error(c, 400, "error getting user credentials", nil)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		api.Error(c, http.StatusUnauthorized, "invalid email or password", nil)
		return
	}

	accessToken, err := auth_service.GenerateUserToken(user.ID, *h.cfg, auth_service.Accesss)
	if err != nil {
		slog.Error("error while generating access token", "err", err, "user_id", user.ID)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	refreshToken, err := auth_service.GenerateUserToken(user.ID, *h.cfg, auth_service.Refresh)
	if err != nil {
		slog.Error("error while generating refresh token", "err", err, "user_id", user.ID)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	moniker := ""
	if user.Moniker.Valid {
		moniker = user.Moniker.String
	}

	resp := SigninResponse{
		User: UserResponse{
			ID:        user.ID.String(),
			Email:     user.Email,
			Moniker:   moniker,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		MasterKey:    encryption.EncryptedMasterKeyPw,
	}

	api.Success(c, http.StatusOK, resp)
}

func (h Handler) Refresh(c *gin.Context) {
	userID, ok := c.Get("user_id")
	if !ok {
		api.Error(c, http.StatusUnauthorized, "missing user id", nil)
		return
	}

	accessToken, err := auth_service.GenerateUserToken(userID.(uuid.UUID), *h.cfg, auth_service.Accesss)
	if err != nil {
		slog.Error("error while generating access token", "err", err, "user_id", userID)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	api.Success(c, http.StatusOK, map[string]string{"access_token": accessToken})
}

type LogoutBody struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type UpdatePasswordBody struct {
	CurrentPassword         string       `json:"current_password" binding:"required"`
	NewPassword             string       `json:"new_password" binding:"required,min=8"`
	NewPasswordSalt         string       `json:"new_password_salt" binding:"required"`
	NewPasswordParams       CryptoParams `json:"new_password_params" binding:"required"`
	NewEncryptedMasterKeyPw string       `json:"new_encrypted_master_key_pw" binding:"required"`
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

func (h Handler) UpdatePassword(c *gin.Context) {
	userID, ok := c.Get("user_id")
	if !ok {
		api.Error(c, http.StatusUnauthorized, "missing user id", nil)
		return
	}

	var req UpdatePasswordBody
	if err := c.ShouldBindJSON(&req); err != nil {
		errs := utils.FormatValidationErrors(err)
		api.Error(c, http.StatusBadRequest, "invalid body", errs)
		return
	}

	user, err := h.q.GetUserByID(c, userID.(uuid.UUID))
	if errors.Is(err, sql.ErrNoRows) {
		api.Error(c, http.StatusNotFound, "user not found", nil)
		return
	}
	if err != nil {
		slog.Error("error while fetching user for password update", "err", err, "user_id", userID)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		api.Error(c, http.StatusBadRequest, "current password is incorrect", nil)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		slog.Error("error while hashing new password", "bcryptError", err)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	params, err := json.Marshal(req.NewPasswordParams)
	if err != nil {
		slog.Error("error while marshalling new password params to json", "marshall_error", err)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	if err := h.q.UpdateUserPassword(c, models.UpdateUserPasswordParams{ID: user.ID, PasswordHash: string(newHash)}); err != nil {
		slog.Error("error while updating user password", "db_error", err, "user_id", user.ID)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	err = h.q.UpdateEncryption(c, models.UpdateEncryptionParams{UserID: user.ID, PasswordSalt: req.NewPasswordSalt, PasswordParams: params, EncryptedMasterKeyPw: req.NewEncryptedMasterKeyPw})
	if err != nil {
		rollbackErr := h.q.UpdateUserPassword(c, models.UpdateUserPasswordParams{ID: user.ID, PasswordHash: user.PasswordHash})
		if rollbackErr != nil {
			slog.Error("failed to restore password hash after encryption update failure", "err", rollbackErr, "user_id", user.ID)
		}
		slog.Error("error while updating user encryption keys", "db_error", err, "user_id", user.ID)
		api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h Handler) GetRecoveryKey(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		api.Error(c, http.StatusBadRequest, "no email in query params", nil)
		return
	}
	user, err := h.q.GetUserByEmail(c, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			api.Success(c, http.StatusOK, map[string]string{"recovery_master_key": uuid.NewString()})
			return
		} else {
			slog.Error("error while getting user by email", "err", err)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}
	}
	recovery, err := h.q.GetEncryptionByID(c, user.ID)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			slog.Info("missing encryption data??", "user_id", recovery.UserID)
			api.Error(c, http.StatusNotFound, "no user encryption data found for some reason", nil)
			return
		} else {
			slog.Error("error while getting user's encryption data", "err", err)
			api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			return
		}
	}
	api.Success(c, http.StatusOK, map[string]string{"recovery_master_key": recovery.EncryptedMasterKeyRec})
}

type RecoverPasswordBody struct {
	Email                   string       `json:"email" binding:"required,email"`
	NewPassword             string       `json:"new_password" binding:"required,min=8"`
	NewPasswordSalt         string       `json:"new_password_salt" binding:"required"`
	NewPasswordParams       CryptoParams `json:"new_password_params" binding:"required"`
	NewEncryptedMasterKeyPw string       `json:"new_encrypted_master_key_pw" binding:"required"`
}
