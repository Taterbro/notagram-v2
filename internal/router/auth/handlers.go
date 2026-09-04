package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Taterbro/notagram-v2/internal/api"
	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/db/models"
	"github.com/Taterbro/notagram-v2/internal/utils"
	"github.com/gin-gonic/gin"

	//"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	cfg *config.Config
	db  *sql.DB
}

func NewHandler(cfg *config.Config, db *sql.DB) *Handler {
	return &Handler{
		cfg: cfg,
		db:  db,
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

func (h Handler) Signup(c *gin.Context) {
	var req SignupBody
	if err := c.ShouldBindJSON(&req); err != nil {
		errs := utils.FormatValidationErrors(err)
		api.Error(c, http.StatusBadRequest, "invalid body", errs)
		return
	}

	q := models.New(h.db)
	formattedEmail := strings.ToLower(req.Email)
	_, err := q.GetUserByEmail(c, formattedEmail)
	if err == nil {
		api.Error(c, http.StatusBadRequest, "email already exists; login instead", nil)
		return
	} else {
		if errors.Is(err, sql.ErrNoRows) {
			bytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
			if err != nil {
				slog.Error("error while hashing user password", "bcryptError", err)
				api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
				return
			}
			createdUser, err := q.CreateUser(c, models.CreateUserParams{Email: req.Email, Moniker: sql.NullString{String: req.Moniker}, PasswordHash: string(bytes)})
			if err != nil {
				slog.Error("error while creating user account", "db_error", err, "user_email", req.Email, "user_moniker", req.Moniker, "password_hash", string(bytes))
				api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
				return
			}
			j, err := json.Marshal(req.PasswordParams)
			if err != nil {
				slog.Error("error while marshalling user password params to json", "marshall_error", err)
				api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			}

			r, err := json.Marshal(req.RecoveryParams)
			if err != nil {
				slog.Error("error while marshalling user recovery params to json", "marshall_error", err)
				api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
			}

			_, err = q.CreateEncryption(c, models.CreateEncryptionParams{UserID: createdUser.ID, PasswordSalt: req.PasswordSalt, PasswordParams: j, EncryptedMasterKeyPw: req.EncryptedMasterKeyPW, RecoverySalt: req.RecoverySalt, RecoveryParams: r, EncryptedMasterKeyRec: req.EncryptedMasterKeyRec})
			if err != nil {
				err = q.DeleteUserByID(c, createdUser.ID)
				if err != nil {
					slog.Error("failed to delete user data after encryption key failure", "err", err, "user_id", createdUser.ID)
				}
				slog.Error("error while creating user encryption keys", "db_error", err, "user_id", createdUser.ID)
				api.Error(c, http.StatusInternalServerError, "something went horribly wrong", nil)
				return
			}

		}
	}
	api.Success(c, http.StatusOK, map[string]string{"url": "some random bs fr", "message": "open the url in your browser"})
}

func (h Handler) Login(c *gin.Context) {
	//loginState = uuid.New().String()
	api.Success(c, http.StatusOK, map[string]string{"url": "some random bs fr", "message": "open the url in your browser"})
}
