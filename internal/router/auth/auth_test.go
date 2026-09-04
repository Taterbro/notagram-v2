package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/db/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type fakeRedis struct{}

func (f *fakeRedis) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	return redis.NewStatusResult("OK", nil)
}

type fakeQuerier struct {
	getUserErr       error
	createUserResult models.User
	createUserErr    error
	createEncErr     error
	deletedUserID    uuid.UUID
}

func (f *fakeQuerier) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	return models.User{}, f.getUserErr
}
func (f *fakeQuerier) CreateUser(ctx context.Context, arg models.CreateUserParams) (models.User, error) {
	return f.createUserResult, f.createUserErr
}
func (f *fakeQuerier) CreateEncryption(ctx context.Context, arg models.CreateEncryptionParams) (models.UserEncryption, error) {
	return models.UserEncryption{}, f.createEncErr
}
func (f *fakeQuerier) DeleteUserByID(ctx context.Context, id uuid.UUID) error {
	f.deletedUserID = id
	return nil
}

func validSignupBody() SignupBody {
	return SignupBody{
		Email:        "test@example.com",
		Moniker:      "tester",
		Password:     "supersecretpassword",
		PasswordSalt: "somesaltvalue",
		PasswordParams: CryptoParams{
			Memory:      65536,
			Iterations:  3,
			Parallelism: 4,
			Version:     19,
		},
		EncryptedMasterKeyPW: "encrypted-key-pw-blob",
		RecoverySalt:         "recoverysaltvalue",
		RecoveryParams: CryptoParams{
			Memory:      65536,
			Iterations:  3,
			Parallelism: 4,
			Version:     19,
		},
		EncryptedMasterKeyRec: "encrypted-key-rec-blob",
	}
}
func testConfig() *config.Config {
	fg := &config.Config{
		JwtSecret: "eiojdkafd0aufpoidsj",
	}
	return fg
}

func TestSignup(t *testing.T) {
	tests := []struct {
		name       string
		q          *fakeQuerier
		body       SignupBody
		wantStatus int
	}{
		{
			name:       "email already exists",
			q:          &fakeQuerier{getUserErr: nil}, // GetUserByEmail succeeds -> exists
			body:       validSignupBody(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "db error checking user",
			q:          &fakeQuerier{getUserErr: errors.New("connection reset")},
			body:       validSignupBody(),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "create user fails",
			q:          &fakeQuerier{getUserErr: sql.ErrNoRows, createUserErr: errors.New("boom")},
			body:       validSignupBody(),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "create encryption fails, rolls back user",
			q:          &fakeQuerier{getUserErr: sql.ErrNoRows, createUserResult: models.User{ID: uuid.New()}, createEncErr: errors.New("boom")},
			body:       validSignupBody(),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "success",
			q:          &fakeQuerier{getUserErr: sql.ErrNoRows, createUserResult: models.User{ID: uuid.New(), Email: "a@b.com", CreatedAt: time.Now()}},
			body:       validSignupBody(),
			wantStatus: http.StatusCreated,
		},
		{
			name:       "invalid body — missing password",
			q:          &fakeQuerier{},
			body:       SignupBody{Email: "a@b.com"},
			wantStatus: http.StatusBadRequest,
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(testConfig(), tt.q, &fakeRedis{})

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			b, _ := json.Marshal(tt.body)
			c.Request = httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(b))
			c.Request.Header.Set("Content-Type", "application/json")

			h.Signup(c)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
