package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Taterbro/notagram-v2/internal/db/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func validUpdatePasswordBody(currentPassword string) UpdatePasswordBody {
	return UpdatePasswordBody{
		CurrentPassword:         currentPassword,
		NewPassword:             "new-super-secret-password",
		NewPasswordSalt:         "newsaltvalue",
		NewPasswordParams:       CryptoParams{Memory: 65536, Iterations: 3, Parallelism: 4, Version: 19},
		NewEncryptedMasterKeyPw: "new-encrypted-key-blob",
	}
}

func TestUpdatePassword(t *testing.T) {
	const currentPassword = "supersecretpassword"
	hash, _ := bcrypt.GenerateFromPassword([]byte(currentPassword), 12)
	wrongHash, _ := bcrypt.GenerateFromPassword([]byte("completelydifferent"), 12)
	user := models.User{ID: uuid.New(), Email: "test@example.com", PasswordHash: string(hash)}

	tests := []struct {
		name       string
		q          *fakeQuerier
		body       UpdatePasswordBody
		setUserID  bool
		wantStatus int
	}{
		{
			name:       "success",
			q:          &fakeQuerier{getUserByIDResult: user},
			body:       validUpdatePasswordBody(currentPassword),
			setUserID:  true,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "invalid body - missing new password",
			q:          &fakeQuerier{},
			body:       UpdatePasswordBody{CurrentPassword: currentPassword},
			setUserID:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing user id in context",
			q:          &fakeQuerier{},
			body:       validUpdatePasswordBody(currentPassword),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "user not found",
			q:          &fakeQuerier{getUserByIDErr: sql.ErrNoRows},
			body:       validUpdatePasswordBody(currentPassword),
			setUserID:  true,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "db error fetching user",
			q:          &fakeQuerier{getUserByIDErr: errors.New("boom")},
			body:       validUpdatePasswordBody(currentPassword),
			setUserID:  true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "wrong current password",
			q:          &fakeQuerier{getUserByIDResult: models.User{ID: user.ID, PasswordHash: string(wrongHash)}},
			body:       validUpdatePasswordBody(currentPassword),
			setUserID:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "update user password fails",
			q:          &fakeQuerier{getUserByIDResult: user, updateUserPasswordErr: errors.New("boom")},
			body:       validUpdatePasswordBody(currentPassword),
			setUserID:  true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "update encryption fails, password rolled back",
			q: &fakeQuerier{
				getUserByIDResult:   user,
				updateEncryptionErr: errors.New("boom"),
			},
			body:       validUpdatePasswordBody(currentPassword),
			setUserID:  true,
			wantStatus: http.StatusInternalServerError,
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(testConfig(), tt.q, &fakeRedis{})

			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.POST("/password/change", func(c *gin.Context) {
				if tt.setUserID {
					c.Set("user_id", user.ID)
				}
				c.Next()
			}, h.UpdatePassword)

			b, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/password/change", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.name == "update encryption fails, password rolled back" {
				assert.Equal(t, 2, len(tt.q.updatePasswordCalls))
				assert.Equal(t, user.PasswordHash, tt.q.updatePasswordCalls[1].PasswordHash)
			}
		})
	}
}
