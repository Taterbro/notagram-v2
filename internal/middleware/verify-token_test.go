package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type fakeTokenStore struct {
	keyExists bool
}

func (f *fakeTokenStore) Get(ctx context.Context, key string) *redis.StringCmd {
	if f.keyExists {
		return redis.NewStringResult("revoked", nil)
	}
	return redis.NewStringResult("", redis.Nil)
}

func issueToken(cfg *config.Config, claims jwt.MapClaims) string {
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(cfg.JwtSecret))
	return token
}

func testTokenConfig() *config.Config {
	return &config.Config{JwtSecret: "test-secret"}
}

func TestTokenValidator(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testTokenConfig()
	userID := uuid.New()
	jti := uuid.NewString()
	exp := float64(time.Now().Add(15 * time.Minute).Unix())

	baseClaims := jwt.MapClaims{
		"exp":     exp,
		"iss":     "api.notagram.app",
		"jti":     jti,
		"user_id": userID.String(),
		"type":    string(Access),
	}

	valid := "Bearer " + issueToken(cfg, baseClaims)
	refresh := "Bearer " + issueToken(cfg, jwt.MapClaims{
		"exp": exp, "iss": "api.notagram.app", "jti": jti, "user_id": userID.String(), "type": string(Refresh),
	})
	expired := "Bearer " + issueToken(cfg, jwt.MapClaims{
		"exp": time.Now().Add(-time.Minute).Unix(), "iss": "api.notagram.app", "jti": jti, "user_id": userID.String(), "type": string(Access),
	})
	wrongSecret := "Bearer " + issueToken(&config.Config{JwtSecret: "wrong-secret"}, baseClaims)
	missingType := "Bearer " + issueToken(cfg, jwt.MapClaims{
		"exp": exp, "iss": "api.notagram.app", "jti": jti, "user_id": userID.String(),
	})
	invalidUserID := "Bearer " + issueToken(cfg, jwt.MapClaims{
		"exp": exp, "iss": "api.notagram.app", "jti": jti, "user_id": "not-a-uuid", "type": string(Access),
	})
	missingJTI := "Bearer " + issueToken(cfg, jwt.MapClaims{
		"exp": exp, "iss": "api.notagram.app", "user_id": userID.String(), "type": string(Access),
	})
	missingExp := "Bearer " + issueToken(cfg, jwt.MapClaims{
		"iss": "api.notagram.app", "jti": jti, "user_id": userID.String(), "type": string(Access),
	})

	tests := []struct {
		name       string
		authHeader string
		tt         TokenType
		keyExists  bool
		wantCode   int
		wantMsg    string
	}{
		{
			name:       "missing auth header",
			authHeader: "",
			tt:         Access,
			keyExists:  false,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "missing auth header",
		},
		{
			name:       "invalid token format - no bearer prefix",
			authHeader: "just-a-random-string",
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token format",
		},
		{
			name:       "invalid token format - single part",
			authHeader: "Bearer",
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token format",
		},
		{
			name:       "invalid token format - wrong scheme",
			authHeader: "Token abc.def.ghi",
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token format",
		},
		{
			name:       "token signed with wrong secret",
			authHeader: wrongSecret,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token",
		},
		{
			name:       "missing exp claim",
			authHeader: missingExp,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token claims",
		},
		{
			name:       "expired token",
			authHeader: expired,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token",
		},
		{
			name:       "wrong token type",
			authHeader: refresh,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token type",
		},
		{
			name:       "missing type claim",
			authHeader: missingType,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token claims",
		},
		{
			name:       "invalid user_id",
			authHeader: invalidUserID,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token claims",
		},
		{
			name:       "missing jti claim",
			authHeader: missingJTI,
			tt:         Access,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "invalid token claims",
		},
		{
			name:       "revoked token",
			authHeader: valid,
			tt:         Access,
			keyExists:  true,
			wantCode:   http.StatusUnauthorized,
			wantMsg:    "token expired",
		},
		{
			name:       "successful access token",
			authHeader: valid,
			tt:         Access,
			wantCode:   http.StatusOK,
		},
		{
			name:       "successful refresh token",
			authHeader: refresh,
			tt:         Refresh,
			wantCode:   http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
			c.Request.Header.Set("Authorization", tt.authHeader)

			store := &fakeTokenStore{keyExists: tt.keyExists}
			TokenValidator(c, cfg, tt.tt, store)

			assert.Equal(t, tt.wantCode, w.Code)

			if tt.wantMsg != "" {
				var body map[string]string
				json.Unmarshal(w.Body.Bytes(), &body)
				assert.Equal(t, tt.wantMsg, body["message"])
			}

			if tt.wantCode == http.StatusOK {
				assert.Equal(t, false, c.IsAborted())
				assert.Equal(t, jti, c.MustGet("jti"))
				assert.Equal(t, exp, c.MustGet("exp"))
				assert.Equal(t, userID, c.MustGet("user_id"))
			}
		})
	}
}
