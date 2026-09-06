package auth

import (
	"testing"
	"time"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/go-playground/assert/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func TestGenerateUserToken(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name      string
		tokenType TokenType
	}{
		{
			name:      "access token",
			tokenType: Accesss,
		},
		{
			name:      "refresh token",
			tokenType: Refresh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{JwtSecret: "test-secret"}

			tokenString, err := GenerateUserToken(userID, *cfg, tt.tokenType)
			assert.Equal(t, nil, err)

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
				return []byte(cfg.JwtSecret), nil
			})
			assert.Equal(t, nil, err)
			assert.Equal(t, true, token.Valid)

			claims, ok := token.Claims.(jwt.MapClaims)
			assert.Equal(t, true, ok)

			assert.Equal(t, string(tt.tokenType), claims["type"])
			assert.Equal(t, userID.String(), claims["user_id"])
			assert.Equal(t, "api.notagram.app", claims["iss"])

			jti, ok := claims["jti"].(string)
			assert.Equal(t, true, ok)
			_, err = uuid.Parse(jti)
			assert.Equal(t, nil, err)

			now := time.Now().Unix()
			exp, ok := claims["exp"].(float64)
			assert.Equal(t, true, ok)
			assert.Equal(t, true, exp > float64(now))
			assert.Equal(t, true, exp <= float64(now+16*60))
		})
	}
}
