package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func TestRefresh(t *testing.T) {
	tests := []struct {
		name       string
		userID     uuid.UUID
		setUserID  bool
		wantStatus int
	}{
		{
			name:       "success",
			userID:     uuid.New(),
			setUserID:  true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing user id in context",
			wantStatus: http.StatusUnauthorized,
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(testConfig(), &fakeQuerier{}, &fakeRedis{})

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/refresh", nil)

			if tt.setUserID {
				c.Set("user_id", tt.userID)
			}

			h.Refresh(c)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				var body struct {
					Data map[string]interface{} `json:"data"`
				}
				json.Unmarshal(w.Body.Bytes(), &body)

				accessToken, ok := body.Data["access_token"].(string)
				assert.Equal(t, true, ok)
				assert.NotEqual(t, "", accessToken)

				token, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
					return []byte("eiojdkafd0aufpoidsj"), nil
				})
				assert.Equal(t, nil, err)
				assert.Equal(t, true, token.Valid)

				claims, ok := token.Claims.(jwt.MapClaims)
				assert.Equal(t, true, ok)
				assert.Equal(t, "access", claims["type"])
				assert.Equal(t, tt.userID.String(), claims["user_id"])
			}
		})
	}
}
