package auth

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
)

func TestLogout(t *testing.T) {
	tests := []struct {
		name       string
		r          *fakeRedis
		wantStatus int
	}{
		{
			name:       "success",
			r:          &fakeRedis{keyExists: false},
			wantStatus: http.StatusOK,
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(testConfig(), &fakeQuerier{}, tt.r)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Request = httptest.NewRequest(http.MethodPost, "/logout", nil)
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set("jti", "nothing")
			c.Set("exp", rand.Float64)

			h.Logout(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.r.storedKey, "nothing")
		})
	}
}
