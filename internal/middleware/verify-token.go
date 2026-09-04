package middleware

import (
	"net/http"
	"strings"

	"github.com/Taterbro/notagram-v2/internal/auth"
	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(c *gin.Context, cfg config.Config) {
	header := c.GetHeader("Authorization")
	if header == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "missing auth header"})
		return
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token format"})
		return
	}

	token, err := auth.ValidateToken(parts[1], cfg)
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token"})
		return
	}

	c.Next()
}
