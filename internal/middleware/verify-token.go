package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/redis/go-redis/v9"
)

type TokenStore interface {
	Get(ctx context.Context, key string) *redis.StringCmd
}

func IsTokenSigned(tokenString string, cfg *config.Config) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %s", token.Method.Alg())
		}
		return []byte(cfg.JwtSecret), nil
	})
}

type TokenType string

const Access TokenType = "access"
const Refresh TokenType = "refresh"

func RequireTokenType(cfg *config.Config, tt TokenType, store TokenStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		TokenValidator(c, cfg, tt, store)
	}
}

func TokenValidator(c *gin.Context, cfg *config.Config, tt TokenType, store TokenStore) {
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

	token, err := IsTokenSigned(parts[1], cfg)
	if err != nil || !token.Valid {
		slog.Error("error validating token", "err", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token claims"})
		return
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token claims"})
		return
	}
	if exp < float64(time.Now().Unix()) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "token expired"})
		return
	}

	tokenType, ok := claims["type"].(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token claims"})
		return
	}
	if TokenType(tokenType) != tt {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token type"})
		return
	}

	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token claims"})
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		slog.Error("error while parsing user ID", "err", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token claims"})
		return
	}
	jti, ok := claims["jti"].(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "invalid token claims"})
		return
	}

	_, err = store.Get(c.Request.Context(), jti).Result()
	if err == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"message": "token expired"})
		return
	}

	// slog.Info("the store key info", "store_key", storeKey)
	// slog.Info("from middleware", "jti", jti)

	c.Set("user_id", userID)
	c.Set("exp", exp)
	c.Set("jti", jti)
	c.Next()
}
