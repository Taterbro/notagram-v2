package auth

// HOWDY Next time you hop on to work on this, find out if it's okay to just use os.getenv here
// or do we still need to inject dependecies.
// Google "when to use dependency injection in go"
import (
	"fmt"
	"time"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type TokenType string

const (
	Refresh TokenType = "refresh"
	Accesss TokenType = "access"
)

func GenerateAccessToken(user_id uuid.UUID, cfg config.Config) (string, error) {
	ttl := 15 * time.Minute

	claims := jwt.MapClaims{
		"exp":     time.Now().Add(ttl).Unix(),
		"iss":     "api.notagram.app",
		"jti":     uuid.NewString(),
		"user_id": user_id,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JwtSecret))
}

func GenerateRefreshToken(cfg config.Config) (string, error) {
	ttl := 167 * time.Hour
	expiresAt := time.Now().Add(ttl)

	claims := jwt.MapClaims{
		"exp": expiresAt.Unix(),
		"iss": "api.notagram.app",
		"jti": uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(cfg.JwtSecret))
}

func ValidateToken(tokenString string, cfg config.Config) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %s", token.Method.Alg())
		}
		return cfg.JwtSecret, nil
	})
}
