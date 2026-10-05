package auth

// HOWDY Next time you hop on to work on this, find out if it's okay to just use os.getenv here
// or do we still need to inject dependecies.
// Google "when to use dependency injection in go"
import (
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

func GenerateUserToken(user_id uuid.UUID, cfg config.Config, tt TokenType) (string, error) {
	tokenType := tt
	ttl := 15 * time.Minute

	claims := jwt.MapClaims{
		"exp":     time.Now().Add(ttl).Unix(),
		"iss":     "api.notagram.app",
		"jti":     uuid.NewString(),
		"user_id": user_id,
		"type":    tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JwtSecret))
}
