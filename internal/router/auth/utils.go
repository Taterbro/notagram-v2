package auth

// HOWDY Next time you hop on to work on this, find out if it's okay to just use os.getenv here
// or do we still need to inject dependecies.
// Google "when to use dependency injection in go"
import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

var jwtSecret []byte

func resolveSecret() []byte {
	if len(jwtSecret) > 0 {
		return jwtSecret
	}
	return []byte(os.Getenv("JWT_SECRET"))
}
func GenerateJWTToken() (string, error) {
	ttl := 6 * time.Hour

	claims := jwt.MapClaims{
		"exp": time.Now().Add(ttl).Unix(),
		"iat": time.Now().Unix(),
		"iss": "api.victorsportfolio",
		"jti": uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(resolveSecret())
}

func ValidateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %s", token.Method.Alg())
		}
		return resolveSecret(), nil
	})
}
