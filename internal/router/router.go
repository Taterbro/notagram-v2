package router

import (
	"database/sql"
	"time"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/middleware"
	"github.com/Taterbro/notagram-v2/internal/router/auth"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func NewRouter(cfg *config.Config, db *sql.DB, rd *redis.Client) *gin.Engine {
	r := gin.Default()
	api := r.Group("/api")

	authLimiter := middleware.NewRateLimiter(rd, 5, time.Minute,
		middleware.WithKeyFunc(middleware.EmailOrIPKeyFunc("email")),
		middleware.WithPrefix("ratelimit:auth"),
	)

	auth.RegisterRoutes(api.Group("/auth"), cfg, db, rd, authLimiter.Middleware())

	return r
}
