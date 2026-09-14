package auth

import (
	"database/sql"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/db/models"
	"github.com/Taterbro/notagram-v2/internal/middleware"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, cfg *config.Config, db *sql.DB, redis RedisClient, rateLimit gin.HandlerFunc) {
	q := models.New(db)
	h := NewHandler(cfg, q, redis)

	r.POST("/signup", h.Signup)
	r.POST("/signin", h.Signin)
	r.POST("/logout", middleware.RequireTokenType(cfg, middleware.Refresh, redis), h.Logout)
	r.POST("/refresh", middleware.RequireTokenType(cfg, middleware.Refresh, redis), h.Refresh)
	r.POST("/password/change", middleware.RequireTokenType(cfg, middleware.Access, redis), h.UpdatePassword)
	// r.POST("/password/recovery", middleware.RequireTokenType(cfg, middleware.Access, redis), h.UpdatePassword)
	r.POST("/keys/recovery", rateLimit, h.GetRecoveryKey)
}
