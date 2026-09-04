package auth

import (
	"database/sql"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/db/models"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, cfg *config.Config, db *sql.DB, redis RedisClient) {
	q := models.New(db)
	h := NewHandler(cfg, q, redis)

	r.POST("/signup", h.Signup)
	r.GET("/login", h.Login)
	r.POST("/logout", h.Logout)
}
