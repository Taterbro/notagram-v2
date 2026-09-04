package auth

import (
	"database/sql"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, cfg *config.Config, db *sql.DB) {
	h := NewHandler(cfg, db)

	r.POST("/signup", h.Signup)
	r.GET("/login", h.Login)
}
