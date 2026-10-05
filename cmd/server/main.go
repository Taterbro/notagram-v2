package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/Taterbro/notagram-v2/internal/caching"
	"github.com/Taterbro/notagram-v2/internal/config"
	database "github.com/Taterbro/notagram-v2/internal/db"
	"github.com/Taterbro/notagram-v2/internal/router"
)

var ctx = context.Background()

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load environment variables", "config_error", err)
		os.Exit(1)
	}
	redisClient := caching.Connect(cfg, ctx)

	db, err := database.Connect(cfg.DatabaseUrl)
	if err != nil {
		slog.Error("failed to connect to database", "db_connect_error", err)
		os.Exit(1)
	}
	defer db.Close()
	defer redisClient.Close()
	r := router.NewRouter(cfg, db, redisClient)
	if err := r.Run(":8080"); err != nil {
		slog.Error("server failed to start", "error", err)
		os.Exit(1)
	}
}
