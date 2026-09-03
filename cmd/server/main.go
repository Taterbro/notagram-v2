package main

import (
	"log/slog"
	"os"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/Taterbro/notagram-v2/internal/db"
	"github.com/Taterbro/notagram-v2/internal/router"
)

func main() {
	r := router.NewRouter()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load environment variables", "config_error", err)
		os.Exit(1)
	}

	err = db.Connect(cfg.DatabaseUrl)
	if err != nil {
		slog.Error("failed to connect to database", "db_connect_error", err)
		os.Exit(1)
	}

	if err := r.Run(":8080"); err != nil {
		slog.Error("server failed to start", "error", err)
		os.Exit(1)
	}
}
