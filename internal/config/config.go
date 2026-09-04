package config

import (
	"errors"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Env         string
	DatabaseUrl string
	JwtSecret   string
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		slog.Error("Failed to load .env", "error", err)
		return nil, err
	}
	cfg := &Config{
		Env:         os.Getenv("APP_ENV"),
		DatabaseUrl: os.Getenv("DATABASE_URL"),
		JwtSecret:   os.Getenv("JWT_SECRET"),
	}
	if cfg.Env == "" {
		return nil, errors.New("environment variable missing: APP_ENV")
	}
	if cfg.DatabaseUrl == "" {
		return nil, errors.New("environment variable missing: DATABASE_URL")
	}
	if cfg.JwtSecret == "" {
		return nil, errors.New("environment variable missing: JWT_SECRET")
	}
	slog.Info("all environment variables loaded successfully")
	return cfg, nil
}
