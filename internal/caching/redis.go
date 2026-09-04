package caching

import (
	"context"

	"github.com/Taterbro/notagram-v2/internal/config"
	"github.com/redis/go-redis/v9"
)

func Connect(cfg *config.Config, ctx context.Context) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: "",
		DB:       0,
	})

	return rdb

}
