package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// KeyFunc extracts the identity to rate-limit on from the request context.
// Return "" to signal "no key available" — the caller decides how to handle that.
type KeyFunc func(c *gin.Context) string

type RateLimiter struct {
	client  *redis.Client
	limit   int
	window  time.Duration
	keyFunc KeyFunc
	prefix  string
}

// Option configures a RateLimiter at construction time.
type Option func(*RateLimiter)

// WithKeyFunc overrides how the rate-limit key is derived from the request.
// Defaults to IPKeyFunc.
func WithKeyFunc(fn KeyFunc) Option {
	return func(rl *RateLimiter) { rl.keyFunc = fn }
}

// WithPrefix overrides the redis key prefix (default "ratelimit").
func WithPrefix(prefix string) Option {
	return func(rl *RateLimiter) { rl.prefix = prefix }
}

func NewRateLimiter(client *redis.Client, limit int, window time.Duration, opts ...Option) *RateLimiter {
	rl := &RateLimiter{
		client:  client,
		limit:   limit,
		window:  window,
		keyFunc: IPKeyFunc,
		prefix:  "ratelimit",
	}
	for _, opt := range opts {
		opt(rl)
	}
	return rl
}

// IPKeyFunc rate-limits per client IP. This is the default.
func IPKeyFunc(c *gin.Context) string {
	return "ip:" + c.ClientIP()
}

// bodyEmailMaxBytes caps how much of the body we'll buffer to find the email
// field, so a huge/malicious payload can't force the middleware to read
// unbounded data into memory before the real handler even runs.
const bodyEmailMaxBytes = 1 << 20 // 1MB

// EmailKeyFunc rate-limits per email address pulled out of the JSON request
// body, e.g. {"email": "user@example.com", ...}. field is the JSON key name
// to look up (usually "email").
//
// It reads and restores c.Request.Body so downstream handlers (including
// c.ShouldBindJSON) still see the full, unconsumed body afterward. If the
// body is missing, isn't JSON, or doesn't contain the field, it returns ""
// so EmailOrIPKeyFunc (or your own fallback) can decide what to do.
func EmailKeyFunc(field string) KeyFunc {
	return func(c *gin.Context) string {
		if c.Request.Body == nil {
			return ""
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, bodyEmailMaxBytes))
		_ = c.Request.Body.Close()
		if err != nil {
			// Restore an empty body so downstream handlers fail predictably
			// instead of panicking on a nil body.
			c.Request.Body = io.NopCloser(bytes.NewReader(nil))
			return ""
		}
		// Restore the body for the real handler regardless of what happens below.
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			return ""
		}
		email, ok := payload[field].(string)
		if !ok || email == "" {
			return ""
		}
		return "email:" + email
	}
}

// EmailOrIPKeyFunc rate-limits by the email in the request body when present,
// and falls back to IP otherwise (e.g. malformed body, missing field, or
// routes where the field simply isn't part of the payload).
func EmailOrIPKeyFunc(field string) KeyFunc {
	emailKey := EmailKeyFunc(field)
	return func(c *gin.Context) string {
		if key := emailKey(c); key != "" {
			return key
		}
		return IPKeyFunc(c)
	}
}

const luaScript = `
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
    redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`

func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	script := redis.NewScript(luaScript)

	return func(c *gin.Context) {
		id := rl.keyFunc(c)
		if id == "" {
			// No usable key (e.g. EmailKeyFunc with no authenticated user yet).
			// Fail open rather than block the request; swap for AbortWithStatus
			// if you'd rather fail closed.
			c.Next()
			return
		}
		key := rl.prefix + ":" + id

		ctx := c.Request.Context()
		count, err := script.Run(ctx, rl.client, []string{key}, rl.window.Milliseconds()).Int()
		if err != nil {
			slog.Error("rate limiter error", "err", err, "key", key)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		remaining := rl.limit - count
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(rl.limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if count > rl.limit {
			ttl, _ := rl.client.PTTL(ctx, key).Result()
			c.Header("Retry-After", strconv.Itoa(int(ttl.Round(time.Second).Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded, try again later",
			})
			return
		}

		c.Next()
	}
}
