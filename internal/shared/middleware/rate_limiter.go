package middleware

import (
	"ambassador/application/dto"
	"ambassador/domain/repositories"
	"ambassador/domain/services"
	"ambassador/internal/shared/response"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	ErrCodeRateLimitExceeded    = "RATE_LIMIT_EXCEEDED"
	ErrMessageRateLimitExceeded = "Rate limit exceeded"
)

type RateLimiter struct {
	visitors     map[string]*visitor
	userVisitors map[string]*visitor
	mu           sync.RWMutex
	rate         int
	window       time.Duration
	tokenRepo    repositories.TokenRepository
}

type visitor struct {
	requests []time.Time
	lastSeen time.Time
}

func NewRateLimiter(rate int, window time.Duration, tokenRepo repositories.TokenRepository) *RateLimiter {
	rl := &RateLimiter{
		visitors:     make(map[string]*visitor),
		userVisitors: make(map[string]*visitor),
		rate:         rate,
		window:       window,
		tokenRepo:    tokenRepo,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !rl.allowRequest(ip, "") {
			response.Error(c, http.StatusTooManyRequests, ErrCodeRateLimitExceeded, ErrMessageRateLimitExceeded)
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rl *RateLimiter) UserAccessTokenMiddleware(authService auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		var userID string

		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				user, err := authService.GetProfile(parts[1])
				if err == nil {
					userID = user.ID
				}
			}
		}

		if !rl.allowRequest(ip, userID) {
			response.Error(c, http.StatusTooManyRequests, ErrCodeRateLimitExceeded, ErrMessageRateLimitExceeded)
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Next()
	}
}

func (rl *RateLimiter) UserRefreshTokenMiddleware(authService services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		var userID string

		var req dto.RefreshTokenRequest
		if err := c.ShouldBindJSON(&req); err == nil {
			token, err := rl.tokenRepo.FindByValue(req.RefreshToken)
			if err == nil {
				userID = token.UserID
			}
		} else {
			response.Error(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
			c.Abort()
			return
		}

		if !rl.allowRequest(ip, userID) {
			response.Error(c, http.StatusTooManyRequests, ErrCodeRateLimitExceeded, ErrMessageRateLimitExceeded)
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Set("refreshToken", req.RefreshToken)
		c.Next()
	}
}

func (rl *RateLimiter) allowRequest(ip, userID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if !rl.checkVisitorRateLimit(rl.visitors, ip, now) {
		return false
	}

	if userID != "" {
		if !rl.checkVisitorRateLimit(rl.userVisitors, userID, now) {
			return false
		}
	}

	return true
}

func (rl *RateLimiter) checkVisitorRateLimit(visitors map[string]*visitor, key string, now time.Time) bool {
	v, exists := visitors[key]
	if !exists {
		visitors[key] = &visitor{
			requests: []time.Time{now},
			lastSeen: now,
		}
		return true
	}

	var validRequests []time.Time
	for _, reqTime := range v.requests {
		if now.Sub(reqTime) < rl.window {
			validRequests = append(validRequests, reqTime)
		}
	}
	v.requests = validRequests
	v.lastSeen = now

	if len(v.requests) >= rl.rate {
		return false
	}

	v.requests = append(v.requests, now)
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()

		for ip, v := range rl.visitors {
			if now.Sub(v.lastSeen) > time.Hour {
				delete(rl.visitors, ip)
			}
		}

		for userID, uv := range rl.userVisitors {
			if now.Sub(uv.lastSeen) > time.Hour {
				delete(rl.userVisitors, userID)
			}
		}

		rl.mu.Unlock()
	}
}
