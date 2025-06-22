// interfaces/http/middleware/rate_limiter.go
package middleware

import (
	"net/http"
	"sync"
	"time"
	"strings"
	"encoding/json"
	"ambassador/interfaces/http/response"
	"ambassador/domain/services"
	"ambassador/domain/repositories"
	"ambassador/application/dto"
)

type RateLimiter struct {
	visitors    map[string]*visitor
	userVisitors map[string]*visitor
	mu          sync.RWMutex
	rate        int
	window      time.Duration
	tokenRepo   repositories.TokenRepository
}

type visitor struct {
	requests  []time.Time
	lastSeen  time.Time
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

func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		if !rl.allowRequest(ip, "") {
			response.Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded", r)
			return
		}

		next(w, r)
	}
}

func (rl *RateLimiter) UserAccessTokenMiddleware(authService services.AuthService) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			var userID string

			authHeader := r.Header.Get("Authorization")
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
				response.Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded", r)
				return
			}

			next(w, r)
		}
	}
}

func (rl *RateLimiter) UserRefreshTokenMiddleware(authService services.AuthService) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			var userID string

			var req dto.RefreshTokenRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				token, err := rl.tokenRepo.FindByValue(req.RefreshToken)
				if err == nil {
					userID = token.UserID
				}
			}
			r.Body = http.NoBody

			if !rl.allowRequest(ip, userID) {
				response.Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded", r)
				return
			}

			next(w, r)
		}
	}
}

func (rl *RateLimiter) allowRequest(ip, userID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// IP-based rate limiting
	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{
			requests: []time.Time{now},
			lastSeen: now,
		}
	} else {
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
	}

	// UserID-based rate limiting
	if userID != "" {
		uv, exists := rl.userVisitors[userID]
		if !exists {
			rl.userVisitors[userID] = &visitor{
				requests: []time.Time{now},
				lastSeen: now,
			}
		} else {
			var validRequests []time.Time
			for _, reqTime := range uv.requests {
				if now.Sub(reqTime) < rl.window {
					validRequests = append(validRequests, reqTime)
				}
			}
			uv.requests = validRequests
			uv.lastSeen = now
			if len(uv.requests) >= rl.rate {
				return false
			}
			uv.requests = append(uv.requests, now)
		}
	}

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