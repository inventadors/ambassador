// interfaces/http/middleware/rate_limiter.go
package middleware

import (
	"net/http"
	"sync"
	"time"
	"ambassador/interfaces/http/response"
)

type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     int
	window   time.Duration
}

type visitor struct {
	requests  []time.Time
	lastSeen  time.Time
}

func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}
	
	// Cleanup goroutine
	go rl.cleanup()
	
	return rl
}

func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		
		if !rl.allowRequest(ip) {
			response.Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded", r)
			return
		}
		
		next(w, r)
	}
}

func (rl *RateLimiter) allowRequest(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{
			requests: []time.Time{now},
			lastSeen: now,
		}
		return true
	}
	
	// Remove old requests outside the window
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
		rl.mu.Unlock()
	}
}