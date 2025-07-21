package auth

import (
	"ambassador/internal/shared/middleware"
	"ambassador/internal/shared/security"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthFeature struct {
	handler     *AuthHandler
	rateLimiter *middleware.RateLimiter
	service     AuthService
}

func NewAuthFeature(hasher security.PasswordHasher, validator middleware.Validator, tokenRepo TokenRepository) *AuthFeature {
	// Initialize repositories
	userRepo := NewMemoryUserRepository()

	// Initialize service
	authService := NewAuthService(userRepo, tokenRepo, hasher)

	// Initialize handler
	handler := NewAuthHandler(authService, validator)

	// Initialize rate limiter
	rateLimiter := middleware.NewRateLimiter(100, time.Minute, tokenRepo)

	return &AuthFeature{
		handler:     handler,
		rateLimiter: rateLimiter,
		service:     authService,
	}
}

func (f *AuthFeature) SetupRoutes(rg *gin.RouterGroup) {
	auth := rg.Group("/auth")
	{
		// Public routes
		auth.POST("/register", f.rateLimiter.Middleware(), f.handler.Register)
		auth.POST("/login", f.rateLimiter.Middleware(), f.handler.Login)
		auth.POST("/refresh", f.handler.RefreshToken)

		// Protected routes
		auth.GET("/me", f.rateLimiter.UserAccessTokenMiddleware(f.service), f.handler.Profile)
		auth.POST("/logout", f.rateLimiter.UserRefreshTokenMiddleware(f.service), f.handler.Logout)
	}
}
