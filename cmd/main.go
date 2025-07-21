package main

import (
	"log"
	"time"
	"ambassador/application/services"
	"ambassador/infrastructure/repositories"
	"ambassador/infrastructure/security"
	"ambassador/interfaces/http/handlers"
	"ambassador/interfaces/http/middleware"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	// Initialize repositories and services
	userRepo := repositories.NewMemoryUserRepository()
	tokenRepo := repositories.NewMemoryTokenRepository()
	// expenseRepo := repositories.NewMemoryExpenseRepository()
	// groupRepo := repositories.NewMemoryGroupRepository()
	hasher := security.NewBcryptHasher()
	validator := middleware.NewValidator()
	rateLimiter := middleware.NewRateLimiter(100, time.Minute, tokenRepo)

	authService := services.NewAuthService(userRepo, tokenRepo, hasher)
	// expenseService := services.NewExpenseService(expenseRepo, groupRepo, userRepo, tokenRepo)
	// groupService := services.NewGroupService(groupRepo, userRepo, tokenRepo)

	authHandler := handlers.NewAuthHandler(authService, validator)
	// expenseHandler := handlers.NewExpenseHandler(expenseService, validator)
	// groupHandler := handlers.NewGroupHandler(groupService, validator)

	// Create Gin router
	r := gin.New()

	// Apply global middleware
	r.Use(middleware.CORS())
	r.Use(middleware.RequestID())
	r.Use(gin.Recovery())

	// Define route group for API
	api := r.Group("/api/v1")
	{
		// Public routes
		api.POST("/auth/register", rateLimiter.Middleware(), authHandler.Register)
		api.POST("/auth/login", rateLimiter.Middleware(), authHandler.Login)
		api.POST("/auth/refresh", authHandler.RefreshToken)

		// Protected routes
		api.GET("/auth/me", rateLimiter.UserAccessTokenMiddleware(authService), authHandler.Profile)
		api.POST("/auth/logout", rateLimiter.UserRefreshTokenMiddleware(authService), authHandler.Logout)
		// api.POST("/expense/add", middleware.GinUserAccessTokenMiddleware(authService), expenseHandler.GinAddExpense)
		// api.PUT("/expense/update", middleware.GinUserAccessTokenMiddleware(authService), expenseHandler.GinUpdateExpense)
		// api.DELETE("/expense/delete", middleware.GinUserAccessTokenMiddleware(authService), expenseHandler.GinDeleteExpense)
		// api.POST("/group/create", middleware.GinUserAccessTokenMiddleware(authService), groupHandler.GinCreateGroup)
	}

	// Create HTTP server
	server := &http.Server{
		Addr:         ":9090",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Server running on :9090")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}