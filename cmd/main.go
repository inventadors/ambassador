package main

import (
	"log"
	"net/http"
	"time"
	"ambassador/application/services"
	"ambassador/infrastructure/repositories"
	"ambassador/infrastructure/security"
	"ambassador/interfaces/http/handlers"
	"ambassador/interfaces/http/middleware"
)

func main() {
	userRepo := repositories.NewMemoryUserRepository()
	tokenRepo := repositories.NewMemoryTokenRepository()
	hasher := security.NewBcryptHasher()
	validator := middleware.NewValidator()
	rateLimiter := middleware.NewRateLimiter(100, time.Minute, tokenRepo)

	authService := services.NewAuthService(userRepo, tokenRepo, hasher)
	authHandler := handlers.NewAuthHandler(authService, validator)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/register",
		middleware.RequestID(
			middleware.CORS(
				rateLimiter.Middleware(authHandler.Register))))

	mux.HandleFunc("/auth/login",
		middleware.RequestID(
			middleware.CORS(
				rateLimiter.Middleware(authHandler.Login))))

	mux.HandleFunc("/auth/me",
		middleware.RequestID(
			middleware.CORS(rateLimiter.UserAccessTokenMiddleware(authService)(authHandler.Profile))))

	mux.HandleFunc("/auth/logout",
		middleware.RequestID(
			middleware.CORS(rateLimiter.UserRefreshTokenMiddleware(authService)(authHandler.Logout))))
			
	mux.HandleFunc("/auth/refresh",
		middleware.RequestID(
			middleware.CORS(authHandler.RefreshToken)))

	server := &http.Server{
		Addr:         ":9090",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Server running on :9090")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}