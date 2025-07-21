package main

import (
	"log"
	"net/http"
	"time"

	"ambassador/internal/features/auth"
	"ambassador/internal/shared/middleware"
	"ambassador/internal/shared/security"

	"github.com/gin-gonic/gin"
)

func main2() {
	// Initialize shared components
	hasher := security.NewBcryptHasher()
	validator := middleware.NewValidator()

	// Initialize auth feature
	authFeature := auth.NewAuthFeature(hasher, validator)

	// Create Gin router
	r := gin.New()

	// Apply global middleware
	r.Use(middleware.CORS())
	r.Use(middleware.RequestID())
	r.Use(gin.Recovery())

	// Setup routes
	api := r.Group("/api/v1")
	authFeature.SetupRoutes(api)

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