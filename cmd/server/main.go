package main

import (
	"log"
	"os"

	"ice_gate_auth/internal/handlers"
	"ice_gate_auth/internal/store"
	"ice_gate_auth/internal/webauthn"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize Store
	dbStore, err := store.NewStore()
	if err != nil {
		log.Printf("Warning: Failed to initialize database store: %v. Database-dependent endpoints will be unavailable.", err)
	}

	// Initialize WebAuthn
	wa, err := webauthn.NewWebAuthn()
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn: %v", err)
	}

	// Initialize Handlers
	h := &handlers.AuthHandler{
		Store:    dbStore,
		WebAuthn: wa,
	}

	// Setup Router
	r := gin.Default()

	// CORS Middleware (simplified)
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Public Endpoints (AASA)
	r.GET("/apple-app-site-association", h.ServeAASA)
	r.GET("/.well-known/apple-app-site-association", h.ServeAASA)

	// API v1 Endpoints
	v1 := r.Group("/v1")
	{
		v1.POST("/register/begin", h.BeginRegistration)
		v1.POST("/register/finish", h.FinishRegistration)
		v1.POST("/login/begin", h.BeginLogin)
		v1.POST("/login/finish", h.FinishLogin)
	}

	// Health Check with version tagging
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"version": "1.0.3-aasa-resilient",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Passkey Hub starting on port %s...", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
