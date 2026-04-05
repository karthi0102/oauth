package main

import (
	"log"
	"net/http"

	"github.com/karthi0102/oauth/internal/config"
	"github.com/karthi0102/oauth/internal/jwtutil"
	"github.com/karthi0102/oauth/internal/middleware"
	"github.com/karthi0102/oauth/internal/store"
	"github.com/karthi0102/oauth/resource-server/handlers"
)

func main() {
	// 1. load config
	cfg := config.Load()

	// 2. open + migrate DB, seed sample resources
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.RunMigrations(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// For demonstration, we'll seed data for a couple dummy users if empty
	if err := db.SeedResources("user_123"); err != nil {
		log.Printf("warning: failed to seed resources: %v", err)
	}

	// 3. init JWKSCache with config.JWKSUrl
	jwksCache := jwtutil.NewJWKSCache(cfg.JWKSUrl)

	// Configure auth middleware
	middleware.InitAuth(jwksCache.GetKey, cfg.ExpectedIss, cfg.Audience)

	// Set up dependencies
	dataHandler := &handlers.DataHandler{
		DB: db,
	}

	// 4. start HTTP server on config.ResourcePort
	mux := http.NewServeMux()

	// routes to register:
	// GET /health              → handlers.Health  (no auth)
	mux.HandleFunc("GET /health", handlers.Health)

	// GET /api/profile         → logging(RequireAuth(RequireScope("profile:read")(handlers.Profile)))
	profileHandler := middleware.Logging(
		middleware.RequireAuth(
			middleware.RequireScope("profile:read")(http.HandlerFunc(handlers.Profile)),
		),
	)
	mux.Handle("GET /api/profile", profileHandler)

	// GET /api/data            → logging(RequireAuth(RequireScope("data:read")(handlers.Data)))
	dataEndpoint := middleware.Logging(
		middleware.RequireAuth(
			middleware.RequireScope("data:read")(http.HandlerFunc(dataHandler.Data)),
		),
	)
	mux.Handle("GET /api/data", dataEndpoint)

	log.Printf("Starting Resource Server on port %s", cfg.ResourcePort)
	if err := http.ListenAndServe(":"+cfg.ResourcePort, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
