package main

import (
	"log"
	"net/http"

	"github.com/karthi0102/oauth/client-app/handlers"
	"github.com/karthi0102/oauth/client-app/oauth"
	"github.com/karthi0102/oauth/client-app/session"
	"github.com/karthi0102/oauth/internal/config"
)

func main() {
	cfg := config.Load()

	store := session.NewStore()
	client := oauth.NewClient(cfg)

	mux := http.NewServeMux()

	mux.HandleFunc("/", handlers.Home(store))
	mux.HandleFunc("/login", handlers.Login(store, client))
	mux.HandleFunc("/callback", handlers.Callback(store, client))
	mux.HandleFunc("/dashboard", handlers.Dashboard(store, client, cfg))
	mux.HandleFunc("/logout", handlers.Logout(store, cfg))

	log.Printf("Client App starting on port %s", cfg.ClientPort)
	if err := http.ListenAndServe(":"+cfg.ClientPort, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
