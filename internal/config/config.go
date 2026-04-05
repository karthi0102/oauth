package config

import (
	"os"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the three services.
// Each binary reads only the fields it needs.
type Config struct {
	// shared
	DBPath string

	// auth server
	AuthPort string
	Issuer   string
	KeyPath  string

	// resource server
	ResourcePort string
	Audience     string
	JWKSUrl      string
	ExpectedIss  string

	// client app
	ClientPort        string
	ClientID          string
	ClientSecret      string
	RedirectURI       string
	AuthServerURL     string
	ResourceServerURL string
	SessionSecret     string
}

// Load reads .env (if present) and populates Config from environment variables.
func Load() *Config {
	godotenv.Load() // ignore error — .env is optional
	return &Config{
		AuthPort:          getEnv("AUTH_SERVER_PORT", "8080"),
		Issuer:            getEnv("AUTH_SERVER_ISSUER", "http://localhost:8080"),
		KeyPath:           getEnv("AUTH_SERVER_KEY_PATH", "./keys/private.pem"),
		DBPath:            getEnv("AUTH_SERVER_DB_PATH", "./auth.db"),
		ResourcePort:      getEnv("RESOURCE_SERVER_PORT", "9090"),
		Audience:          getEnv("RESOURCE_SERVER_AUDIENCE", "http://localhost:9090"),
		JWKSUrl:           getEnv("RESOURCE_SERVER_JWKS_URL", "http://localhost:8080/.well-known/jwks.json"),
		ExpectedIss:       getEnv("RESOURCE_SERVER_ISSUER", "http://localhost:8080"),
		ClientPort:        getEnv("CLIENT_APP_PORT", "3000"),
		ClientID:          getEnv("CLIENT_APP_CLIENT_ID", "client_app_001"),
		ClientSecret:      getEnv("CLIENT_APP_CLIENT_SECRET", ""),
		RedirectURI:       getEnv("CLIENT_APP_REDIRECT_URI", "http://localhost:3000/callback"),
		AuthServerURL:     getEnv("CLIENT_APP_AUTH_SERVER_URL", "http://localhost:8080"),
		ResourceServerURL: getEnv("CLIENT_APP_RESOURCE_SERVER_URL", "http://localhost:9090"),
		SessionSecret:     getEnv("CLIENT_APP_SESSION_SECRET", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
