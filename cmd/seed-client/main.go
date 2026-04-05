package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading it, continuing with environment variables")
	}

	clientID := os.Getenv("CLIENT_APP_CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_APP_CLIENT_SECRET")
	redirectURI := os.Getenv("CLIENT_APP_REDIRECT_URI")
	dbPath := os.Getenv("AUTH_SERVER_DB_PATH")
	if dbPath == "" {
		dbPath = "./auth.db"
	}

	if clientID == "" || clientSecret == "" {
		log.Fatal("CLIENT_APP_CLIENT_ID and CLIENT_APP_CLIENT_SECRET must be set")
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash secret: %v", err)
	}

	allowedScopes := "openid profile:read data:read" // default scopes

	query := `
		INSERT INTO clients (id, secret_hash, name, redirect_uris, allowed_scopes)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET 
			secret_hash=excluded.secret_hash,
			name=excluded.name,
			redirect_uris=excluded.redirect_uris,
			allowed_scopes=excluded.allowed_scopes;
	`
	
	_, err = db.Exec(query, clientID, string(secretHash), "Demo Client App", redirectURI, allowedScopes)
	if err != nil {
		log.Fatalf("Failed to insert/update client: %v", err)
	}

	fmt.Printf("Successfully registered client %s in database %s\n", clientID, dbPath)
}
