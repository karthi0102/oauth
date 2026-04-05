package store

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

// DB wraps the sql.DB connection to SQLite.
type DB struct {
	*sql.DB
}

// Open creates or opens a SQLite database at the given path.
// It enables WAL mode and foreign keys for performance and correctness.
func Open(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("store: open db: %w", err)
	}

	// Verify the connection is alive
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store: ping db: %w", err)
	}

	log.Printf("[store] opened database: %s", dbPath)
	return &DB{db}, nil
}

// RunMigrations creates all tables if they don't already exist.
// This is safe to call on every startup — CREATE TABLE IF NOT EXISTS is idempotent.
func (db *DB) RunMigrations() error {
	migrations := []struct {
		name string
		sql  string
	}{
		{
			name: "create_users_table",
			sql: `CREATE TABLE IF NOT EXISTS users (
				id            TEXT PRIMARY KEY,
				email         TEXT UNIQUE NOT NULL,
				password_hash TEXT NOT NULL,
				name          TEXT NOT NULL,
				created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
			);`,
		},
		{
			name: "create_clients_table",
			sql: `CREATE TABLE IF NOT EXISTS clients (
				id              TEXT PRIMARY KEY,
				secret_hash     TEXT NOT NULL,
				name            TEXT NOT NULL,
				redirect_uris   TEXT NOT NULL,
				allowed_scopes  TEXT NOT NULL,
				created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
			);`,
		},
		{
			name: "create_auth_codes_table",
			sql: `CREATE TABLE IF NOT EXISTS auth_codes (
				code                  TEXT PRIMARY KEY,
				client_id             TEXT NOT NULL,
				user_id               TEXT NOT NULL,
				scope                 TEXT NOT NULL,
				redirect_uri          TEXT NOT NULL,
				code_challenge        TEXT NOT NULL,
				code_challenge_method TEXT NOT NULL DEFAULT 'S256',
				nonce                 TEXT,
				expires_at            DATETIME NOT NULL,
				used_at               DATETIME,
				created_at            DATETIME DEFAULT CURRENT_TIMESTAMP
			);`,
		},
		{
			name: "create_refresh_tokens_table",
			sql: `CREATE TABLE IF NOT EXISTS refresh_tokens (
				token_hash   TEXT PRIMARY KEY,
				client_id    TEXT NOT NULL,
				user_id      TEXT NOT NULL,
				scope        TEXT NOT NULL,
				expires_at   DATETIME NOT NULL,
				revoked_at   DATETIME,
				created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
			);`,
		},
		{
			name: "create_resources_table",
			sql: `CREATE TABLE IF NOT EXISTS resources (
				id         TEXT PRIMARY KEY,
				owner_sub  TEXT NOT NULL,
				title      TEXT NOT NULL,
				body       TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);`,
		},
	}

	for _, m := range migrations {
		if _, err := db.Exec(m.sql); err != nil {
			return fmt.Errorf("store: migration %q failed: %w", m.name, err)
		}
		log.Printf("[store] migration OK: %s", m.name)
	}

	log.Println("[store] all migrations completed successfully")
	return nil
}
