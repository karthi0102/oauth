package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAndMigrate(t *testing.T) {
	// Use a temp file so we don't pollute the workspace
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations failed: %v", err)
	}

	// Verify all 5 tables were created
	tables := []string{"users", "clients", "auth_codes", "refresh_tokens", "resources"}
	for _, table := range tables {
		var name string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("expected table %q to exist, got error: %v", table, err)
		}
	}

	// Verify the DB file was created on disk
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("expected DB file to exist at %s", dbPath)
	}

	// Run migrations again — should be idempotent
	if err := db.RunMigrations(); err != nil {
		t.Errorf("second RunMigrations should be idempotent, got: %v", err)
	}
}
