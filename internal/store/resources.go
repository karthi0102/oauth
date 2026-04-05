package store

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Resource represents a protected data item.
type Resource struct {
	ID        string    `json:"id"`
	OwnerSub  string    `json:"owner_sub"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// SeedResources seeds some sample data into the resources table.
// It creates items for a specific ownerSub if the table is empty.
func (db *DB) SeedResources(ownerSub string) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM resources").Scan(&count)
	if err != nil {
		return fmt.Errorf("store: failed to check resources count: %w", err)
	}

	if count > 0 {
		return nil // Already seeded
	}

	resources := []Resource{
		{
			ID:       uuid.New().String(),
			OwnerSub: ownerSub,
			Title:    "Secret Bank Details",
			Body:     "Account balance is ONE MILLION DOLLARS.",
		},
		{
			ID:       uuid.New().String(),
			OwnerSub: ownerSub,
			Title:    "Private Diary Entry",
			Body:     "Today I built an OAuth 2.0 server from scratch.",
		},
	}

	for _, r := range resources {
		query := `
			INSERT INTO resources (id, owner_sub, title, body)
			VALUES (?, ?, ?, ?)
		`
		_, err := db.Exec(query, r.ID, r.OwnerSub, r.Title, r.Body)
		if err != nil {
			return fmt.Errorf("store: failed to insert seed resource: %w", err)
		}
	}

	return nil
}

// GetResourcesByOwner retrieves all resources for a specific user ID (sub).
func (db *DB) GetResourcesByOwner(ownerSub string) ([]Resource, error) {
	query := `
		SELECT id, owner_sub, title, body, created_at
		FROM resources
		WHERE owner_sub = ?
		ORDER BY created_at DESC
	`
	rows, err := db.Query(query, ownerSub)
	if err != nil {
		return nil, fmt.Errorf("store: query resources by owner: %w", err)
	}
	defer rows.Close()

	var resources []Resource
	for rows.Next() {
		var r Resource
		if err := rows.Scan(&r.ID, &r.OwnerSub, &r.Title, &r.Body, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan resource row: %w", err)
		}
		resources = append(resources, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: resources rows iteration error: %w", err)
	}

	return resources, nil
}
