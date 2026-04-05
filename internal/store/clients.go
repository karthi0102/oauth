package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	ID            string
	SecretHash    string
	Name          string
	RedirectURIs  string
	AllowedScopes string
	CreatedAt     time.Time
}

func (db *DB) GetClient(id string) (*Client, error) {
	query := `SELECT id, secret_hash, name, redirect_uris, allowed_scopes, created_at FROM clients WHERE id = ?`
	row := db.QueryRow(query, id)
	return parseClient(row)
}

func (db *DB) ValidateClientSecret(id, secret string) (*Client, error) {
	client, err := db.GetClient(id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("client not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(secret))
	if err != nil {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

func parseClient(row *sql.Row) (*Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.SecretHash, &c.Name, &c.RedirectURIs, &c.AllowedScopes, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan client: %w", err)
	}
	return &c, nil
}
