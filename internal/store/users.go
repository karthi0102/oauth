package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
	CreatedAt    time.Time
}

func (db *DB) CreateUser(id, email, passwordHash, name string) error {
	query := `INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, id, email, passwordHash, name)
	if err != nil {
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

func (db *DB) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, password_hash, name, created_at FROM users WHERE email = ?`
	row := db.QueryRow(query, email)
	return parseUser(row)
}

func (db *DB) GetUserByID(id string) (*User, error) {
	query := `SELECT id, email, password_hash, name, created_at FROM users WHERE id = ?`
	row := db.QueryRow(query, id)
	return parseUser(row)
}

func parseUser(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil if not found
		}
		return nil, fmt.Errorf("store: scan user: %w", err)
	}
	return &u, nil
}
