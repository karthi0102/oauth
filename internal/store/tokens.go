package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type RefreshToken struct {
	TokenHash string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
	RevokedAt sql.NullTime
	CreatedAt time.Time
}

func (db *DB) SaveRefreshToken(tokenHash, clientID, userID, scope string, expiresAt time.Time) error {
	query := `INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, expires_at)
		VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(query, tokenHash, clientID, userID, scope, expiresAt)
	if err != nil {
		return fmt.Errorf("store: save refresh token: %w", err)
	}
	return nil
}

func (db *DB) GetRefreshToken(tokenHash string) (*RefreshToken, error) {
	query := `SELECT token_hash, client_id, user_id, scope, expires_at, revoked_at, created_at
		FROM refresh_tokens WHERE token_hash = ?`
	row := db.QueryRow(query, tokenHash)
	var rt RefreshToken
	err := row.Scan(&rt.TokenHash, &rt.ClientID, &rt.UserID, &rt.Scope, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // not found
		}
		return nil, fmt.Errorf("store: scan refresh token: %w", err)
	}
	return &rt, nil
}

func (db *DB) RevokeToken(tokenHash string) error {
	query := `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?`
	_, err := db.Exec(query, tokenHash)
	if err != nil {
		return fmt.Errorf("store: revoke token: %w", err)
	}
	return nil
}
