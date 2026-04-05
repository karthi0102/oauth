package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	Scope               string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               sql.NullString
	ExpiresAt           time.Time
	UsedAt              sql.NullTime
	CreatedAt           time.Time
}

func (db *DB) SaveCode(c *AuthCode) error {
	query := `INSERT INTO auth_codes 
		(code, client_id, user_id, scope, redirect_uri, code_challenge, code_challenge_method, nonce, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := db.Exec(query, c.Code, c.ClientID, c.UserID, c.Scope, c.RedirectURI, c.CodeChallenge, c.CodeChallengeMethod, c.Nonce, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: save auth code: %w", err)
	}
	return nil
}

func (db *DB) GetCode(code string) (*AuthCode, error) {
	query := `SELECT code, client_id, user_id, scope, redirect_uri, code_challenge, code_challenge_method, nonce, expires_at, used_at, created_at 
		FROM auth_codes WHERE code = ?`
	row := db.QueryRow(query, code)
	var c AuthCode
	err := row.Scan(&c.Code, &c.ClientID, &c.UserID, &c.Scope, &c.RedirectURI, &c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &c.ExpiresAt, &c.UsedAt, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: scan auth code: %w", err)
	}
	return &c, nil
}

func (db *DB) MarkCodeUsed(code string) error {
	query := `UPDATE auth_codes SET used_at = CURRENT_TIMESTAMP WHERE code = ?`
	_, err := db.Exec(query, code)
	if err != nil {
		return fmt.Errorf("store: update auth code used_at: %w", err)
	}
	return nil
}
