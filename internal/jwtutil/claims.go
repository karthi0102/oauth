package jwtutil

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AccessTokenClaims represents the claims embedded in an OAuth 2.0 access token.
// These tokens are consumed by the resource server.
type AccessTokenClaims struct {
	Sub      string `json:"sub"`       // Subject — user ID
	Iss      string `json:"iss"`       // Issuer — auth server URL
	Aud      string `json:"aud"`       // Audience — resource server URL
	Exp      int64  `json:"exp"`       // Expiration time (unix)
	Iat      int64  `json:"iat"`       // Issued at (unix)
	Jti      string `json:"jti"`       // JWT ID — unique identifier
	Scope    string `json:"scope"`     // Space-separated scopes
	ClientID string `json:"client_id"` // OAuth client that requested the token
}

// IDTokenClaims represents the claims embedded in an OpenID Connect ID token.
// These tokens are consumed by the client app.
type IDTokenClaims struct {
	Sub           string `json:"sub"`                    // Subject — user ID
	Iss           string `json:"iss"`                    // Issuer — auth server URL
	Aud           string `json:"aud"`                    // Audience — client_id
	Exp           int64  `json:"exp"`                    // Expiration time (unix)
	Iat           int64  `json:"iat"`                    // Issued at (unix)
	Nonce         string `json:"nonce,omitempty"`        // Replay protection
	Name          string `json:"name"`                   // User display name
	Email         string `json:"email"`                  // User email
	EmailVerified bool   `json:"email_verified"`         // Whether email is verified
	AuthTime      int64  `json:"auth_time"`              // Time of authentication (unix)
}

// NewAccessTokenClaims creates a new AccessTokenClaims with standard fields
// pre-populated (iat, exp, jti). The caller supplies identity and scope data.
//
// The token is valid for 1 hour (3600 seconds) as per the spec.
func NewAccessTokenClaims(sub, iss, aud, scope, clientID string) AccessTokenClaims {
	now := time.Now().Unix()
	return AccessTokenClaims{
		Sub:      sub,
		Iss:      iss,
		Aud:      aud,
		Exp:      now + 3600, // 1 hour
		Iat:      now,
		Jti:      uuid.New().String(),
		Scope:    scope,
		ClientID: clientID,
	}
}

// NewIDTokenClaims creates a new IDTokenClaims with standard fields
// pre-populated (iat, exp). The caller supplies identity data.
//
// The token is valid for 1 hour (3600 seconds) as per the spec.
func NewIDTokenClaims(sub, iss, aud, nonce, name, email string, authTime int64) IDTokenClaims {
	now := time.Now().Unix()
	return IDTokenClaims{
		Sub:           sub,
		Iss:           iss,
		Aud:           aud,
		Exp:           now + 3600, // 1 hour
		Iat:           now,
		Nonce:         nonce,
		Name:          name,
		Email:         email,
		EmailVerified: true,
		AuthTime:      authTime,
	}
}

// ToMap converts AccessTokenClaims to map[string]any for use with jwtutil.Sign().
// This is the bridge between typed claims and the generic JWT signing function.
func (c AccessTokenClaims) ToMap() map[string]any {
	return map[string]any{
		"sub":       c.Sub,
		"iss":       c.Iss,
		"aud":       c.Aud,
		"exp":       c.Exp,
		"iat":       c.Iat,
		"jti":       c.Jti,
		"scope":     c.Scope,
		"client_id": c.ClientID,
	}
}

// ToMap converts IDTokenClaims to map[string]any for use with jwtutil.Sign().
func (c IDTokenClaims) ToMap() map[string]any {
	m := map[string]any{
		"sub":            c.Sub,
		"iss":            c.Iss,
		"aud":            c.Aud,
		"exp":            c.Exp,
		"iat":            c.Iat,
		"name":           c.Name,
		"email":          c.Email,
		"email_verified": c.EmailVerified,
		"auth_time":      c.AuthTime,
	}
	// Only include nonce if it was provided (omitempty equivalent)
	if c.Nonce != "" {
		m["nonce"] = c.Nonce
	}
	return m
}

// AccessTokenClaimsFromMap converts a raw claims map (returned by Verify)
// back into a typed AccessTokenClaims struct.
func AccessTokenClaimsFromMap(m map[string]any) (AccessTokenClaims, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return AccessTokenClaims{}, fmt.Errorf("marshal claims map: %w", err)
	}
	var c AccessTokenClaims
	if err := json.Unmarshal(data, &c); err != nil {
		return AccessTokenClaims{}, fmt.Errorf("unmarshal to AccessTokenClaims: %w", err)
	}
	return c, nil
}

// IDTokenClaimsFromMap converts a raw claims map (returned by ParseUnverified)
// back into a typed IDTokenClaims struct.
func IDTokenClaimsFromMap(m map[string]any) (IDTokenClaims, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("marshal claims map: %w", err)
	}
	var c IDTokenClaims
	if err := json.Unmarshal(data, &c); err != nil {
		return IDTokenClaims{}, fmt.Errorf("unmarshal to IDTokenClaims: %w", err)
	}
	return c, nil
}

// IsExpired returns true if the access token has expired.
func (c AccessTokenClaims) IsExpired() bool {
	return c.Exp <= time.Now().Unix()
}

// IsExpired returns true if the ID token has expired.
func (c IDTokenClaims) IsExpired() bool {
	return c.Exp <= time.Now().Unix()
}

// ValidateStandard checks the standard access token claims:
//   - iss matches expectedIssuer
//   - aud matches expectedAudience
//   - token is not expired
func (c AccessTokenClaims) ValidateStandard(expectedIssuer, expectedAudience string) error {
	if c.Iss != expectedIssuer {
		return fmt.Errorf("issuer mismatch: got %q, want %q", c.Iss, expectedIssuer)
	}
	if c.Aud != expectedAudience {
		return fmt.Errorf("audience mismatch: got %q, want %q", c.Aud, expectedAudience)
	}
	if c.IsExpired() {
		return fmt.Errorf("token expired at %d, current time %d", c.Exp, time.Now().Unix())
	}
	return nil
}

// HasScope checks whether the access token contains a specific scope.
// Scopes are space-separated in the Scope field.
func (c AccessTokenClaims) HasScope(scope string) bool {
	// Fast path: exact match
	if c.Scope == scope {
		return true
	}
	// Check space-separated list
	for _, s := range splitScopes(c.Scope) {
		if s == scope {
			return true
		}
	}
	return false
}

// splitScopes splits a space-separated scope string into individual scopes.
// Handles multiple spaces and leading/trailing whitespace.
func splitScopes(scope string) []string {
	var scopes []string
	current := ""
	for _, ch := range scope {
		if ch == ' ' {
			if current != "" {
				scopes = append(scopes, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		scopes = append(scopes, current)
	}
	return scopes
}