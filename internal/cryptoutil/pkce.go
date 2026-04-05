package cryptoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GenerateVerifier generates a 32-byte random string, then base64url encodes it without padding.
// The result is a 43-character string used as the PKCE code_verifier.
func GenerateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ComputeChallenge takes a verifier, computes its SHA256-256 hash,
// and returns the base64url encoded result without padding.
// This is used as the PKCE code_challenge (with method S256).
func ComputeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// VerifyChallenge checks if the provided verifier matches the expected challenge.
func VerifyChallenge(verifier, challenge string) bool {
	return ComputeChallenge(verifier) == challenge
}