package jwtutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken    = errors.New("invalid token format")
	ErrUnsupportedAlg  = errors.New("unsupported signing algorithm (only RS256 is accepted)")
	ErrSignatureInvalid = errors.New("signature verification failed")
	ErrTokenExpired    = errors.New("token has expired")
	ErrMissingKID      = errors.New("missing kid in token header")
)

// base64url encodes data using unpadded base64url encoding (RFC 4648 §5).
func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64urlDecode decodes an unpadded base64url string.
func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Sign creates a signed RS256 JWT from the given claims.
//
// Steps:
//  1. Build header: {"alg":"RS256","typ":"JWT","kid": kid}
//  2. Marshal claims to JSON
//  3. Base64url encode both (no padding)
//  4. signingInput = encodedHeader + "." + encodedPayload
//  5. digest = SHA256(signingInput)
//  6. signature = rsa.SignPKCS1v15(rand, key, crypto.SHA256, digest)
//  7. Return signingInput + "." + base64url(signature)
func Sign(claims map[string]any, privateKey *rsa.PrivateKey, kid string) (string, error) {
	// 1. Build header
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	// 2. Marshal claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	// 3. Base64url encode both (no padding)
	encodedHeader := base64urlEncode(headerJSON)
	encodedPayload := base64urlEncode(claimsJSON)

	// 4. signingInput = encodedHeader + "." + encodedPayload
	signingInput := encodedHeader + "." + encodedPayload

	// 5. digest = SHA256(signingInput)
	digest := sha256.Sum256([]byte(signingInput))

	// 6. signature = rsa.SignPKCS1v15(rand, key, crypto.SHA256, digest)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// 7. Return signingInput + "." + base64url(signature)
	return signingInput + "." + base64urlEncode(signature), nil
}

// Verify parses and verifies an RS256 JWT.
//
// keyFunc is called with the kid from the token header and must return the
// corresponding RSA public key (e.g. from a JWKS cache).
//
// Steps:
//  1.  Split on "." — must have exactly 3 parts
//  2.  Decode header — read "kid" and "alg" fields
//  3.  Reject if alg != "RS256" (never accept "none")
//  4.  Fetch public key via keyFunc(kid)
//  5.  signingInput = parts[0] + "." + parts[1]
//  6.  digest = SHA256(signingInput)
//  7.  signature = base64url decode parts[2]
//  8.  rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, digest, signature)
//  9.  Decode payload JSON → map[string]any
//  10. Check exp > time.Now().Unix()
//  11. Return claims
func Verify(tokenString string, keyFunc func(kid string) (*rsa.PublicKey, error)) (map[string]any, error) {
	// 1. Split on "." — must have exactly 3 parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// 2. Decode header — read "kid" and "alg"
	headerBytes, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal header: %w", err)
	}

	// 3. Reject if alg != "RS256"
	if header["alg"] != "RS256" {
		return nil, ErrUnsupportedAlg
	}

	kid, ok := header["kid"]
	if !ok || kid == "" {
		return nil, ErrMissingKID
	}

	// 4. Fetch public key via keyFunc(kid)
	pubKey, err := keyFunc(kid)
	if err != nil {
		return nil, fmt.Errorf("get public key for kid %q: %w", kid, err)
	}

	// 5. signingInput = parts[0] + "." + parts[1]
	signingInput := parts[0] + "." + parts[1]

	// 6. digest = SHA256(signingInput)
	digest := sha256.Sum256([]byte(signingInput))

	// 7. signature = base64url decode parts[2]
	signature, err := base64urlDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	// 8. rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, digest, signature)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, ErrSignatureInvalid
	}

	// 9. Decode payload JSON → map[string]any
	payloadBytes, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	// 10. Check exp > time.Now().Unix()
	if exp, ok := claims["exp"]; ok {
		var expFloat float64
		switch v := exp.(type) {
		case float64:
			expFloat = v
		case json.Number:
			expFloat, err = v.Float64()
			if err != nil {
				return nil, fmt.Errorf("invalid exp value: %w", err)
			}
		default:
			return nil, fmt.Errorf("invalid exp type: %T", exp)
		}

		if int64(expFloat) <= time.Now().Unix() {
			return nil, ErrTokenExpired
		}
	}

	// 11. Return claims
	return claims, nil
}

// ParseUnverified parses a JWT without verifying the signature.
// This is used by the client app to read id_token claims after receiving
// them over a trusted back-channel (the token endpoint response).
//
// It still validates the token structure but skips cryptographic verification.
func ParseUnverified(tokenString string) (map[string]any, error) {
	// Split on "." — must have exactly 3 parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode payload (parts[1])
	payloadBytes, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	return claims, nil
}
