package jwtutil

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

var (
	ErrKeyNotFound   = errors.New("key not found in JWKS")
	ErrInvalidJWK    = errors.New("invalid JWK: missing or malformed fields")
	ErrJWKSFetch     = errors.New("failed to fetch JWKS")
)

// JWKSResponse is the top-level response from a /.well-known/jwks.json endpoint.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key for RSA public keys.
type JWK struct {
	Kty string `json:"kty"` // Key type — always "RSA"
	Use string `json:"use"` // Usage — "sig" for signing
	Kid string `json:"kid"` // Key ID — used to match tokens to keys
	Alg string `json:"alg"` // Algorithm — "RS256"
	N   string `json:"n"`   // Modulus — base64url encoded
	E   string `json:"e"`   // Exponent — base64url encoded
}

// PublicKeyToJWK converts an RSA public key to a JWK struct suitable for
// inclusion in a JWKS endpoint response.
//
// The modulus (N) and exponent (E) are encoded as base64url without padding
// per RFC 7518 §6.3.1.
func PublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ParseJWKS parses a raw JWKS JSON body and returns a map of key ID → RSA public key.
//
// Each JWK in the response is decoded:
//   - N (modulus) is base64url decoded → big.Int
//   - E (exponent) is base64url decoded → int
//   - The resulting RSA public key is stored by its kid
//
// Keys with kty != "RSA" or alg != "RS256" are silently skipped.
func ParseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var resp JWKSResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(resp.Keys))

	for _, jwk := range resp.Keys {
		// Only process RSA signing keys
		if jwk.Kty != "RSA" || jwk.Alg != "RS256" {
			continue
		}
		if jwk.Kid == "" || jwk.N == "" || jwk.E == "" {
			continue
		}

		pubKey, err := jwkToPublicKey(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse JWK kid=%q: %w", jwk.Kid, err)
		}

		keys[jwk.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no valid RSA keys found", ErrInvalidJWK)
	}

	return keys, nil
}

// jwkToPublicKey converts a single JWK to an *rsa.PublicKey.
func jwkToPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode modulus (N)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus N: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent (E)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent E: %w", err)
	}
	// Convert exponent bytes to int
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// JWKSCache provides a thread-safe, lazily-loaded cache of RSA public keys
// fetched from a JWKS endpoint. It is used by the resource server to validate
// JWT signatures without needing the private key.
//
// Behaviour:
//   - On first GetKey() call, fetches the JWKS from the configured URL
//   - Caches all keys in memory
//   - If a requested kid is not found, re-fetches (handles key rotation)
//   - Uses sync.RWMutex for thread safety
type JWKSCache struct {
	jwksURL    string
	keys       map[string]*rsa.PublicKey
	mu         sync.RWMutex
	lastFetch  time.Time
	httpClient *http.Client
}

// NewJWKSCache creates a new JWKSCache that will fetch keys from the given URL.
// The cache starts empty and will be populated on the first GetKey() call.
func NewJWKSCache(jwksURL string) *JWKSCache {
	return &JWKSCache{
		jwksURL: jwksURL,
		keys:    make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetKey returns the RSA public key for the given kid.
//
// Lookup strategy:
//  1. Check the in-memory cache (read lock)
//  2. If not found, re-fetch JWKS from the endpoint (write lock)
//  3. Check again after fetch
//  4. If still not found, return ErrKeyNotFound
//
// This design handles key rotation: when the auth server rotates keys and
// starts signing with a new kid, the resource server will automatically
// fetch the updated JWKS.
func (c *JWKSCache) GetKey(kid string) (*rsa.PublicKey, error) {
	// 1. Try cached lookup first (read lock — allows concurrent reads)
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()

	if ok {
		return key, nil
	}

	// 2. Key not found — re-fetch JWKS (write lock)
	if err := c.refresh(); err != nil {
		return nil, err
	}

	// 3. Check again after refresh
	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: kid=%q", ErrKeyNotFound, kid)
	}

	return key, nil
}

// refresh fetches the JWKS from the endpoint and updates the cache.
// It holds an exclusive write lock during the update.
func (c *JWKSCache) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Rate limit: don't re-fetch more than once per 5 seconds
	// This prevents a flood of requests if many tokens arrive with an unknown kid
	if time.Since(c.lastFetch) < 5*time.Second {
		return nil
	}

	resp, err := c.httpClient.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d from %s", ErrJWKSFetch, resp.StatusCode, c.jwksURL)
	}

	// Limit body size to 1MB to prevent malicious responses
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: reading body: %v", ErrJWKSFetch, err)
	}

	keys, err := ParseJWKS(body)
	if err != nil {
		return fmt.Errorf("parse JWKS from %s: %w", c.jwksURL, err)
	}

	c.keys = keys
	c.lastFetch = time.Now()

	return nil
}

// BuildJWKSResponse creates a JWKSResponse from an RSA public key and kid.
// This is used by the auth server's /.well-known/jwks.json handler.
func BuildJWKSResponse(pub *rsa.PublicKey, kid string) JWKSResponse {
	return JWKSResponse{
		Keys: []JWK{PublicKeyToJWK(pub, kid)},
	}
}
