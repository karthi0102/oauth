package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/karthi0102/oauth/internal/jwtutil"
)

type contextKey string

const claimsKey contextKey = "claims"

var (
	authKeyFunc func(kid string) (*rsa.PublicKey, error)
	authIss     string
	authAud     string
)

// InitAuth initializes the middleware's configuration.
// It is intended to be called at application startup with specific config values.
func InitAuth(keyFunc func(kid string) (*rsa.PublicKey, error), iss, aud string) {
	authKeyFunc = keyFunc
	authIss = iss
	authAud = aud
}

// RequireAuth extracts "Authorization: Bearer <token>", validates the token utilizing
// the provided key function, verifies ISS and AUD claims, and puts claims in context.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeAuthError(w, "invalid_token")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := jwtutil.Verify(tokenString, authKeyFunc)
		if err != nil {
			writeAuthError(w, "invalid_token")
			return
		}

		if iss, ok := claims["iss"].(string); !ok || iss != authIss {
			writeAuthError(w, "invalid_token")
			return
		}

		if aud, ok := claims["aud"].(string); !ok || aud != authAud {
			writeAuthError(w, "invalid_token")
			return
		}

		// Validate exp claim (often also done inside jwtutil.Verify, handled here to be doubly sure/explicit)
		if expFloat, ok := claims["exp"].(float64); ok {
			if int64(expFloat) <= time.Now().Unix() {
				writeAuthError(w, "invalid_token")
				return
			}
		} else if expInt, ok := claims["exp"].(int64); ok {
			if expInt <= time.Now().Unix() {
				writeAuthError(w, "invalid_token")
				return
			}
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// RequireScope returns a middleware configured to check if the claims have the specific scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r)
			if claims == nil {
				writeScopeError(w)
				return
			}

			scopeStr, ok := claims["scope"].(string)
			if !ok {
				writeScopeError(w)
				return
			}

			scopes := strings.Split(scopeStr, " ")
			hasScope := false
			for _, s := range scopes {
				if s == scope {
					hasScope = true
					break
				}
			}

			if !hasScope {
				writeScopeError(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeScopeError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{"error": "insufficient_scope"})
}

// GetClaims retrieves JWT claims from the request context.
func GetClaims(r *http.Request) map[string]any {
	claims, ok := r.Context().Value(claimsKey).(map[string]any)
	if !ok {
		return nil
	}
	return claims
}
