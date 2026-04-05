package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/karthi0102/oauth/internal/middleware"
)

// Profile returns user profile information.
// It requires the "profile:read" scope.
func Profile(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)

	nameSuffix := sub
	if len(sub) > 8 {
		nameSuffix = sub[:8]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":   sub,
		"name":  "User " + nameSuffix,
		"email": "user_" + nameSuffix + "@example.com",
		"scope": scope,
	})
}
