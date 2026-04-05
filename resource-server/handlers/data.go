package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/karthi0102/oauth/internal/middleware"
	"github.com/karthi0102/oauth/internal/store"
)

// DataHandler handles requests to the protected data endpoint.
type DataHandler struct {
	DB *store.DB
}

// Data returns the resources owned by the user.
// It requires the "data:read" scope.
func (h *DataHandler) Data(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		http.Error(w, "Invalid token claims: sub missing", http.StatusUnauthorized)
		return
	}

	items, err := h.DB.GetResourcesByOwner(sub)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Make sure we don't return null if items is empty
	if items == nil {
		items = []store.Resource{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"items": items,
	})
}
