package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/karthi0102/oauth/internal/middleware"
	"github.com/karthi0102/oauth/internal/store"
)

type UserInfoHandler struct {
	DB *store.DB
}

func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		http.Error(w, "Invalid token claims", http.StatusBadRequest)
		return
	}

	user, err := h.DB.GetUserByID(sub)
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	resp := map[string]interface{}{
		"sub":            user.ID,
		"name":           user.Name,
		"email":          user.Email,
		"email_verified": true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
