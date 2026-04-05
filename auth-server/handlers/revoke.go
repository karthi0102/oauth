package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/karthi0102/oauth/internal/store"
)

type RevokeHandler struct {
	DB *store.DB
}

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	token := r.FormValue("token")

	// RFC 7009 says we should authenticate the client.
	client, err := h.DB.ValidateClientSecret(clientID, clientSecret)
	if err != nil || client == nil {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	if token != "" {
		hash := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(hash[:])

		// It's safe if it fails or if the token belongs to someone else, RFC 7009 says
		// always return 200 OK whether the token was revoked or not found.
		// For strict compliance, we should only revoke if the token was issued to this client.
		rt, err := h.DB.GetRefreshToken(tokenHash)
		if err == nil && rt != nil && rt.ClientID == client.ID {
			h.DB.RevokeToken(tokenHash)
		}
	}

	w.WriteHeader(http.StatusOK)
}
