package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/karthi0102/oauth/internal/jwtutil"
)

type JWKSHandler struct {
	PrivateKey *rsa.PrivateKey
	KID        string
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwk := jwtutil.PublicKeyToJWK(&h.PrivateKey.PublicKey, h.KID)

	resp := jwtutil.JWKSResponse{
		Keys: []jwtutil.JWK{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	json.NewEncoder(w).Encode(resp)
}
