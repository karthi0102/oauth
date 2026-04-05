package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/karthi0102/oauth/internal/config"
)

type DiscoveryHandler struct {
	Config *config.Config
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseURL := h.Config.Issuer

	doc := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/authorize",
		"token_endpoint":                        baseURL + "/token",
		"userinfo_endpoint":                     baseURL + "/userinfo",
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"revocation_endpoint":                   baseURL + "/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "data:read", "profile:read"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
