package handlers

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/karthi0102/oauth/internal/store"
)

type AuthorizeHandler struct {
	DB   *store.DB
	Tmpl *template.Template
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scopeRaw := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if responseType != "code" {
		http.Error(w, "Unsupported response_type", http.StatusBadRequest)
		return
	}
	if state == "" || codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "Missing or invalid PKCE or state parameters", http.StatusBadRequest)
		return
	}

	client, err := h.DB.GetClient(clientID)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if client == nil {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect URI (in a real app, this should be exact match or list of allowed URIs)
	if !strings.Contains(client.RedirectURIs, redirectURI) {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Validate scopes
	requestedScopes := strings.Fields(scopeRaw)
	allowedScopes := strings.Fields(client.AllowedScopes)
	if !isSubset(requestedScopes, allowedScopes) {
		http.Error(w, "Invalid scopes requested", http.StatusBadRequest)
		return
	}

	userID := getSessionUser(r)
	if userID == "" {
		// Not logged in -> redirect to /login
		loginURL := "/login?next=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Render consent template
	data := map[string]interface{}{
		"ClientName":          client.Name,
		"Scopes":              requestedScopes,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"ScopeRaw":            scopeRaw,
		"State":               state,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	}

	if err := h.Tmpl.ExecuteTemplate(w, "consent.html", data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func isSubset(requested []string, allowed []string) bool {
	allowedMap := make(map[string]bool)
	for _, a := range allowed {
		allowedMap[a] = true
	}
	for _, r := range requested {
		if !allowedMap[r] {
			return false
		}
	}
	return true
}
