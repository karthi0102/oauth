package handlers

import (
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/karthi0102/oauth/internal/store"
)

type ConsentHandler struct {
	DB *store.DB
}

func (h *ConsentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	userID := getSessionUser(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	decision := r.FormValue("decision")
	state := r.FormValue("state")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scopeRaw := r.FormValue("scope")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("state", state)

	if decision == "deny" {
		q.Set("error", "access_denied")
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}

	if decision != "approve" {
		http.Error(w, "Invalid decision", http.StatusBadRequest)
		return
	}

	// Generate Auth Code
	code := uuid.New().String()
	authCode := &store.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		Scope:               scopeRaw,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(60 * time.Second), // 60s expiry
		CreatedAt:           time.Now(),
		// Nonce could be handled if provided; leaving NULL for now
	}

	if err := h.DB.SaveCode(authCode); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	q.Set("code", code)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
