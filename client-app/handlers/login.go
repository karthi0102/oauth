package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/karthi0102/oauth/client-app/oauth"
	"github.com/karthi0102/oauth/client-app/session"
	"github.com/karthi0102/oauth/internal/cryptoutil"
)

func Login(store *session.Store, client *oauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := uuid.New().String()
		verifier, err := cryptoutil.GenerateVerifier()
		if err != nil {
			http.Error(w, "Failed to generate verifier", http.StatusInternalServerError)
			return
		}

		challenge := cryptoutil.ComputeChallenge(verifier)

		// Save state and verifier in session
		store.CreateSession(w, &session.SessionData{
			State:        state,
			CodeVerifier: verifier,
		})

		authURL := client.BuildAuthURL(state, challenge)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
