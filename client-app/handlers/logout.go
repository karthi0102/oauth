package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/karthi0102/oauth/client-app/session"
	"github.com/karthi0102/oauth/internal/config"
)

func Logout(store *session.Store, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, sessionData := store.GetSession(r)

		if sessionData != nil && sessionData.RefreshToken != "" {
			data := url.Values{}
			data.Set("token", sessionData.RefreshToken)
			data.Set("client_id", cfg.ClientID)
			data.Set("client_secret", cfg.ClientSecret)

			req, _ := http.NewRequest("POST", cfg.AuthServerURL+"/revoke", strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			client := &http.Client{}
			client.Do(req)
		}

		if sessionID != "" {
			store.DestroySession(w, r)
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
