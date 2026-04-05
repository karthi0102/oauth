package handlers

import (
	"net/http"
	"time"

	"github.com/karthi0102/oauth/client-app/oauth"
	"github.com/karthi0102/oauth/client-app/session"
	"github.com/karthi0102/oauth/internal/jwtutil"
)

func Callback(store *session.Store, client *oauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errQuery := r.URL.Query().Get("error")

		if errQuery != "" {
			http.Error(w, "Authorization failed: "+errQuery, http.StatusUnauthorized)
			return
		}

		sessionID, sessionData := store.GetSession(r)
		if sessionData == nil || sessionData.State != state {
			http.Error(w, "Invalid state or session", http.StatusBadRequest)
			return
		}

		tokens, err := client.ExchangeCode(code, sessionData.CodeVerifier)
		if err != nil {
			http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
			return
		}

		claims, err := jwtutil.ParseUnverified(tokens.IDToken)
		if err != nil {
			http.Error(w, "Failed to parse ID token", http.StatusInternalServerError)
			return
		}

		sessionData.AccessToken = tokens.AccessToken
		sessionData.IDToken = tokens.IDToken
		sessionData.RefreshToken = tokens.RefreshToken
		sessionData.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)

		if sub, ok := claims["sub"].(string); ok {
			sessionData.UserInfo.Sub = sub
		}
		if name, ok := claims["name"].(string); ok {
			sessionData.UserInfo.Name = name
		}
		if email, ok := claims["email"].(string); ok {
			sessionData.UserInfo.Email = email
		}

		store.SaveSession(sessionID, sessionData)

		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}
