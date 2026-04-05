package handlers

import (
	"html/template"
	"net/http"

	"github.com/karthi0102/oauth/client-app/session"
)

func Home(store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("client-app/templates/home.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sessionID, sessionData := store.GetSession(r)
		isLoggedIn := sessionID != "" && sessionData != nil && sessionData.AccessToken != ""

		t.Execute(w, map[string]interface{}{
			"IsLoggedIn": isLoggedIn,
		})
	}
}
