package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/karthi0102/oauth/internal/store"
)

type LoginHandler struct {
	DB   *store.DB
	Tmpl *template.Template
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")

	if r.Method == http.MethodGet {
		h.Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Next": next})
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		email := strings.ToLower(r.FormValue("email"))
		password := r.FormValue("password")
		next = r.FormValue("next") // Try to get next from form data if posted

		user, err := h.DB.GetUserByEmail(email)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
			h.Tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{"Error": "Invalid email or password", "Next": next})
			return
		}

		// Login success
		createSession(w, user.ID)

		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
		} else {
			// No next URL, redirect to a default page or show success
			w.Write([]byte("Logged in successfully"))
		}
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
