package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/karthi0102/oauth/internal/store"
)

type RegisterHandler struct {
	DB   *store.DB
	Tmpl *template.Template
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.Tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		name := r.FormValue("name")
		email := strings.ToLower(r.FormValue("email"))
		password := r.FormValue("password")

		if name == "" || email == "" || password == "" {
			h.Tmpl.ExecuteTemplate(w, "register.html", map[string]string{"Error": "All fields are required"})
			return
		}

		// Check if user exists
		existing, err := h.DB.GetUserByEmail(email)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if existing != nil {
			h.Tmpl.ExecuteTemplate(w, "register.html", map[string]string{"Error": "Email already registered"})
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		userID := uuid.New().String()
		err = h.DB.CreateUser(userID, email, string(hash), name)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
