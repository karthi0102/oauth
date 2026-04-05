package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

var (
	sessionStore = make(map[string]string)
	sessionMutex sync.RWMutex
)

func createSession(w http.ResponseWriter, userID string) {
	b := make([]byte, 32)
	rand.Read(b)
	sessionID := base64.URLEncoding.EncodeToString(b)

	sessionMutex.Lock()
	sessionStore[sessionID] = userID
	sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   false, // set to true in prod with HTTPS
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
	})
}

// getSessionUser returns the user ID or empty string
func getSessionUser(r *http.Request) string {
	cookie, err := r.Cookie("auth_session")
	if err != nil {
		return ""
	}

	sessionMutex.RLock()
	userID := sessionStore[cookie.Value]
	sessionMutex.RUnlock()

	return userID
}
