package session

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

type UserInfo struct {
	Sub   string
	Name  string
	Email string
}

type SessionData struct {
	UserID       string
	AccessToken  string
	IDToken      string
	RefreshToken string
	UserInfo     UserInfo  // decoded from id_token
	State        string    // stored during login, verified on callback
	CodeVerifier string    // stored during login, sent on callback
	ExpiresAt    time.Time // access token expiry
}

type Store struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
}

func NewStore() *Store {
	return &Store{
		sessions: make(map[string]*SessionData),
	}
}

// GetSession retrieves the session data for the given request.
// It returns the session ID and the session data (if found).
func (s *Store) GetSession(r *http.Request) (string, *SessionData) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return "", nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.sessions[cookie.Value]
	if !exists {
		return "", nil
	}
	return cookie.Value, data
}

// CreateSession generates a new session ID, stores the given data, and sets the cookie.
func (s *Store) CreateSession(w http.ResponseWriter, data *SessionData) string {
	sessionID := uuid.New().String()

	s.mu.Lock()
	s.sessions[sessionID] = data
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return sessionID
}

// SaveSession updates the session data for a given session ID.
func (s *Store) SaveSession(sessionID string, data *SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = data
}

// DestroySession removes the session and clears the cookie.
func (s *Store) DestroySession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
