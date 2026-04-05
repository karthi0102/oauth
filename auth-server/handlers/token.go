package handlers

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/karthi0102/oauth/internal/config"
	"github.com/karthi0102/oauth/internal/cryptoutil"
	"github.com/karthi0102/oauth/internal/jwtutil"
	"github.com/karthi0102/oauth/internal/store"
)

type TokenHandler struct {
	DB         *store.DB
	Config     *config.Config
	PrivateKey *rsa.PrivateKey
	KID        string
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	client, err := h.DB.ValidateClientSecret(clientID, clientSecret)
	if err != nil {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	switch grantType {
	case "authorization_code":
		h.handleAuthCode(w, r, client)
	case "refresh_token":
		h.handleRefreshToken(w, r, client)
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
	}
}

func (h *TokenHandler) handleAuthCode(w http.ResponseWriter, r *http.Request, client *store.Client) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	authCode, err := h.DB.GetCode(code)
	if err != nil || authCode == nil {
		http.Error(w, "Invalid or expired code", http.StatusBadRequest)
		return
	}

	if authCode.UsedAt.Valid || authCode.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Code already used or expired", http.StatusBadRequest)
		return
	}

	if authCode.ClientID != client.ID || authCode.RedirectURI != redirectURI {
		http.Error(w, "Invalid client or redirect URI", http.StatusBadRequest)
		return
	}

	// PKCE check
	if !cryptoutil.VerifyChallenge(codeVerifier, authCode.CodeChallenge) {
		http.Error(w, "Invalid code verifier", http.StatusBadRequest)
		return
	}

	h.DB.MarkCodeUsed(code)

	user, _ := h.DB.GetUserByID(authCode.UserID)
	if user == nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	// Access Token
	atClaims := jwtutil.AccessTokenClaims{
		Sub:      user.ID,
		Iss:      h.Config.Issuer,
		Aud:      h.Config.ResourceServerURL, // Resource server URL from config
		Exp:      now.Add(time.Hour).Unix(),
		Iat:      now.Unix(),
		Jti:      uuid.New().String(),
		Scope:    authCode.Scope,
		ClientID: client.ID,
	}

	atMap := toMap(atClaims)
	accessToken, _ := jwtutil.Sign(atMap, h.PrivateKey, h.KID)

	nonce := ""
	if authCode.Nonce.Valid {
		nonce = authCode.Nonce.String
	}

	// ID Token
	idClaims := jwtutil.IDTokenClaims{
		Sub:           user.ID,
		Iss:           h.Config.Issuer,
		Aud:           client.ID,
		Exp:           now.Add(time.Hour).Unix(),
		Iat:           now.Unix(),
		Nonce:         nonce,
		Name:          user.Name,
		Email:         user.Email,
		EmailVerified: true,
		AuthTime:      now.Unix(), // simplifying auth_time to now
	}

	idMap := toMap(idClaims)
	idToken, _ := jwtutil.Sign(idMap, h.PrivateKey, h.KID)

	// Refresh Token
	refreshTokenRaw := uuid.New().String()
	hash := sha256.Sum256([]byte(refreshTokenRaw))
	tokenHash := hex.EncodeToString(hash[:])
	
	h.DB.SaveRefreshToken(tokenHash, client.ID, user.ID, authCode.Scope, now.Add(30*24*time.Hour))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshTokenRaw,
		"id_token":      idToken,
		"scope":         authCode.Scope,
	})
}

func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request, client *store.Client) {
	refreshTokenRaw := r.FormValue("refresh_token")
	if refreshTokenRaw == "" {
		http.Error(w, "Missing refresh token", http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256([]byte(refreshTokenRaw))
	tokenHash := hex.EncodeToString(hash[:])

	rt, err := h.DB.GetRefreshToken(tokenHash)
	if err != nil || rt == nil || rt.RevokedAt.Valid || rt.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		return
	}

	if rt.ClientID != client.ID {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	user, _ := h.DB.GetUserByID(rt.UserID)
	now := time.Now()
	
	atClaims := jwtutil.AccessTokenClaims{
		Sub:      user.ID,
		Iss:      h.Config.Issuer,
		Aud:      h.Config.ResourceServerURL,
		Exp:      now.Add(time.Hour).Unix(),
		Iat:      now.Unix(),
		Jti:      uuid.New().String(),
		Scope:    rt.Scope,
		ClientID: client.ID,
	}

	atMap := toMap(atClaims)
	accessToken, _ := jwtutil.Sign(atMap, h.PrivateKey, h.KID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        rt.Scope,
	})
}

func toMap(v interface{}) map[string]interface{} {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	return m
}
