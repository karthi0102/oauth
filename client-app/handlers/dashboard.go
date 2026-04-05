package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/karthi0102/oauth/client-app/oauth"
	"github.com/karthi0102/oauth/client-app/session"
	"github.com/karthi0102/oauth/internal/config"
)

type ProfileResponse struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Scope string `json:"scope"`
}

type ResourceItem struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

type DataResponse struct {
	Items []ResourceItem `json:"items"`
}

func Dashboard(store *session.Store, client *oauth.Client, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, sessionData := store.GetSession(r)
		if sessionData == nil || sessionData.AccessToken == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if time.Until(sessionData.ExpiresAt) < 60*time.Second && sessionData.RefreshToken != "" {
			tokens, err := client.RefreshToken(sessionData.RefreshToken)
			if err != nil {
				store.DestroySession(w, r)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			sessionData.AccessToken = tokens.AccessToken
			if tokens.RefreshToken != "" {
				sessionData.RefreshToken = tokens.RefreshToken
			}
			sessionData.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
			store.SaveSession(sessionID, sessionData)
		}

		profile, err := fetchProfile(cfg.ResourceServerURL, sessionData.AccessToken)
		if err != nil {
			http.Error(w, "Failed to fetch profile: "+err.Error(), http.StatusInternalServerError)
			return
		}

		dataRes, err := fetchData(cfg.ResourceServerURL, sessionData.AccessToken)
		if err != nil {
			http.Error(w, "Failed to fetch data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		t, err := template.ParseFiles("client-app/templates/dashboard.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		t.Execute(w, map[string]interface{}{
			"UserInfo": sessionData.UserInfo,
			"Profile":  profile,
			"Data":     dataRes.Items,
		})
	}
}

func fetchProfile(resourceServerURL, token string) (*ProfileResponse, error) {
	req, _ := http.NewRequest("GET", resourceServerURL+"/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var profile ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func fetchData(resourceServerURL, token string) (*DataResponse, error) {
	req, _ := http.NewRequest("GET", resourceServerURL+"/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var data DataResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}
