package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/karthi0102/oauth/internal/config"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type Client struct {
	Config *config.Config
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		Config: cfg,
	}
}

func (c *Client) BuildAuthURL(state, challenge string) string {
	u, _ := url.Parse(c.Config.AuthServerURL + "/authorize")
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.Config.ClientID)
	q.Set("redirect_uri", c.Config.RedirectURI)
	q.Set("scope", "openid profile:read data:read")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) ExchangeCode(code, verifier string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", c.Config.ClientID)
	data.Set("client_secret", c.Config.ClientSecret)
	data.Set("redirect_uri", c.Config.RedirectURI)
	data.Set("code_verifier", verifier)

	return c.postFormTokens(c.Config.AuthServerURL+"/token", data)
}

func (c *Client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.Config.ClientID)
	data.Set("client_secret", c.Config.ClientSecret)

	return c.postFormTokens(c.Config.AuthServerURL+"/token", data)
}

func (c *Client) postFormTokens(endpoint string, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status: %s", resp.Status)
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}

	return &tr, nil
}
