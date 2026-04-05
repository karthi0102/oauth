# OAuth 2.0 From Scratch — Go Project Specification

> Single Go module, three binaries, build this top-to-bottom.
> Hand this file to an AI coding assistant or use it as your build checklist.

---

## Project Overview

Build a complete OAuth 2.0 + OIDC stack from scratch in Go with **no OAuth libraries and no JWT libraries**. Use only Go stdlib crypto packages so you understand every layer.

**Three services, one module:**

| Service | Port | Role |
|---|---|---|
| Auth Server | `:8080` | Identity provider — runs OAuth 2.0 flow, issues JWTs |
| Resource Server | `:9090` | Protected API — validates JWTs locally, serves data |
| Client App | `:3000` | Confidential client — orchestrates the auth code flow |

**Build order: Resource Server → Auth Server → Client App**

---

## Module Initialisation

```bash
mkdir oauth-from-scratch && cd oauth-from-scratch
go mod init github.com/you/oauth-from-scratch
mkdir -p cmd/auth-server cmd/resource-server cmd/client-app
mkdir -p internal/{jwtutil,cryptoutil,middleware,store,config}
mkdir -p auth-server/handlers auth-server/templates
mkdir -p resource-server/handlers
mkdir -p client-app/handlers client-app/oauth client-app/session client-app/templates
mkdir keys
```

---

## Folder Structure

```
oauth-from-scratch/
├── go.mod                              ← single module: github.com/you/oauth-from-scratch
├── go.sum
├── Makefile
├── .env.example
├── .gitignore
│
├── cmd/                                ← entry points, one per binary
│   ├── auth-server/
│   │   └── main.go                    ← loads config, wires routes, starts :8080
│   ├── resource-server/
│   │   └── main.go                    ← loads config, wires routes, starts :9090
│   └── client-app/
│       └── main.go                    ← loads config, wires routes, starts :3000
│
├── internal/                           ← shared, compiler-enforced private packages
│   ├── jwtutil/
│   │   ├── jwt.go                     ← Sign(), Verify(), ParseUnverified()
│   │   ├── claims.go                  ← AccessTokenClaims, IDTokenClaims structs
│   │   └── jwks.go                    ← JWKSResponse struct, ParseJWKS(), key cache
│   ├── cryptoutil/
│   │   ├── rsa.go                     ← GenerateKey(), LoadKeyFromFile(), SaveKeyToFile()
│   │   └── pkce.go                    ← GenerateVerifier(), ComputeChallenge(), VerifyChallenge()
│   ├── middleware/
│   │   ├── logging.go                 ← request/response logger for all three servers
│   │   ├── recovery.go                ← panic recovery → 500 response
│   │   └── auth.go                    ← RequireAuth(next), RequireScope(scope)(next)
│   ├── store/
│   │   ├── db.go                      ← Open(path), RunMigrations() — single SQLite file
│   │   ├── users.go                   ← CreateUser, GetUserByEmail, GetUserByID
│   │   ├── clients.go                 ← RegisterClient, GetClient, ValidateClientSecret
│   │   ├── codes.go                   ← SaveCode, ConsumeCode, DeleteExpiredCodes
│   │   ├── tokens.go                  ← SaveRefreshToken, GetRefreshToken, RevokeToken
│   │   └── resources.go               ← SeedResources, GetResourcesByOwner
│   └── config/
│       └── config.go                  ← single Config struct loaded from env
│
├── auth-server/
│   └── handlers/
│       ├── authorize.go               ← GET  /authorize
│       ├── consent.go                 ← POST /authorize/consent
│       ├── token.go                   ← POST /token
│       ├── revoke.go                  ← POST /revoke
│       ├── jwks.go                    ← GET  /.well-known/jwks.json
│       ├── discovery.go               ← GET  /.well-known/openid-configuration
│       ├── userinfo.go                ← GET  /userinfo
│       ├── login.go                   ← GET+POST /login
│       └── register.go               ← GET+POST /register
│   └── templates/
│       ├── login.html
│       ├── register.html
│       └── consent.html               ← shows requested scopes to user
│
├── resource-server/
│   └── handlers/
│       ├── profile.go                 ← GET /api/profile  (scope: profile:read)
│       ├── data.go                    ← GET /api/data     (scope: data:read)
│       └── health.go                  ← GET /health       (public)
│
├── client-app/
│   ├── handlers/
│   │   ├── home.go                    ← GET /
│   │   ├── login.go                   ← GET /login
│   │   ├── callback.go                ← GET /callback
│   │   ├── dashboard.go               ← GET /dashboard
│   │   └── logout.go                  ← GET /logout
│   ├── oauth/
│   │   ├── client.go                  ← BuildAuthURL(), ExchangeCode(), RefreshToken()
│   │   └── token_store.go             ← read/write tokens from session
│   ├── session/
│   │   └── store.go                   ← in-memory map[sessionID]SessionData + cookie
│   └── templates/
│       ├── home.html
│       └── dashboard.html
│
└── keys/                               ← gitignored, generated on first run
    └── private.pem
```

---

## .env.example

```env
# Auth Server
AUTH_SERVER_PORT=8080
AUTH_SERVER_ISSUER=http://localhost:8080
AUTH_SERVER_DB_PATH=./auth.db
AUTH_SERVER_KEY_PATH=./keys/private.pem

# Resource Server
RESOURCE_SERVER_PORT=9090
RESOURCE_SERVER_AUDIENCE=http://localhost:9090
RESOURCE_SERVER_JWKS_URL=http://localhost:8080/.well-known/jwks.json
RESOURCE_SERVER_ISSUER=http://localhost:8080
RESOURCE_SERVER_DB_PATH=./resource.db

# Client App
CLIENT_APP_PORT=3000
CLIENT_APP_CLIENT_ID=client_app_001
CLIENT_APP_CLIENT_SECRET=super_secret_change_me
CLIENT_APP_REDIRECT_URI=http://localhost:3000/callback
CLIENT_APP_AUTH_SERVER_URL=http://localhost:8080
CLIENT_APP_RESOURCE_SERVER_URL=http://localhost:9090
CLIENT_APP_SESSION_SECRET=session_secret_change_me
```

---

## .gitignore

```
keys/
*.db
*.sqlite
bin/
.env
```

---

## Makefile

```makefile
.PHONY: run build tidy seed

run-auth:
	go run ./cmd/auth-server

run-resource:
	go run ./cmd/resource-server

run-client:
	go run ./cmd/client-app

build:
	go build -o bin/auth-server     ./cmd/auth-server
	go build -o bin/resource-server ./cmd/resource-server
	go build -o bin/client-app      ./cmd/client-app

tidy:
	go mod tidy

test:
	go test ./...
```

---

## Dependencies (go.mod)

```
require (
    github.com/mattn/go-sqlite3    v1.14.22   // SQLite driver
    golang.org/x/crypto            v0.22.0    // bcrypt for passwords
    github.com/google/uuid         v1.6.0     // UUIDs for jti, session IDs, codes
    github.com/joho/godotenv       v1.5.1     // load .env file
)
```

No JWT library. No OAuth library. No HTTP framework. Everything else is Go stdlib.

---

## Database Schema (single SQLite, auto-migrated on startup)

```sql
-- auth server tables
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,        -- uuid
    email        TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- bcrypt
    name         TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    id              TEXT PRIMARY KEY,     -- client_id
    secret_hash     TEXT NOT NULL,        -- bcrypt
    name            TEXT NOT NULL,
    redirect_uris   TEXT NOT NULL,        -- comma-separated
    allowed_scopes  TEXT NOT NULL,        -- space-separated
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    nonce                 TEXT,
    expires_at            DATETIME NOT NULL,
    used_at               DATETIME,
    created_at            DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash   TEXT PRIMARY KEY,        -- SHA256 of the actual token
    client_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    scope        TEXT NOT NULL,
    expires_at   DATETIME NOT NULL,
    revoked_at   DATETIME,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- resource server table
CREATE TABLE IF NOT EXISTS resources (
    id         TEXT PRIMARY KEY,
    owner_sub  TEXT NOT NULL,             -- matches user.id from auth server
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## internal/jwtutil — Build JWT from scratch (no library)

### jwt.go — what to implement

```
Sign(claims map[string]any, privateKey *rsa.PrivateKey, kid string) (string, error)
  1. build header:  {"alg":"RS256","typ":"JWT","kid": kid}
  2. marshal claims to JSON
  3. base64url encode both (no padding)
  4. signingInput = encodedHeader + "." + encodedPayload
  5. digest = SHA256(signingInput)
  6. signature = rsa.SignPKCS1v15(rand, key, crypto.SHA256, digest)
  7. return signingInput + "." + base64url(signature)

Verify(tokenString string, keyFunc func(kid string) (*rsa.PublicKey, error)) (map[string]any, error)
  1. split on "." — must have exactly 3 parts
  2. decode header — read "kid" and "alg" fields
  3. reject if alg != "RS256" (never accept "none")
  4. fetch public key via keyFunc(kid)
  5. signingInput = parts[0] + "." + parts[1]
  6. digest = SHA256(signingInput)
  7. signature = base64url decode parts[2]
  8. rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, digest, signature)
  9. decode payload JSON → map[string]any
  10. check exp > time.Now().Unix()
  11. return claims

ParseUnverified(tokenString string) (map[string]any, error)
  — same as Verify but skips signature check
  — used by client app to read id_token claims
```

### claims.go — structs

```go
type AccessTokenClaims struct {
    Sub      string   `json:"sub"`
    Iss      string   `json:"iss"`
    Aud      string   `json:"aud"`
    Exp      int64    `json:"exp"`
    Iat      int64    `json:"iat"`
    Jti      string   `json:"jti"`
    Scope    string   `json:"scope"`
    ClientID string   `json:"client_id"`
}

type IDTokenClaims struct {
    Sub           string `json:"sub"`
    Iss           string `json:"iss"`
    Aud           string `json:"aud"`
    Exp           int64  `json:"exp"`
    Iat           int64  `json:"iat"`
    Nonce         string `json:"nonce,omitempty"`
    Name          string `json:"name"`
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    AuthTime      int64  `json:"auth_time"`
}
```

### jwks.go — what to implement

```
JWKSResponse struct {
    Keys []JWK `json:"keys"`
}
JWK struct {
    Kty string `json:"kty"`  // "RSA"
    Use string `json:"use"`  // "sig"
    Kid string `json:"kid"`
    Alg string `json:"alg"`  // "RS256"
    N   string `json:"n"`    // base64url modulus
    E   string `json:"e"`    // base64url exponent
}

PublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK
  — encode N and E as base64url, build JWK struct

ParseJWKS(body []byte) (map[string]*rsa.PublicKey, error)
  — parse JWKSResponse, decode each JWK back to *rsa.PublicKey
  — return map[kid]*rsa.PublicKey

NewJWKSCache(jwksURL string) *JWKSCache
  — fetches JWKS on first use, caches result
  — re-fetches if kid not found (key rotation)
  — thread-safe with sync.RWMutex
  GetKey(kid string) (*rsa.PublicKey, error)
```

---

## internal/cryptoutil

### rsa.go

```
GenerateKey() (*rsa.PrivateKey, error)          — rsa.GenerateKey(rand, 2048)
SaveKeyToFile(key *rsa.PrivateKey, path string) — PEM encode, write file
LoadKeyFromFile(path string) (*rsa.PrivateKey, error)
  — if file not found: generate, save, return
  — used by auth server on startup
```

### pkce.go

```
GenerateVerifier() (string, error)
  — 32 random bytes → base64url encode → 43 char string

ComputeChallenge(verifier string) string
  — base64url( SHA256(verifier) )   — no padding

VerifyChallenge(verifier, challenge string) bool
  — ComputeChallenge(verifier) == challenge
```

---

## internal/middleware/auth.go

```
RequireAuth(next http.Handler) http.Handler
  — extract "Authorization: Bearer <token>" header
  — call jwtutil.Verify() with JWKSCache.GetKey as keyFunc
  — validate iss and aud match config
  — validate exp
  — store claims in request context: ctx.WithValue(key, claims)
  — on failure: 401 JSON {"error":"invalid_token"}

RequireScope(scope string) func(http.Handler) http.Handler
  — reads claims from context (set by RequireAuth)
  — checks claims["scope"] contains the required scope string
  — on failure: 403 JSON {"error":"insufficient_scope"}

GetClaims(r *http.Request) map[string]any
  — helper to read claims from context in handlers
```

---

## Auth Server — Handler Specifications

### GET /authorize

```
Validate query params:
  - response_type == "code"                   → else 400
  - client_id exists in DB                    → else 400
  - redirect_uri matches client's registered  → else 400
  - scope is subset of client's allowed_scopes
  - state present
  - code_challenge present
  - code_challenge_method == "S256"

If user not logged in (no session cookie):
  → redirect to /login?next=<full authorize URL>

If user logged in:
  → render consent.html with: client name, requested scopes, state
```

### POST /authorize/consent

```
Read from form: approve/deny, state, all original authorize params from hidden fields

If denied:
  → redirect to redirect_uri?error=access_denied&state=<state>

If approved:
  → generate auth code: uuid, 60 second expiry
  → store in auth_codes table with: code, client_id, user_id, scope,
    redirect_uri, code_challenge, code_challenge_method, nonce, expires_at
  → redirect to redirect_uri?code=<code>&state=<state>
```

### POST /token

```
Parse application/x-www-form-urlencoded body

grant_type=authorization_code:
  1. look up code in DB — 400 if not found or used or expired
  2. verify client_id matches
  3. verify redirect_uri matches exactly
  4. verify client_secret (bcrypt compare)
  5. PKCE: VerifyChallenge(code_verifier, stored code_challenge) — 400 if fail
  6. mark code as used (set used_at = now)
  7. issue access token (1 hour exp):
       claims: sub=user_id, iss, aud=resource_server_url,
               exp, iat, jti=uuid, scope, client_id
  8. issue ID token (1 hour exp):
       claims: sub, iss, aud=client_id, exp, iat,
               nonce (from code), name, email, email_verified=true, auth_time
  9. generate refresh token: uuid → store SHA256(token) in DB (30 day exp)
  10. respond: {access_token, token_type:"Bearer", expires_in:3600,
                refresh_token, id_token, scope}

grant_type=refresh_token:
  1. hash incoming token, look up in DB — 400 if not found/revoked/expired
  2. verify client_id and client_secret
  3. issue new access token with same scope
  4. optionally rotate refresh token (revoke old, issue new)
  5. respond: {access_token, token_type:"Bearer", expires_in:3600, scope}
```

### GET /.well-known/jwks.json

```
Load current private key → extract public key
Return: {"keys": [PublicKeyToJWK(pubKey, kid)]}
Content-Type: application/json
Cache-Control: max-age=3600
```

### GET /.well-known/openid-configuration

```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/token",
  "userinfo_endpoint": "http://localhost:8080/userinfo",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "revocation_endpoint": "http://localhost:8080/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "data:read", "profile:read"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

### GET /userinfo (protected)

```
- Run RequireAuth middleware
- Read sub from access token claims
- Fetch user from DB by sub
- Return: {sub, name, email, email_verified:true}
```

### POST /revoke

```
- Validate client_id + client_secret
- Hash incoming token
- Set revoked_at = now in refresh_tokens table
- Always return 200 (RFC 7009 — don't reveal if token existed)
```

### GET /login + POST /login

```
GET:  render login.html (email + password form)
      if ?next= param present, store in hidden field

POST: look up user by email
      bcrypt.CompareHashAndPassword
      on success: set session cookie (httpOnly, SameSite=Lax)
                  store user_id in session
                  redirect to ?next= or /
      on failure: re-render login.html with error message
```

### GET /register + POST /register

```
GET:  render register.html

POST: validate email not already taken
      bcrypt.GenerateFromPassword (cost 12)
      insert user with uuid id
      redirect to /login
```

---

## Resource Server — Handler Specifications

### Middleware chain for protected routes

```
logging → RequireAuth → RequireScope(scope) → handler
```

RequireAuth verifies the JWT and stores claims in context.
RequireScope checks the scope claim for the specific permission.

### GET /api/profile  (scope: profile:read)

```
Read sub from JWT claims in context
Return JSON: {sub, name:"fetched from token claims or DB", email, scope}
```

### GET /api/data  (scope: data:read)

```
Read sub from JWT claims in context
Fetch resources from DB where owner_sub = sub
Return JSON: {items: [{id, title, body, created_at}]}
```

### GET /health  (public, no auth)

```
Return JSON: {status:"ok", service:"resource-server", time:<unix>}
```

---

## Client App — Handler Specifications

### SessionData struct

```go
type SessionData struct {
    UserID       string
    AccessToken  string
    IDToken      string
    RefreshToken string
    UserInfo     UserInfo    // decoded from id_token
    State        string      // stored during login, verified on callback
    CodeVerifier string      // stored during login, sent on callback
    ExpiresAt    time.Time   // access token expiry
}

type UserInfo struct {
    Sub   string
    Name  string
    Email string
}
```

### GET /login

```
1. generate state = uuid
2. generate code_verifier via pkce.GenerateVerifier()
3. compute code_challenge = pkce.ComputeChallenge(verifier)
4. save state + code_verifier in session (new session ID → cookie)
5. build auth URL:
     http://localhost:8080/authorize
       ?response_type=code
       &client_id=<CLIENT_ID>
       &redirect_uri=<REDIRECT_URI>
       &scope=openid profile:read data:read
       &state=<state>
       &code_challenge=<challenge>
       &code_challenge_method=S256
6. http.Redirect to auth URL
```

### GET /callback

```
1. read code and state from query params
2. load session — verify state matches stored state → 400 if mismatch (CSRF)
3. POST to http://localhost:8080/token:
     grant_type=authorization_code
     &code=<code>
     &client_id=<CLIENT_ID>
     &client_secret=<CLIENT_SECRET>
     &redirect_uri=<REDIRECT_URI>
     &code_verifier=<stored verifier>
4. parse token response → store access_token, id_token, refresh_token in session
5. decode id_token with ParseUnverified() → extract name, email, sub → store in session
6. set session.ExpiresAt = time.Now().Add(1 hour)
7. redirect to /dashboard
```

### GET /dashboard

```
1. load session — redirect to / if no tokens
2. if access token expires within 60s → call RefreshToken() silently
     if refresh fails → clear session → redirect /login
3. call GET http://localhost:9090/api/profile
     with Authorization: Bearer <access_token>
4. call GET http://localhost:9090/api/data
     with Authorization: Bearer <access_token>
5. render dashboard.html with: user info, profile data, resource items
```

### GET /logout

```
1. load session → POST /revoke to auth server with refresh_token
2. delete session from store
3. clear session cookie (MaxAge=-1)
4. redirect to /
```

### oauth/client.go

```
BuildAuthURL(state, challenge string) string
  — assembles the full /authorize URL with all params

ExchangeCode(code, verifier string) (*TokenResponse, error)
  — POST to /token with grant_type=authorization_code
  — returns parsed TokenResponse

RefreshToken(refreshToken string) (*TokenResponse, error)
  — POST to /token with grant_type=refresh_token
  — returns parsed TokenResponse

TokenResponse struct {
    AccessToken  string `json:"access_token"`
    IDToken      string `json:"id_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    Scope        string `json:"scope"`
}
```

---

## internal/config/config.go

```go
type Config struct {
    // shared
    DBPath string

    // auth server
    AuthPort    string
    Issuer      string
    KeyPath     string

    // resource server
    ResourcePort string
    Audience     string
    JWKSUrl      string
    ExpectedIss  string

    // client app
    ClientPort          string
    ClientID            string
    ClientSecret        string
    RedirectURI         string
    AuthServerURL       string
    ResourceServerURL   string
    SessionSecret       string
}

func Load() *Config {
    godotenv.Load()
    return &Config{
        AuthPort:          getEnv("AUTH_SERVER_PORT", "8080"),
        Issuer:            getEnv("AUTH_SERVER_ISSUER", "http://localhost:8080"),
        KeyPath:           getEnv("AUTH_SERVER_KEY_PATH", "./keys/private.pem"),
        DBPath:            getEnv("AUTH_SERVER_DB_PATH", "./auth.db"),
        ResourcePort:      getEnv("RESOURCE_SERVER_PORT", "9090"),
        Audience:          getEnv("RESOURCE_SERVER_AUDIENCE", "http://localhost:9090"),
        JWKSUrl:           getEnv("RESOURCE_SERVER_JWKS_URL", "http://localhost:8080/.well-known/jwks.json"),
        ExpectedIss:       getEnv("RESOURCE_SERVER_ISSUER", "http://localhost:8080"),
        ClientPort:        getEnv("CLIENT_APP_PORT", "3000"),
        ClientID:          getEnv("CLIENT_APP_CLIENT_ID", "client_app_001"),
        ClientSecret:      getEnv("CLIENT_APP_CLIENT_SECRET", ""),
        RedirectURI:       getEnv("CLIENT_APP_REDIRECT_URI", "http://localhost:3000/callback"),
        AuthServerURL:     getEnv("CLIENT_APP_AUTH_SERVER_URL", "http://localhost:8080"),
        ResourceServerURL: getEnv("CLIENT_APP_RESOURCE_SERVER_URL", "http://localhost:9090"),
        SessionSecret:     getEnv("CLIENT_APP_SESSION_SECRET", ""),
    }
}
```

---

## cmd/auth-server/main.go — route wiring

```
routes to register:
  GET  /login               → handlers.LoginGet
  POST /login               → handlers.LoginPost
  GET  /register            → handlers.RegisterGet
  POST /register            → handlers.RegisterPost
  GET  /authorize           → handlers.Authorize
  POST /authorize/consent   → handlers.Consent
  POST /token               → handlers.Token
  POST /revoke              → handlers.Revoke
  GET  /userinfo            → middleware.RequireAuth(handlers.Userinfo)
  GET  /.well-known/jwks.json            → handlers.JWKS
  GET  /.well-known/openid-configuration → handlers.Discovery

on startup:
  1. load config
  2. open + migrate DB (create tables if not exist)
  3. seed default client (client_app_001) if not exists
  4. load or generate RSA key pair from config.KeyPath
  5. start HTTP server on config.AuthPort
```

## cmd/resource-server/main.go — route wiring

```
routes to register:
  GET /health              → handlers.Health  (no auth)
  GET /api/profile         → logging(RequireAuth(RequireScope("profile:read")(handlers.Profile)))
  GET /api/data            → logging(RequireAuth(RequireScope("data:read")(handlers.Data)))

on startup:
  1. load config
  2. open + migrate DB, seed sample resources
  3. init JWKSCache with config.JWKSUrl
  4. start HTTP server on config.ResourcePort
```

## cmd/client-app/main.go — route wiring

```
routes to register:
  GET /           → handlers.Home
  GET /login      → handlers.Login
  GET /callback   → handlers.Callback
  GET /dashboard  → handlers.Dashboard
  GET /logout     → handlers.Logout

on startup:
  1. load config
  2. init session store (in-memory map + mutex)
  3. init oauth client with config
  4. start HTTP server on config.ClientPort
```

---

## Seed Data (run on auth server startup)

```go
// insert this client if not exists
Client{
    ID:             "client_app_001",
    SecretHash:     bcrypt("super_secret_change_me"),
    Name:           "OAuth Demo Client",
    RedirectURIs:   "http://localhost:3000/callback",
    AllowedScopes:  "openid profile:read data:read",
}

// insert sample resources owned by any registered user
// seeded in resource server DB when first user registers
Resource{Title: "My first note",    Body: "Hello OAuth world"}
Resource{Title: "My second note",   Body: "JWT signing works!"}
Resource{Title: "My third note",    Body: "PKCE is important"}
```

---

## Go Packages — full require block

```go
require (
    github.com/mattn/go-sqlite3 v1.14.22
    golang.org/x/crypto         v0.22.0
    github.com/google/uuid      v1.6.0
    github.com/joho/godotenv    v1.5.1
)
```

**Stdlib packages used (no external deps for crypto):**
- `crypto/rsa` — key generation, signing, verification
- `crypto/sha256` — JWT digest, PKCE challenge
- `crypto/rand` — secure random for keys and verifiers
- `crypto/x509` — PEM encode/decode RSA keys
- `encoding/base64` — base64url encoding (no padding)
- `encoding/json` — marshal/unmarshal JWT parts and API responses
- `encoding/pem` — PEM block read/write
- `net/http` — all three HTTP servers
- `html/template` — auth server and client app HTML pages
- `database/sql` — SQLite queries
- `sync` — RWMutex for JWKS cache and session store
- `time` — token expiry checks
- `strings` — scope parsing, bearer extraction
- `math/big` — RSA public key N encoding for JWKS

---

## Key Security Rules — enforce these exactly

1. **Never accept `alg: "none"`** in JWT verification — hard reject
2. **Always verify `aud`** — access token aud must be resource server URL
3. **Always verify `iss`** — must match auth server issuer exactly
4. **Always verify `exp`** — reject expired tokens with 401
5. **Auth code is single-use** — set `used_at` before issuing tokens; reject if already set
6. **PKCE is mandatory** — reject token requests without `code_verifier`
7. **Verify `state` in callback** — reject if missing or mismatched
8. **bcrypt all secrets** — user passwords AND client secrets
9. **SHA256 refresh tokens** — never store raw refresh token in DB
10. **`private.pem` is gitignored** — generated fresh per environment

---

## End-to-End Happy Path (test this flow manually)

```
1. Start all three servers
2. Open http://localhost:3000
3. Click "Login" → redirected to http://localhost:8080/login
4. Register a new account at http://localhost:8080/register
5. Log in → see consent screen listing: profile:read, data:read
6. Click "Approve"
7. Redirected to http://localhost:3000/callback with ?code=...&state=...
8. Client app exchanges code for tokens (back-channel POST to /token)
9. Redirected to /dashboard
10. Dashboard shows: user name/email from id_token + data from resource server API
11. Click logout → refresh token revoked, session cleared, back to home
```

---

## Build Checklist (in order)

- [ ] `internal/cryptoutil/rsa.go` — key generation + PEM load/save
- [ ] `internal/cryptoutil/pkce.go` — verifier, challenge, verify
- [ ] `internal/jwtutil/claims.go` — claim structs
- [ ] `internal/jwtutil/jwt.go` — Sign() and Verify() from scratch
- [ ] `internal/jwtutil/jwks.go` — JWK struct, encode/decode, cache
- [ ] `internal/store/db.go` — open SQLite, run migrations
- [ ] `internal/store/users.go`
- [ ] `internal/store/clients.go`
- [ ] `internal/store/codes.go`
- [ ] `internal/store/tokens.go`
- [ ] `internal/store/resources.go`
- [ ] `internal/config/config.go`
- [ ] `internal/middleware/logging.go`
- [ ] `internal/middleware/recovery.go`
- [ ] `internal/middleware/auth.go` — RequireAuth + RequireScope
- [ ] `resource-server/handlers/health.go`
- [ ] `resource-server/handlers/profile.go`
- [ ] `resource-server/handlers/data.go`
- [ ] `cmd/resource-server/main.go`
- [ ] `auth-server/handlers/register.go`
- [ ] `auth-server/handlers/login.go`
- [ ] `auth-server/handlers/authorize.go`
- [ ] `auth-server/handlers/consent.go`
- [ ] `auth-server/handlers/token.go`
- [ ] `auth-server/handlers/revoke.go`
- [ ] `auth-server/handlers/jwks.go`
- [ ] `auth-server/handlers/discovery.go`
- [ ] `auth-server/handlers/userinfo.go`
- [ ] `auth-server/templates/` — login.html, register.html, consent.html
- [ ] `cmd/auth-server/main.go`
- [ ] `client-app/session/store.go`
- [ ] `client-app/oauth/client.go`
- [ ] `client-app/oauth/token_store.go`
- [ ] `client-app/handlers/` — all five handlers
- [ ] `client-app/templates/` — home.html, dashboard.html
- [ ] `cmd/client-app/main.go`
- [ ] End-to-end manual flow test
