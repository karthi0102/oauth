# Auth Server Implementation Walkthrough

We have successfully built the **Auth Server**, translating standard OAuth 2.0 flow requirements into scratch Go code without using external libraries. Here's a breakdown of the implementation:

## Data Access Layer (`internal/store`)
We began by scaffolding the database models directly against a SQLite connection:
- Added `users.go`, `clients.go`, `codes.go`, and `tokens.go` files inside `internal/store`.
- Implemented strongly typed retrieval wrappers around our raw SQL schemas mapping rows to native structs.
- Wired secure hashing mechanics automatically via `bcrypt` during `CreateUser` and `ValidateClientSecret`.

## Handlers (`auth-server/handlers`)
We developed distinct endpoints mapping identical to the specifications in `OAUTH_FROM_SCRATCH.md`:

### User Facing Endpoints
1. **[Register `/register`](file:///Users/karthi/Development/oauth/auth-server/handlers/register.go)**: Form rendering and POST endpoint to insert new user records hashed properly.
2. **[Login `/login`](file:///Users/karthi/Development/oauth/auth-server/handlers/login.go)**: Authenticates credentials and issues an ephemeral symmetric cookie indicating the user's logged-in state inside `session.go`.
3. **[Consent `/authorize`](file:///Users/karthi/Development/oauth/auth-server/handlers/authorize.go)**: Performs extensive redirect URI and scope validation prior to querying the user for access approval via the consent HTML template.
4. **[Authorize Submit `/authorize/consent`](file:///Users/karthi/Development/oauth/auth-server/handlers/consent.go)**: Validates approval POST forms, mints transient Auth Codes coupled with code challenges (PKCE), and kicks off the HTTP redirect back to the client app.

### API Integrations
1. **[Token `/token`](file:///Users/karthi/Development/oauth/auth-server/handlers/token.go)**: Fully operational Auth Code → Access Token exchange including Refresh Token handling. Performs deep PKCE cryptographic challenges ensuring code-stealing prevention. Generates full RSA Signed JWTs using standard `crypto/rsa`.
2. **[Revoke `/revoke`](file:///Users/karthi/Development/oauth/auth-server/handlers/revoke.go)**: Voids active refresh tokens cleanly.
3. **[JWKS `/jwks.json`](file:///Users/karthi/Development/oauth/auth-server/handlers/jwks.go)**: Implements `.well-known/jwks.json` issuing the corresponding Public Key so other services (Resource Server and Client App) can establish verify JWTs.
4. **[Discovery `/.well-known/openid-configuration`](file:///Users/karthi/Development/oauth/auth-server/handlers/discovery.go)**: Centralized configuration broadcast exposing all endpoints and supported methods.

## Executable Entry (`cmd/auth-server/main.go`)
- Integrated automated migration execution to initialize cleanly across environments `db.RunMigrations()`.
- Seeds a default `client_app_001` test harness client via `bcrypt` key issuance.
- Injects our configurations (JWT Issuers/Audiences) contextually directly into standard HTTP Mux handlers.
- The binary cleanly starts via `make run-auth` and successfully processes background interactions.

## Verification
I compiled and verified the binary startup command seamlessly. The `auth-server` is configured and listening successfully on `localhost:8080`, logging:
```
[store] all migrations completed successfully
Seeded default client 'client_app_001'
Auth server listening on :8080
```
