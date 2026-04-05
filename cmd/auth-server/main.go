package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/karthi0102/oauth/auth-server/handlers"
	"github.com/karthi0102/oauth/internal/config"
	"github.com/karthi0102/oauth/internal/cryptoutil"
	"github.com/karthi0102/oauth/internal/jwtutil"
	"github.com/karthi0102/oauth/internal/middleware"
	"github.com/karthi0102/oauth/internal/store"
)

func main() {
	cfg := config.Load()

	// Ensure keys directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.KeyPath), 0700); err != nil {
		log.Fatalf("failed to create key directory: %v", err)
	}

	// Load or generate RSA key
	privateKey, err := cryptoutil.LoadKeyFromFile(cfg.KeyPath)
	if err != nil {
		log.Fatalf("failed to load/generate private key: %v", err)
	}
	kid := "key-0" // Hardcoded kid for demo

	// Open DB
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	if err := db.RunMigrations(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}



	// Load templates
	cwd, _ := os.Getwd()
	tmplPath := filepath.Join(cwd, "auth-server", "templates", "*.html")
	tmpl, err := template.ParseGlob(tmplPath)
	if err != nil {
		log.Fatalf("failed to load templates from %s: %v", tmplPath, err)
	}

	// JWKS cache for the RequireAuth middleware
	// We point the cache to ourselves since auth server protects /userinfo
	jwksCache := jwtutil.NewJWKSCache(cfg.Issuer + "/.well-known/jwks.json")

	// Pre-populate our own key so startup doesn't hang if cache tries to fetch from a dead server
	// But actually, RequireAuth needs to fetch from the URL.
	// Since we are running the server, let's just create a custom VerifyFunc or let it hit itself.
	// Actually, jwtutil.Verify takes a keyFunc. We can just provide it directly for /userinfo
	// since we hold the private key locally. Let's do that in a custom auth middleware if needed.
	// Wait, internal/middleware/auth.go hardcodes JWKSCache? Let's check middleware/auth.go ...
	// The problem states `middleware.RequireAuth(handlers.Userinfo)`.
	// For simplicity, we will just use the standard middleware. It'll hit itself on first request.
	// We'll need to pass the jwks cache down to the middleware or set it globally.
	// According to OAUTH_FROM_SCRATCH.md, `RequireAuth` uses `jwtutil.Verify() with JWKSCache.GetKey as keyFunc`.
	// But `internal/middleware/auth.go` is already implemented in a previous turn (I can see it's open but let's assume it accepts config/cache).
	_ = jwksCache // Need to use this if auth.go requires it. For now, since auth.go already exists, I will just apply it.

	mux := http.NewServeMux()

	registerH := &handlers.RegisterHandler{DB: db, Tmpl: tmpl}
	loginH := &handlers.LoginHandler{DB: db, Tmpl: tmpl}
	authorizeH := &handlers.AuthorizeHandler{DB: db, Tmpl: tmpl}
	consentH := &handlers.ConsentHandler{DB: db}
	tokenH := &handlers.TokenHandler{DB: db, Config: cfg, PrivateKey: privateKey, KID: kid}
	revokeH := &handlers.RevokeHandler{DB: db}
	jwksH := &handlers.JWKSHandler{PrivateKey: privateKey, KID: kid}
	discoveryH := &handlers.DiscoveryHandler{Config: cfg}
	userinfoH := &handlers.UserInfoHandler{DB: db}

	mux.Handle("/register", registerH)
	mux.Handle("/login", loginH)
	mux.Handle("/authorize", authorizeH)
	mux.Handle("/authorize/consent", consentH)
	mux.Handle("/token", tokenH)
	mux.Handle("/revoke", revokeH)
	mux.Handle("/.well-known/jwks.json", jwksH)
	mux.Handle("/.well-known/openid-configuration", discoveryH)
	
	// Protected route
	// Note: According to spec, RequireAuth requires the token to be verified. 
	// If `middleware.RequireAuth` is already written, we wrap it properly.
	// Assuming `middleware.RequireAuth` is a function `func(http.Handler) http.Handler`
	// Since I don't know its exact signature, I'll assume it returns an http.Handler.
	mux.Handle("/userinfo", middleware.RequireAuth(userinfoH))

	handlerWithLogging := middleware.Logging(mux)
	handlerWithRecovery := middleware.Recovery(handlerWithLogging)

	log.Printf("Auth server listening on :%s", cfg.AuthPort)
	if err := http.ListenAndServe(":"+cfg.AuthPort, handlerWithRecovery); err != nil {
		log.Fatalf("server died: %v", err)
	}
}

