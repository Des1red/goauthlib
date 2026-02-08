package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Des1red/goauthlib/goauth"
)

// --------------------
// Demo token store
// --------------------

type InMemoryStore struct {
	tokens map[string]bool
}

func (s *InMemoryStore) SaveToken(uuid, jti, tokenType string, exp int64) error {
	s.tokens[jti] = true
	return nil
}

func (s *InMemoryStore) DeleteToken(jti string) error {
	delete(s.tokens, jti)
	return nil
}

func (s *InMemoryStore) TokenExists(jti string) (bool, error) {
	_, exists := s.tokens[jti]
	return exists, nil
}

// --------------------
// Templates
// --------------------

var templates = template.Must(template.ParseGlob("example/basic-server/templates/*.html"))

// --------------------
// Handlers
// --------------------

func loginPage(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Fake successful login
	userID := 1
	log.Println("Logging in user ID:", userID)
	goauth.Login(w, goauth.RoleUser(), userID)

	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	payload := goauth.FromContext(r.Context())
	if payload == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(
		w,
		"Welcome admin!\nUserID=%d\nRole=%s\n",
		payload.UserID,
		payload.Role,
	)
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Fake admin login
	userID := 42
	log.Println("Logging in ADMIN user ID:", userID)
	goauth.Login(w, goauth.RoleAdmin(), userID)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	payload := goauth.FromContext(r.Context())
	if payload == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		log.Println("Unauthorized: No payload found in context.")
		return
	}

	// Log the token information
	log.Println("Authenticated user ID:", payload.UserID, "Role:", payload.Role)

	// Read cookies safely on backend
	var accessToken, refreshToken, csrfToken string

	if c, err := r.Cookie("auth_token"); err == nil {
		accessToken = c.Value
	}
	if c, err := r.Cookie("refresh_token"); err == nil {
		refreshToken = c.Value

	}
	if c, err := r.Cookie("csrf_token"); err == nil {
		csrfToken = c.Value

	}

	// Prepare response data
	data := map[string]any{
		"UserID": payload.UserID,
		"Role":   payload.Role,

		// raw tokens (demo only)
		"AccessToken":  accessToken,
		"RefreshToken": refreshToken,
		"CSRFToken":    csrfToken,

		// decoded payload (trusted, backend)
		"Claims": payload,
	}

	templates.ExecuteTemplate(w, "home.html", data)
}

// Fake POST just to demonstrate CSRF
func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{
		"status": "ok",
		"note":   "CSRF token accepted",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	goauth.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --------------------
// Main
// --------------------

func main() {
	// --------------------------------------------------
	// Enable verbose logging (development only)
	// This logs internal auth decisions (token validation,
	// refresh attempts, role checks, etc).
	// --------------------------------------------------
	goauth.Verbose()

	// --------------------------------------------------
	// Configure JWT signing secret
	// REQUIRED.
	// Must be stable across restarts or sessions will break.
	// --------------------------------------------------
	goauth.JWTSecret([]byte(os.Getenv("JWT_SECRET")))

	// --------------------------------------------------
	// Inject token persistence backend
	// REQUIRED.
	// goauth does not care how tokens are stored
	// (sqlite, redis, postgres, memory, etc).
	// --------------------------------------------------
	goauth.UseStore(&InMemoryStore{tokens: make(map[string]bool)})

	// --------------------------------------------------
	// Cookie configuration (optional)
	// Controls security flags only — NOT auth logic.
	// --------------------------------------------------
	goauth.Cookies(goauth.CookieConfig{
		Secure:   false, // true in production (HTTPS only)
		SameSite: http.SameSiteStrictMode,
	})

	// --------------------------------------------------
	// Token lifetime configuration (optional)
	// Safe defaults are used if omitted.
	// --------------------------------------------------
	goauth.Tokens(goauth.TokenConfig{
		AccessTTL:  5 * time.Minute, // short-lived access token
		RefreshTTL: 12 * time.Hour,  // long-lived refresh token
	})

	// --------------------------------------------------
	// Role configuration (optional)
	// Allows applications to rename roles without
	// changing any internal logic.
	// --------------------------------------------------
	goauth.Roles(goauth.RolesConfig{
		User:  "member",
		Admin: "owner",
	})

	// --------------------------------------------------
	// Custom error handling (optional)
	// This controls *presentation only*.
	// Auth decisions are unchanged.
	// --------------------------------------------------
	goauth.Errors(func(w http.ResponseWriter, r *http.Request, err error) {
		switch err {
		case goauth.ErrUnauthorized:
			// e.g. not logged in / invalid session
			http.Error(w, "dont know you", http.StatusUnauthorized)

		case goauth.ErrForbidden:
			// e.g. logged in but wrong role
			http.Error(w, "nope", http.StatusForbidden)

		default:
			// internal auth failure (store, JWT, etc)
			http.Error(w, "auth failure", http.StatusInternalServerError)
		}
	})

	// --------------------------------------------------
	// HTTP routing
	// goauth does NOT require any framework.
	// Works with net/http directly.
	// --------------------------------------------------
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/login", loginPage)
	mux.HandleFunc("/login/submit", loginHandler)

	// Default redirect
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// --------------------------------------------------
	// Protected routes
	// Requires authenticated user (member OR owner).
	// No CSRF enforcement here (safe for APIs / GETs).
	// --------------------------------------------------
	mux.HandleFunc(
		"/home",
		goauth.Protected(homeHandler),
	)

	// --------------------------------------------------
	// Browser-protected route with CSRF enforcement
	// Use for POST/PUT/DELETE from browsers.
	// --------------------------------------------------
	mux.HandleFunc(
		"/profile/update",
		goauth.ProtectedCsrfActive(updateProfileHandler),
	)

	// Admin login (demo only)
	mux.HandleFunc("/login/admin", adminLoginHandler)

	// --------------------------------------------------
	// Admin-only route
	// Requires role = owner (admin).
	// --------------------------------------------------
	mux.HandleFunc(
		"/admin",
		goauth.Admin(adminHandler),
	)

	// Logout (expires cookies + revokes tokens)
	mux.HandleFunc("/logout", logoutHandler)

	// --------------------------------------------------
	// Start HTTP server
	// --------------------------------------------------
	host := "localhost"
	port := ":8000"
	fmt.Printf("Listening on %s%s\n", host, port)
	http.ListenAndServe(host+port, mux)
}
