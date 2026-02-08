package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

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
	goauth.Login(w, "user", userID)

	http.Redirect(w, r, "/home", http.StatusSeeOther)
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
	goauth.Verbose()
	goauth.JWTSecret([]byte(os.Getenv("JWT_SECRET")))
	goauth.UseStore(&InMemoryStore{tokens: make(map[string]bool)})

	mux := http.NewServeMux()

	mux.HandleFunc("/login", loginPage)
	mux.HandleFunc("/login/submit", loginHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	mux.HandleFunc(
		"/home",
		goauth.Protected(homeHandler),
	)

	mux.HandleFunc(
		"/profile/update",
		goauth.ProtectedCsrfActive(updateProfileHandler),
	)

	mux.HandleFunc("/logout", logoutHandler)
	host := "localhost"
	port := ":8000"
	fmt.Printf("Listening on %s%s\n", host, port)
	http.ListenAndServe(host+port, mux)
}
