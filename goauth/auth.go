package goauth

import (
	"goauthlib/internal/tokens"
	"net/http"
)

// --------------------
// Setup / configuration
// --------------------

// UseStore injects the token persistence backend (sqlite, redis, etc.)
func UseStore(store tokens.TokenStore) {
	tokens.SetTokenStore(store)
}

// JWTSecret sets the HMAC secret used to sign JWTs.
// MUST be called once at startup.
func JWTSecret(secret []byte) {
	tokens.SetJWTSecret(secret)
}

// Cookies configures auth cookies (secure, samesite, etc.)
func Cookies(cfg tokens.CookieConfig) {
	tokens.SetCookieConfig(tokens.CookieConfig(cfg))
}

// Login issues access + refresh + csrf tokens
func Login(w http.ResponseWriter, role string, userID int) {
	tokens.CreateTokens(w, role, userID)
}

// Logout expires cookies and revokes tokens
func Logout(w http.ResponseWriter, r *http.Request) {
	tokens.ExpireTokens(w, r)
}
