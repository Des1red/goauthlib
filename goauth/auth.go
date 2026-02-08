package goauth

import (
	"net/http"

	"github.com/Des1red/goauthlib/internal/authError"
	"github.com/Des1red/goauthlib/internal/logger"
	"github.com/Des1red/goauthlib/internal/tokens"
)

// Enables Verbose mode (only for developement)
func Verbose() {
	logger.EnableVerbose()
}

type TokenConfig = tokens.TokenConfig
type RolesConfig = tokens.Roles
type CookieConfig = tokens.CookieConfig
type ErrorHandler = authError.ErrorHandler

// --------------------
// Setup / configuration
// --------------------

// Tokens configures token lifetimes (optional).
// Safe defaults are used if not called.
func Tokens(cfg TokenConfig) {
	tokens.SetTokenConfig(cfg)
}

// Roles configures application role names (optional).
func Roles(cfg RolesConfig) {
	tokens.SetRoles(cfg)
}

// Cookies configures auth cookies (secure, samesite, etc.)
func Cookies(cfg CookieConfig) {
	tokens.SetCookieConfig(tokens.CookieConfig(cfg))
}

// UseStore injects the token persistence backend (sqlite, redis, etc.)
func UseStore(store tokens.TokenStore) {
	tokens.SetTokenStore(store)
}

// JWTSecret sets the HMAC secret used to sign JWTs.
// MUST be called once at startup.
func JWTSecret(secret []byte) {
	tokens.SetJWTSecret(secret)
}

// Login issues access + refresh + csrf tokens
func Login(w http.ResponseWriter, role string, userID int) {
	tokens.CreateTokens(w, role, userID)
}

// Logout expires cookies and revokes tokens
func Logout(w http.ResponseWriter, r *http.Request) {
	tokens.ExpireTokens(w, r)
}

// Errors allows customizing how authentication / authorization
// errors are presented (JSON, HTML, redirects, etc).
// Optional — defaults to plain HTTP errors.
func Errors(h ErrorHandler) {
	authError.SetErrorHandler(h)
}
