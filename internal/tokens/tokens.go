package tokens

import (
	"errors"
	"net/http"
	"time"

	"github.com/Des1red/goauthlib/internal/csrf"
	"github.com/Des1red/goauthlib/internal/uuid"
)

// TokenExists allows middleware to check token validity
// without knowing about the underlying database.
func TokenExists(jti string) (bool, error) {
	if store == nil {
		return false, ErrTokenStoreNotSet
	}
	return store.TokenExists(jti)
}
func SaveToken(uuid, jti, tokenType string, exp int64) error {
	if store == nil {
		return ErrTokenStoreNotSet
	}
	return store.SaveToken(uuid, jti, tokenType, exp)
}

func DeleteToken(jti string) error {
	if store == nil {
		return ErrTokenStoreNotSet
	}
	return store.DeleteToken(jti)
}

type TokenStore interface {
	SaveToken(uuid, jti, tokenType string, exp int64) error
	DeleteToken(jti string) error
	TokenExists(jti string) (bool, error)
}

// store is injected by the host app (db, redis, etc.)
var store TokenStore

func SetTokenStore(s TokenStore) {
	store = s
}

type CookieConfig struct {
	Secure   bool
	SameSite http.SameSite
	Path     string
	Domain   string // optional
}

var cookieCfg = CookieConfig{
	Secure:   false,
	SameSite: http.SameSiteStrictMode,
	Path:     "/",
}

func SetCookieConfig(cfg CookieConfig) {
	// keep defaults if caller leaves fields empty/zero
	if cfg.Path == "" {
		cfg.Path = cookieCfg.Path
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = cookieCfg.SameSite
	}
	cookieCfg = cfg
}

func cookie(name, value string, httpOnly bool, expires time.Time, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cookieCfg.Path,
		HttpOnly: httpOnly,
		Secure:   cookieCfg.Secure,
		SameSite: cookieCfg.SameSite,
		MaxAge:   maxAge,
	}
	if !expires.IsZero() {
		c.Expires = expires
	}
	if cookieCfg.Domain != "" {
		c.Domain = cookieCfg.Domain
	}
	return c
}

const (
	RoleAnonymous = "anonymous"
	RoleUser      = "user"
	RoleAdmin     = "admin"
)

const (
	AccessTokenTime    = 10 * time.Minute
	AnonymousTokenTime = 5 * time.Minute
	RefreshTokenTime   = 24 * time.Hour
)

var (
	ErrTokenStoreNotSet = errors.New("token store not set")
)

const AnonymousUserID = 0

func CreateAnonymousToken(w http.ResponseWriter, uuid string) {
	token, err := GenerateJWT(uuid, RoleAnonymous, TokenTypeAccess, "", AnonymousTokenTime, AnonymousUserID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie("auth_token", token, true, time.Time{}, 0))
}

func CreateAccessToken(
	w http.ResponseWriter,
	role, uuid, jti string,
	userID int) string {

	token, err := GenerateJWT(uuid, role, TokenTypeAccess, jti, AccessTokenTime, userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return ""
	}

	http.SetCookie(w, cookie("auth_token", token, true, time.Time{}, 0))
	return token
}

func CreateRefreshToken(
	w http.ResponseWriter,
	role, uuid, jti, accessJTI string,
	userID int,
) {
	refreshToken, err := GenerateJWT(uuid, role, TokenTypeRefresh, jti, RefreshTokenTime, userID, accessJTI)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie("refresh_token", refreshToken, true, time.Time{}, 0))
}

func CreateCsrfToken(w http.ResponseWriter) {
	csrfToken := csrf.GenerateCSRFToken()
	http.SetCookie(w, cookie("csrf_token", csrfToken, false, time.Time{}, 0)) // readable by frontend
}

func CreateTokens(
	w http.ResponseWriter,
	role string,
	userID int,
) {
	if store == nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Generate UUID + JTI
	u := uuid.GenerateUUID()
	refreshJTI := uuid.GenerateUUID()
	accessJTI := uuid.GenerateUUID()
	expiry := time.Now().Add(RefreshTokenTime).Unix()

	// Store refresh token & access JTI
	if err := store.SaveToken(u, refreshJTI, TokenTypeRefresh, expiry); err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}
	if err := store.SaveToken(u, accessJTI, TokenTypeAccess, expiry); err != nil {
		http.Error(w, "Failed to store access token", http.StatusInternalServerError)
		return
	}

	// expire anonymous/access token cookie first
	ExpireAccessToken(w)

	// issue tokens
	_ = CreateAccessToken(w, role, u, accessJTI, userID)
	CreateRefreshToken(w, role, u, refreshJTI, accessJTI, userID)
	CreateCsrfToken(w)
}

//----------------------------------------------------------------

func ExpireAccessToken(w http.ResponseWriter) {
	http.SetCookie(w, cookie("auth_token", "", true, time.Unix(0, 0), -1))
}

func ExpireRefreshToken(w http.ResponseWriter) {
	http.SetCookie(w, cookie("refresh_token", "", true, time.Unix(0, 0), -1))
}

func ExpireCsrfToken(w http.ResponseWriter) {
	http.SetCookie(w, cookie("csrf_token", "", false, time.Unix(0, 0), -1))
}

// NOTE: your middleware calls tokens.ExpireSessionKilledToken(w)
// so this must be exported.
func ExpireSessionKilledToken(w http.ResponseWriter) {
	http.SetCookie(w, cookie("session_killed", "true", true, time.Unix(0, 0), -1))
}

func ExpireTokens(w http.ResponseWriter, r *http.Request) {
	// Expire cookies
	ExpireAccessToken(w)
	ExpireRefreshToken(w)
	ExpireCsrfToken(w)

	// Revoke refresh/access JTI if possible
	if store != nil {
		if refreshCookie, err := r.Cookie("refresh_token"); err == nil && refreshCookie.Value != "" {
			if payload, err := VerifyJWT(refreshCookie.Value, TokenTypeRefresh); err == nil {
				_ = store.DeleteToken(payload.JTI)
				if payload.AccessJTI != "" {
					_ = store.DeleteToken(payload.AccessJTI)
				}
			}
		}
	}

	// logout flag to block refresh
	http.SetCookie(w, cookie("session_killed", "true", true, time.Now().Add(5*time.Minute), 0))
}
