package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Des1red/goauthlib/internal/authError"
	"github.com/Des1red/goauthlib/internal/logger"
	"github.com/Des1red/goauthlib/internal/tokens"
	"github.com/Des1red/goauthlib/internal/uuid"
)

// =========================
// context key
// =========================

type jwtContextKey struct{}

// =========================
// AuthMiddleware
// =========================

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Newline()
		logger.Log("AuthMiddleware entered")

		if clearSessionKilledIfPresent(w, r) {
			return
		}

		// 1) Grab auth cookie
		tok, ok := getCookieValue(r, "auth_token")
		if !ok {
			u := uuid.GenerateUUID()
			tokens.CreateAnonymousToken(w, u)
			anon := &tokens.JWTPayload{
				UUID:   u,
				Role:   tokens.RoleAnonymous(),
				UserID: tokens.AnonymousUserID,
			}

			ctx := context.WithValue(r.Context(), jwtContextKey{}, anon)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 2) Validate access token
		_, r2, ok := authenticateRequest(w, r, tok)
		if !ok {
			logger.Log("Unauthenticated request")
			authError.Handle(w, r, authError.ErrUnauthorized)
			return
		}

		next.ServeHTTP(w, r2)
	}
}

// =========================
// helpers
// =========================

func clearSessionKilledIfPresent(w http.ResponseWriter, r *http.Request) bool {
	if ck, err := r.Cookie("session_killed"); err == nil && ck.Value == "true" {
		tokens.ExpireAccessToken(w)
		tokens.ExpireRefreshToken(w)
		tokens.ExpireCsrfToken(w)
		tokens.ExpireSessionKilledToken(w)
		authError.Handle(w, r, authError.ErrUnauthorized)
		return true
	}
	return false
}

func getCookieValue(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// =========================
// authentication
// =========================

func authenticateRequest(
	w http.ResponseWriter,
	r *http.Request,
	accessToken string,
) (*tokens.JWTPayload, *http.Request, bool) {
	logger.Log("Validating access token: " + accessToken)

	payload, err := tokens.VerifyJWT(accessToken, tokens.TokenTypeAccess)
	if err == nil {
		if checkAccessJTI(payload) {
			ctx := context.WithValue(r.Context(), jwtContextKey{}, payload)
			return payload, r.WithContext(ctx), true
		}

		logger.Log(
			fmt.Sprintf(
				"Access token rejected: JTI invalid or missing | rejected: JTI not found user_id=%d role=%s jti=%s",
				payload.UserID,
				payload.Role,
				payload.JTI,
			),
		)

		// stale/revoked access token: drop it and try refresh
		tokens.ExpireAccessToken(w)
	}

	if err != nil && !errors.Is(err, tokens.ErrTokenExpired) {
		logger.Log("Access token invalid: " + err.Error())
		tokens.ExpireTokens(w, r)
		return nil, r, false
	}

	if anon := checkForAnonymousPayload(accessToken); anon != nil {
		ctx := context.WithValue(r.Context(), jwtContextKey{}, anon)
		u := uuid.GenerateUUID()
		tokens.CreateAnonymousToken(w, u)
		return anon, r.WithContext(ctx), true
	}

	refreshTok, ok := getCookieValue(r, "refresh_token")
	if !ok {
		logger.Log("Refresh token not found in cookies")
		tokens.ExpireTokens(w, r)
		return nil, r, false
	}
	logger.Log("Found refresh token:" + refreshTok)

	newAccess, err := refreshAccessToken(refreshTok, w, r)
	if err != nil {
		return nil, r, false
	}

	payload, err = tokens.VerifyJWT(newAccess, tokens.TokenTypeAccess)
	if err != nil {
		tokens.ExpireTokens(w, r)
		return nil, r, false
	}

	if !checkAccessJTI(payload) {
		logger.Log(
			fmt.Sprintf(
				"New access token rejected: JTI not found user_id=%d role=%s jti=%s",
				payload.UserID,
				payload.Role,
				payload.JTI,
			),
		)
		tokens.ExpireTokens(w, r)
		return nil, r, false
	}

	ctx := context.WithValue(r.Context(), jwtContextKey{}, payload)
	return payload, r.WithContext(ctx), true
}

func checkForAnonymousPayload(token string) *tokens.JWTPayload {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var payload tokens.JWTPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}

	if payload.Role == tokens.RoleAnonymous() {
		return &payload
	}
	return nil
}

// =========================
// enforcement
// =========================

func checkAccessJTI(
	payload *tokens.JWTPayload,
) bool {

	if payload.JTI != "" {
		exists, err := tokens.TokenExists(payload.JTI)
		if err != nil || !exists {
			return false
		}
		return true
	}

	if payload.Role != tokens.RoleAnonymous() {
		return false
	}
	return true
}
