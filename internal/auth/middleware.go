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

		clearSessionKilledIfPresent(w, r)

		// 1) Grab auth cookie
		tok, ok := getCookieValue(r, "auth_token")
		if !ok {
			u := uuid.GenerateUUID()
			tokens.CreateAnonymousToken(w, u)
			next.ServeHTTP(w, r)
			return
		}

		// 2) Validate access token
		payload, r2, ok := authenticateRequest(w, r, tok)
		if !ok {
			logger.Log("Unauthenticated request")
			authError.Handle(w, r, authError.ErrUnauthorized)
			return
		}

		// 3) Enforce JTI
		if !checkAccessJTI(payload) {
			logger.Log(
				fmt.Sprintf(
					"Access token rejected: JTI not found user_id=%d role=%s jti=%s",
					payload.UserID,
					payload.Role,
					payload.JTI,
				),
			)
			authError.Handle(w, r, authError.ErrUnauthorized)
			return
		}

		next.ServeHTTP(w, r2)
	}
}

// =========================
// helpers
// =========================

func clearSessionKilledIfPresent(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("session_killed"); err == nil && ck.Value == "true" {
		tokens.ExpireSessionKilledToken(w)
	}
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
		ctx := context.WithValue(r.Context(), jwtContextKey{}, payload)
		return payload, r.WithContext(ctx), true
	}

	if errors.Is(err, tokens.ErrTokenExpired) {
		if anon := checkForAnonymousPayload(accessToken); anon != nil {
			ctx := context.WithValue(r.Context(), jwtContextKey{}, anon)
			u := uuid.GenerateUUID()
			tokens.CreateAnonymousToken(w, u)
			return anon, r.WithContext(ctx), true
		}

		// 2. Try refresh
		refreshTok, ok := getCookieValue(r, "refresh_token")
		if !ok {
			logger.Log("Refresh token not found in cookies")
			return nil, r, false
		}
		logger.Log("Found refresh token:" + refreshTok)

		newAccess, err := refreshAccessToken(refreshTok, w, r)
		if err != nil {
			return nil, r, false
		}
		// 3. Verify new access token
		payload, err = tokens.VerifyJWT(newAccess, tokens.TokenTypeAccess)
		if err != nil {
			return nil, r, false
		}
		ctx := context.WithValue(r.Context(), jwtContextKey{}, payload)
		return payload, r.WithContext(ctx), true

	}
	// log any other type of error
	logger.Log("Access token invalid: " + err.Error())

	return nil, r, false
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
