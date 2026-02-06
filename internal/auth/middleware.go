package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"goauthlib/internal/tokens"
	"goauthlib/internal/uuid"
	"net/http"
	"strings"
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
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// 3) Enforce JTI
		if !checkAccessJTI(w, r2, payload) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r2)
	}
}

// =========================
// helpers
// =========================

func writeAPIUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "unauthorized",
	})
}

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
	}

	return nil, r, false
}

// =========================
// enforcement
// =========================

func checkAccessJTI(
	w http.ResponseWriter,
	r *http.Request,
	payload *tokens.JWTPayload,
) bool {

	if payload.JTI != "" {
		exists, err := tokens.TokenExists(payload.JTI)
		if err != nil || !exists {
			return false
		}
		return true
	}

	if payload.Role != tokens.RoleAnonymous {
		http.Error(w, "Invalid token structure", http.StatusUnauthorized)
		return false
	}
	return true
}

// =========================
// helpers
// =========================

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

	if payload.Role == tokens.RoleAnonymous {
		return &payload
	}
	return nil
}
