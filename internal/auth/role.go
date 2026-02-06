package auth

import (
	"encoding/json"
	"goauthlib/internal/tokens"
	"net/http"
	"strings"
)

//----------------------------------------------------------------

func RequireRoleMiddleware(allowedRoles ...string) func(http.HandlerFunc) http.HandlerFunc {
	roleSet := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		roleSet[role] = struct{}{}
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			payload, ok := r.Context().Value(jwtContextKey{}).(*tokens.JWTPayload)

			wantsJSON :=
				strings.Contains(r.Header.Get("Accept"), "application/json") ||
					r.Header.Get("X-Requested-With") == "XMLHttpRequest"

			// Not authenticated
			if !ok || payload == nil {
				if wantsJSON {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "unauthorized",
					})
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
				return
			}

			// Authenticated but forbidden
			if _, allowed := roleSet[payload.Role]; !allowed {
				if wantsJSON {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "forbidden",
					})
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}
