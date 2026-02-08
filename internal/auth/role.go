package auth

import (
	"net/http"

	"github.com/Des1red/goauthlib/internal/authError"
	"github.com/Des1red/goauthlib/internal/tokens"
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

			// Not authenticated
			if !ok || payload == nil {
				authError.Handle(w, r, authError.ErrUnauthorized)
				return
			}

			// Authenticated but forbidden
			if _, allowed := roleSet[payload.Role]; !allowed {
				authError.Handle(w, r, authError.ErrForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}
