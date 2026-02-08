package goauth

import (
	"net/http"

	"github.com/Des1red/goauthlib/internal/auth"
	"github.com/Des1red/goauthlib/internal/csrf"
)

// Auth attaches authentication context (anonymous allowed)
func Auth(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(h)
}

// Require enforces one or more roles
func Require(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return auth.RequireRoleMiddleware(roles...)
}

// Protected = authenticated user (user OR admin)
func Protected(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		auth.RequireRoleMiddleware(
			RoleUser(),
			RoleAdmin(),
		)(h),
	)
}

// Protected = authenticated browser user (CSRF enforced)
func ProtectedCsrfActive(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		csrf.CSRFMiddleware(
			auth.RequireRoleMiddleware(
				RoleUser(),
				RoleAdmin(),
			)(h),
		),
	)
}

// Admin-only routes
func Admin(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		auth.RequireRoleMiddleware(RoleAdmin())(h),
	)
}

func AdminCsrfActive(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		csrf.CSRFMiddleware(
			auth.RequireRoleMiddleware(RoleAdmin())(h),
		),
	)
}
