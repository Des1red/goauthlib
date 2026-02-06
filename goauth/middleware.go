package goauth

import (
	"goauth/internal/auth"
	"goauth/internal/csrf"
	"goauth/internal/tokens"
	"net/http"
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
			tokens.RoleUser,
			tokens.RoleAdmin,
		)(h),
	)
}

// Protected = authenticated browser user (CSRF enforced)
func ProtectedCsrfActive(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		csrf.CSRFMiddleware(
			auth.RequireRoleMiddleware(
				tokens.RoleUser,
				tokens.RoleAdmin,
			)(h),
		),
	)
}

// Admin-only routes
func Admin(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		auth.RequireRoleMiddleware(tokens.RoleAdmin)(h),
	)
}

func AdminCsrfActive(h http.HandlerFunc) http.HandlerFunc {
	return auth.AuthMiddleware(
		csrf.CSRFMiddleware(
			auth.RequireRoleMiddleware(tokens.RoleAdmin)(h),
		),
	)
}
