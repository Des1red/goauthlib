package goauth

import (
	"context"
	"goauth/internal/auth"
	"goauth/internal/tokens"
)

// FromContext returns the JWT payload or nil
func FromContext(ctx context.Context) *tokens.JWTPayload {
	return auth.FromContext(ctx)
}
