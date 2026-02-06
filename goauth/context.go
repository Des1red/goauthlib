package goauth

import (
	"context"
	"goauthlib/internal/auth"
	"goauthlib/internal/tokens"
)

// FromContext returns the JWT payload or nil
func FromContext(ctx context.Context) *tokens.JWTPayload {
	return auth.FromContext(ctx)
}
