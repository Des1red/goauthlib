package goauth

import (
	"context"

	"github.com/Des1red/goauthlib/internal/auth"
	"github.com/Des1red/goauthlib/internal/tokens"
)

// FromContext returns the JWT payload or nil
func FromContext(ctx context.Context) *tokens.JWTPayload {
	return auth.FromContext(ctx)
}
