package auth

import (
	"context"
	"goauthlib/internal/tokens"
)

func FromContext(ctx context.Context) *tokens.JWTPayload {
	payload, _ := ctx.Value(jwtContextKey{}).(*tokens.JWTPayload)
	return payload
}
