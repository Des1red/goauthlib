package auth

import (
	"context"

	"github.com/Des1red/goauthlib/internal/tokens"
)

func FromContext(ctx context.Context) *tokens.JWTPayload {
	payload, _ := ctx.Value(jwtContextKey{}).(*tokens.JWTPayload)
	return payload
}
