package goauth

import (
	"github.com/Des1red/goauthlib/internal/authError"
)

// Re-export error values
var (
	ErrUnauthorized = authError.ErrUnauthorized
	ErrForbidden    = authError.ErrForbidden
	ErrInternal     = authError.ErrInternal
)
