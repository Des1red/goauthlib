package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/Des1red/goauthlib/internal/tokens"
	"github.com/Des1red/goauthlib/internal/uuid"
)

func refreshAccessToken(
	refreshToken string,
	w http.ResponseWriter,
	r *http.Request,
) (string, error) {

	// 1. Verify refresh token
	payload, err := tokens.VerifyJWT(refreshToken, tokens.TokenTypeRefresh)
	if err != nil {
		return "", errors.New("invalid or expired refresh token")
	}

	// 2 Anonymous users cannot refresh
	if payload.Role == tokens.RoleAnonymous {
		return "", errors.New("anonymous users cannot refresh")
	}

	// 3. Check refresh JTI exists (one-time-use)
	exists, err := tokens.TokenExists(payload.JTI)
	if err != nil || !exists {
		return "", errors.New("refresh token already used or invalid")
	}
	if err := tokens.DeleteToken(payload.JTI); err != nil {
		return "", errors.New("failed to revoke refresh token")
	}

	// 4. Revoke old access token (if linked)
	if payload.AccessJTI != "" {
		_ = tokens.DeleteToken(payload.AccessJTI)
	}

	// 5. Generate new JTIs
	newRefreshJTI := uuid.GenerateUUID()
	newAccessJTI := uuid.GenerateUUID()

	refreshExpiry := time.Now().Add(tokens.RefreshTokenTime).Unix()
	accessExpiry := time.Now().Add(tokens.AccessTokenTime).Unix()

	// 6. Store new tokens
	if err := tokens.SaveToken(payload.UUID, newRefreshJTI, tokens.TokenTypeRefresh, refreshExpiry); err != nil {
		return "", errors.New("failed to store new refresh token")
	}

	if err := tokens.SaveToken(payload.UUID, newAccessJTI, tokens.TokenTypeAccess, accessExpiry); err != nil {
		return "", errors.New("failed to store new access token")
	}

	// 7. Expire old cookies
	tokens.ExpireRefreshToken(w)
	tokens.ExpireCsrfToken(w)

	// 8. Issue new tokens
	accessToken := tokens.CreateAccessToken(
		w,
		payload.Role,
		payload.UUID,
		newAccessJTI,
		payload.UserID,
	)

	tokens.CreateRefreshToken(
		w,
		payload.Role,
		payload.UUID,
		newRefreshJTI,
		newAccessJTI,
		payload.UserID,
	)

	tokens.CreateCsrfToken(w)

	return accessToken, nil
}
