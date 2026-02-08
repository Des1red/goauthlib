package auth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Des1red/goauthlib/internal/logger"
	"github.com/Des1red/goauthlib/internal/tokens"
	"github.com/Des1red/goauthlib/internal/uuid"
)

func refreshAccessToken(
	refreshToken string,
	w http.ResponseWriter,
) (string, error) {

	logger.Log("Starting refreshAccessToken")

	// 1. Verify refresh token
	payload, err := tokens.VerifyJWT(refreshToken, tokens.TokenTypeRefresh)
	if err != nil {
		logger.Log(fmt.Sprintf("Error verifying refresh token: %v", err))
		return "", errors.New("invalid or expired refresh token")
	}
	logger.Log(fmt.Sprintf("Verified refresh token for user %s, role: %s", payload.UUID, payload.Role))

	// 2. Anonymous users cannot refresh
	if payload.Role == tokens.RoleAnonymous {
		logger.Log("Anonymous user attempted to refresh token")
		return "", errors.New("anonymous users cannot refresh")
	}

	// 3. Check refresh JTI exists (one-time-use)
	exists, err := tokens.TokenExists(payload.JTI)
	if err != nil || !exists {
		logger.Log(fmt.Sprintf("Refresh token JTI check failed: %v, exists: %v", err, exists))
		return "", errors.New("refresh token already used or invalid")
	}

	logger.Log("Refresh token JTI is valid, deleting used token")
	if err := tokens.DeleteToken(payload.JTI); err != nil {
		logger.Log(fmt.Sprintf("Failed to revoke refresh token: %v", err))
		return "", errors.New("failed to revoke refresh token")
	}

	// 4. Revoke old access token (if linked)
	if payload.AccessJTI != "" {
		logger.Log(fmt.Sprintf("Revoking old access token with JTI: %s", payload.AccessJTI))
		_ = tokens.DeleteToken(payload.AccessJTI)
	}

	// 5. Generate new JTIs
	newRefreshJTI := uuid.GenerateUUID()
	newAccessJTI := uuid.GenerateUUID()
	logger.Log(fmt.Sprintf("Generated new JTI for refresh: %s, access: %s", newRefreshJTI, newAccessJTI))

	refreshExpiry := time.Now().Add(tokens.RefreshTokenTime).Unix()
	accessExpiry := time.Now().Add(tokens.AccessTokenTime).Unix()

	// 6. Store new tokens
	logger.Log("Storing new refresh and access tokens")
	if err := tokens.SaveToken(payload.UUID, newRefreshJTI, tokens.TokenTypeRefresh, refreshExpiry); err != nil {
		logger.Log(fmt.Sprintf("Failed to store new refresh token: %v", err))
		return "", errors.New("failed to store new refresh token")
	}

	if err := tokens.SaveToken(payload.UUID, newAccessJTI, tokens.TokenTypeAccess, accessExpiry); err != nil {
		logger.Log(fmt.Sprintf("Failed to store new access token: %v", err))
		return "", errors.New("failed to store new access token")
	}

	// 7. Expire old cookies
	logger.Log("Expiring old cookies")
	tokens.ExpireRefreshToken(w)
	tokens.ExpireCsrfToken(w)

	// 8. Issue new tokens
	logger.Log("Issuing new tokens")
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

	logger.Log("Successfully refreshed tokens and set new cookies")

	return accessToken, nil
}
