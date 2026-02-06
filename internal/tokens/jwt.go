package tokens

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var secretKey []byte

func SetJWTSecret(secret []byte) {
	// copy to avoid external mutation
	if secret == nil {
		secretKey = nil
		return
	}
	secretKey = append([]byte(nil), secret...)
}

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTPayload struct {
	UUID      string `json:"uuid"`
	Role      string `json:"role"`
	Exp       int64  `json:"exp"`
	TokenType string `json:"type"`
	JTI       string `json:"jti"`
	AccessJTI string `json:"access_jti,omitempty"`
	UserID    int    `json:"user_id,omitempty"`
}

func GenerateJWT(
	uuid, role, tokenType, jti string,
	duration time.Duration,
	userID int,
	extra ...string,
) (string, error) {
	if len(secretKey) == 0 {
		return "", ErrJWTSecretNotSet
	}

	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	payload := JWTPayload{
		UUID:      uuid,
		Role:      role,
		Exp:       time.Now().Add(duration).Unix(),
		TokenType: tokenType,
		JTI:       jti,
		UserID:    userID,
	}

	// If it's a refresh token and we passed an access token's JTI
	if tokenType == TokenTypeRefresh && len(extra) > 0 {
		payload.AccessJTI = extra[0]
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	unsignedToken := headerBase64 + "." + payloadBase64

	signature := signHMAC(unsignedToken, secretKey)
	signedToken := unsignedToken + "." + signature

	return signedToken, nil
}

// cryptographic signature for the JWT using HMAC-SHA256
func signHMAC(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

//--------------------------------------------------------------

var (
	ErrJWTSecretNotSet        = errors.New("jwt secret not set")
	ErrInvalidTokenFromat     = errors.New("invalid token format")
	ErrTokenExpired           = errors.New("token expired")
	ErrInvalidTokken          = errors.New("invalid token type")
	ErrInvalidPayloadJSON     = errors.New("invalid payload JSON")
	ErrInvalidPayloadEncode   = errors.New("invalid payload encoding")
	ErrInvalidTokkenSignature = errors.New("invalid token signature")
)

func VerifyJWT(token, expectedType string) (*JWTPayload, error) {
	if len(secretKey) == 0 {
		return nil, ErrJWTSecretNotSet
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidTokenFromat
	}

	unsignedToken := parts[0] + "." + parts[1]
	expectedSig := signHMAC(unsignedToken, secretKey)

	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, ErrInvalidTokkenSignature
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidPayloadEncode
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidPayloadJSON
	}

	if time.Now().Unix() > payload.Exp {
		return nil, ErrTokenExpired
	}

	if payload.TokenType != expectedType {
		return nil, ErrInvalidTokken
	}

	return &payload, nil
}

// Extract data from jwt
func GetJWTFromContext(ctx context.Context) *JWTPayload {
	payload, ok := ctx.Value("jwtPayload").(*JWTPayload)
	if !ok {
		return nil
	}
	return payload
}
