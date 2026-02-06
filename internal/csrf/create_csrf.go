package csrf

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
