package uuid

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateUUID() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "" // or panic/log
	}

	// Simple hex-encoded UUID-like string
	return hex.EncodeToString(bytes)
}
