package catalog

import (
	"crypto/rand"
	"encoding/hex"
)

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
