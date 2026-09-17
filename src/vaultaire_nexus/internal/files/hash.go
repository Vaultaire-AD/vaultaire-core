package files

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
