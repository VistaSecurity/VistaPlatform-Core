package cbom

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex returns hex(sha256(b)) — used by the verify endpoint to recompute
// the content_hash for comparison.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
