package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequestBodyTooLarge reports whether err is an http.MaxBytesReader ceiling.
//
// The typed check is the real one — net/http returns *http.MaxBytesError — and
// the string check is kept beside it because the error travels through
// mime/multipart and gin, either of which may wrap it in something that does
// not implement Unwrap. Matching on text alone is what this codebase keeps
// warning about; matching on text only as a FALLBACK to the typed test is the
// part that makes it safe.
//
// This is the single copy. inventory-service grew the first one for the SBOM
// upload; every cap added since needs exactly the same predicate, and two
// copies of a security predicate is one copy that gets fixed.
func RequestBodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "http: request body too large")
}

// PayloadTooLarge answers 413 and names the cap in the message.
//
// A caller that hits a ceiling has to be told the number, because "too large"
// is not something anyone can act on. It aborts the gin chain: an over-cap
// request has read a partial body at best, so nothing downstream of the cap
// should run.
func PayloadTooLarge(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
		"error":   "Request too large",
		"message": message,
	})
}
