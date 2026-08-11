// Package serviceauth provides HMAC-SHA256 signed service-to-service authentication,
// replacing the spoofable X-Internal-Call header approach.
//
// Usage (caller side):
//
//	signer := serviceauth.NewSigner(os.Getenv("INTERNAL_AUTH_SECRET"))
//	signer.SignRequest(req)
//
// Usage (receiver middleware):
//
//	verifier := serviceauth.NewVerifier(os.Getenv("INTERNAL_AUTH_SECRET"))
//	if verifier.Verify(c) { /* trusted internal call */ }
package serviceauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// HeaderSignature carries the HMAC-SHA256 hex digest.
	HeaderSignature = "X-Internal-Signature"
	// HeaderTimestamp carries the Unix epoch seconds at signing time.
	HeaderTimestamp = "X-Internal-Timestamp"
	// HeaderServiceCall is the legacy header, kept for logging/detection.
	HeaderServiceCall = "X-Internal-Call"
	// HeaderNonce carries a random nonce mixed into the signed message so two
	// otherwise-identical requests (same method/path/query/body/tenant/second)
	// produce different signatures. It adds entropy to the HMAC input — it does
	// NOT by itself prevent replay. Verify never records or checks nonces for
	// reuse, so a captured request can be replayed verbatim until it falls
	// outside maxClockSkew (see Verify's doc comment). A distributed nonce
	// cache (e.g. Redis SETNX with TTL) would close that gap; tracked as
	// tracker item W2-12, deferred because it needs a Redis handle this
	// package doesn't have.
	HeaderNonce = "X-Internal-Nonce"
	// HeaderBodyHash carries the SHA-256 hex digest of the request body.
	HeaderBodyHash = "X-Internal-Body-Hash"
	// HeaderTenantID carries the tenant identifier (signed when present).
	HeaderTenantID = "X-Tenant-ID"
	// nonceBytes is the number of random bytes used for nonce generation.
	nonceBytes = 16
	// maxClockSkew is the maximum allowed difference between signing and verification time.
	maxClockSkew = 5 * time.Minute
)

// Signer signs outbound HTTP requests.
type Signer struct {
	secret []byte
}

// NewSigner creates a signer with the given shared secret.
func NewSigner(secret string) *Signer {
	return &Signer{secret: []byte(secret)}
}

// generateNonce returns a hex-encoded random nonce.
func generateNonce() string {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		// Fall back to timestamp-based nonce if crypto/rand fails (should never happen).
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// computeBodyHash returns the hex-encoded SHA-256 digest of the request body.
// If the body is nil or empty, it returns an empty string.
// The body is read and then restored so it can be read again downstream.
func computeBodyHash(req *http.Request) string {
	if req.Body == nil {
		return ""
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || len(body) == 0 {
		return ""
	}
	// Restore the body so it can be read again by the handler.
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// canonicalQuery returns a deterministic, order-independent encoding of a
// request's query string so the HMAC binds to the actual query parameters
// rather than their on-the-wire order. Keys are sorted, and each key's
// values are sorted too (repeated keys, e.g. "a=2&a=1", are preserved but
// normalized), so an on-path modifier that only reorders parameters can't
// produce a different canonical form — but changing, adding, or removing a
// key or value does. Returns "" for a request with no query string, which
// keeps buildMessage's legacy (query-omitted) form for the common case.
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Malformed query string: fall back to the raw bytes so a
		// broken-but-present query still participates in the signature
		// instead of being silently treated as absent.
		return rawQuery
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		vals := append([]string(nil), values[k]...)
		sort.Strings(vals)
		for j, v := range vals {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// buildMessage constructs the canonical HMAC message string.
//
// Format when query == "": method|path|timestamp|nonce|bodyHash|tenantID
// Format when query != "": method|path|query|timestamp|nonce|bodyHash|tenantID
//
// The query segment is included only when non-empty specifically so a
// no-query request produces byte-identical messages to the pre-SEC-2 format
// — no compatibility fallback is needed for the (overwhelmingly common)
// no-query case. See Verify for how query-carrying requests stay compatible
// with peers still running the pre-SEC-2 signer during a rolling upgrade.
func buildMessage(method, path, query, timestamp, nonce, bodyHash, tenantID string) string {
	if query == "" {
		return fmt.Sprintf("%s|%s|%s|%s|%s|%s", method, path, timestamp, nonce, bodyHash, tenantID)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", method, path, query, timestamp, nonce, bodyHash, tenantID)
}

// SignRequest adds HMAC headers to an outbound request.
func (s *Signer) SignRequest(req *http.Request) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := generateNonce()
	bodyHash := computeBodyHash(req)
	tenantID := req.Header.Get(HeaderTenantID) // include if already set by caller
	query := canonicalQuery(req.URL.RawQuery)

	message := buildMessage(req.Method, req.URL.Path, query, ts, nonce, bodyHash, tenantID)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set(HeaderServiceCall, "true")
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodyHash, bodyHash)
	req.Header.Set(HeaderSignature, sig)
}

// Verifier validates inbound signed requests.
type Verifier struct {
	secret []byte
}

// NewVerifier creates a verifier with the given shared secret.
func NewVerifier(secret string) *Verifier {
	return &Verifier{secret: []byte(secret)}
}

// Verify checks that an inbound Gin request has a valid HMAC signature
// and was signed within the allowed clock skew window.
// It returns true if the request is a legitimately signed internal call.
//
// Replay window: this bounds replay to at most maxClockSkew (±5m) via the
// timestamp check below — nothing more. HeaderNonce is signed entropy, not
// a dedup key: Verify never records a nonce or rejects a reused one, so an
// exact replay of a captured request succeeds until it ages out of the
// clock-skew window. See HeaderNonce's doc comment and tracker item W2-12.
func (v *Verifier) Verify(c *gin.Context) bool {
	header := strings.ToLower(strings.TrimSpace(c.GetHeader(HeaderServiceCall)))
	if header != "true" && header != "1" {
		return false
	}

	sig := c.GetHeader(HeaderSignature)
	tsStr := c.GetHeader(HeaderTimestamp)
	if sig == "" || tsStr == "" {
		return false
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}

	// Check clock skew
	diff := time.Since(time.Unix(ts, 0))
	if math.Abs(diff.Seconds()) > maxClockSkew.Seconds() {
		return false
	}

	// Extract optional hardened headers (backward-compatible: missing = empty string).
	nonce := c.GetHeader(HeaderNonce)
	tenantID := c.GetHeader(HeaderTenantID)

	// Recompute the body hash from the ACTUAL inbound body rather than trusting
	// the X-Internal-Body-Hash header value. Folding the header into the HMAC
	// message only proves the header was signed — not that the body matches it,
	// which let a captured signed request be replayed with a substituted body
	// (the signature still verified). Hashing the real body binds the signature
	// to the payload. computeBodyHash restores c.Request.Body so the handler can
	// still read it. A legitimate signer sends header == SHA-256(body), so this
	// stays compatible with existing callers.
	bodyHash := computeBodyHash(c.Request)
	query := canonicalQuery(c.Request.URL.RawQuery)
	sigBytes := []byte(sig)

	// Recompute expected signature against the current canonical message
	// (query included whenever the request carries one). matchedQuery tracks
	// which query form actually matched, so the defense-in-depth tenant check
	// below re-derives the SAME message shape rather than assuming the new one.
	matchedQuery := query
	message := buildMessage(c.Request.Method, c.Request.URL.Path, query, tsStr, nonce, bodyHash, tenantID)
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))
	matched := hmac.Equal(sigBytes, []byte(expected))

	// Rolling-upgrade compatibility: a peer still running the pre-SEC-2
	// signer never included the query string in the message at all (it only
	// ever signed method|path|timestamp|nonce|bodyHash|tenantID, regardless
	// of RawQuery). For a request that DOES carry a query string, retry
	// against that legacy (query-omitted) message before giving up, so
	// not-yet-upgraded pods keep verifying mid-rollout. Requests with no
	// query string already produce the legacy message on the first attempt
	// (buildMessage omits the query segment when query == ""), so no
	// fallback branch is needed — or possible — for them.
	if !matched && query != "" {
		matchedQuery = ""
		legacyMessage := buildMessage(c.Request.Method, c.Request.URL.Path, "", tsStr, nonce, bodyHash, tenantID)
		legacyMac := hmac.New(sha256.New, v.secret)
		legacyMac.Write([]byte(legacyMessage))
		legacyExpected := hex.EncodeToString(legacyMac.Sum(nil))
		matched = hmac.Equal(sigBytes, []byte(legacyExpected))
	}

	if !matched {
		return false
	}

	// Defense in depth: explicitly reject the "signed-empty + inbound-nonempty"
	// case. The HMAC check above already covers it (signer used "" → verifier
	// recomputes with the inbound value → mismatch), but we re-check against an
	// alt canonical message with tenantID="" so a future refactor that derives
	// the verifier's tenant from elsewhere can't reopen the bypass. If the
	// signature *also* validates against the empty-tenant message, the inbound
	// X-Tenant-ID header was added by an intermediary post-signing. Uses
	// matchedQuery so this re-derives the exact message shape (new or legacy)
	// that produced the match above, rather than assuming the new one.
	if tenantID != "" {
		altMessage := buildMessage(c.Request.Method, c.Request.URL.Path, matchedQuery, tsStr, nonce, bodyHash, "")
		altMac := hmac.New(sha256.New, v.secret)
		altMac.Write([]byte(altMessage))
		altExpected := hex.EncodeToString(altMac.Sum(nil))
		if hmac.Equal(sigBytes, []byte(altExpected)) {
			return false
		}
	}

	return true
}

var (
	packageSigner     *Signer
	packageSignerOnce sync.Once
)

// SignRequestFromEnv signs the request using the INTERNAL_AUTH_SECRET env var.
// If the secret is not set, it falls back to the legacy X-Internal-Call header.
func SignRequestFromEnv(req *http.Request) {
	packageSignerOnce.Do(func() {
		if secret := os.Getenv("INTERNAL_AUTH_SECRET"); secret != "" {
			packageSigner = NewSigner(secret)
		}
	})
	if packageSigner != nil {
		packageSigner.SignRequest(req)
	} else {
		req.Header.Set(HeaderServiceCall, "true")
	}
}
