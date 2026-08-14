package serviceauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const testSecret = "test-secret-do-not-use-in-prod"

func newVerifyCtx(t *testing.T, req *http.Request) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	return c
}

// Happy path: signed with tenantID="acme", inbound header "acme" → accept.
func TestVerify_TenantBound(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	req.Header.Set(HeaderTenantID, "acme")
	signer.SignRequest(req)

	verifier := NewVerifier(testSecret)
	if !verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("expected legitimate tenant-bound request to verify")
	}
}

// Happy path: signed with no tenant, no inbound tenant header → accept.
func TestVerify_NoTenant(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	signer.SignRequest(req)

	verifier := NewVerifier(testSecret)
	if !verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("expected legitimate no-tenant request to verify")
	}
}

// Attack path: caller signs with no tenant, intermediary adds X-Tenant-ID
// before the verifier sees it. Current HMAC check catches it because the
// verifier recomputes with the inbound (post-signing) value. The new
// alt-message guard MUST also catch this case so a future refactor can't
// reopen the gap.
func TestVerify_RejectsPostSigningTenantInjection(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	signer.SignRequest(req) // signed with tenantID=""

	// Intermediary injects a tenant header.
	req.Header.Set(HeaderTenantID, "victim")

	verifier := NewVerifier(testSecret)
	if verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier accepted post-signing tenant injection — bypass!")
	}
}

// Sanity check the wrong-secret path still rejects.
func TestVerify_RejectsWrongSecret(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	req.Header.Set(HeaderTenantID, "acme")
	signer.SignRequest(req)

	otherVerifier := NewVerifier("different-secret")
	if otherVerifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier accepted request signed with a different secret")
	}
}

// Happy path with a request body: signer hashes the body, verifier recomputes
// the same hash from the (restored) body → accept. Also asserts the handler can
// still read the body after verification.
func TestVerify_BodySignedAndReadable(t *testing.T) {
	signer := NewSigner(testSecret)
	body := `{"api_calls":1,"storage_mb":10}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/metrics", strings.NewReader(body))
	signer.SignRequest(req)

	c := newVerifyCtx(t, req)
	verifier := NewVerifier(testSecret)
	if !verifier.Verify(c) {
		t.Fatal("expected a legitimately signed request with a body to verify")
	}

	// The handler must still be able to read the body after verification.
	got, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("reading body after verify: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body not restored for handler: got %q want %q", got, body)
	}
}

// Attack path: capture a signed request and replay it with a substituted body,
// keeping the original signature/nonce/timestamp headers. The verifier must
// reject because it recomputes the hash from the actual (swapped) body rather
// than trusting the X-Internal-Body-Hash header.
func TestVerify_RejectsBodySubstitution(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/metrics",
		strings.NewReader(`{"api_calls":1}`))
	signer.SignRequest(req) // signs over the hash of the original body

	// Swap the body wholesale; leave every signed header intact.
	req.Body = io.NopCloser(strings.NewReader(`{"api_calls":1000000}`))

	verifier := NewVerifier(testSecret)
	if verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier accepted a request whose body was swapped after signing — replay bypass!")
	}
}

// Expired-timestamp path: signature is valid but outside the clock-skew window.
func TestVerify_RejectsExpiredTimestamp(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	signer.SignRequest(req)

	old := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	req.Header.Set(HeaderTimestamp, old)

	verifier := NewVerifier(testSecret)
	if verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier accepted a request outside the clock-skew window")
	}
}

// --- SEC-2: query-string binding -------------------------------------------

// Happy path: a request with a query string signs and verifies normally.
func TestVerify_QueryString_HappyPath(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo?tenant_id=acme&limit=10", nil)
	signer.SignRequest(req)

	verifier := NewVerifier(testSecret)
	if !verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("expected a legitimately signed request with a query string to verify")
	}
}

// Mutation test (a): an on-path modifier tampers a query parameter after
// signing. Before SEC-2 the HMAC never covered the query string at all, so
// this mutation would have sailed through verification unnoticed.
func TestVerify_RejectsQueryParamTampering(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo?tenant_id=acme&limit=10", nil)
	signer.SignRequest(req)

	// Tamper the query after signing, leaving every signed header intact.
	req.URL.RawQuery = "tenant_id=victim&limit=10"

	verifier := NewVerifier(testSecret)
	if verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier accepted a request whose query string was tampered after signing")
	}
}

// Reordering query parameters must NOT invalidate the signature — the
// canonical form sorts keys/values, so this is not the same as tampering.
func TestVerify_QueryParamReorderingDoesNotInvalidate(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo?limit=10&tenant_id=acme", nil)
	signer.SignRequest(req)

	// Reorder (not tamper) the query params before verification.
	req.URL.RawQuery = "tenant_id=acme&limit=10"

	verifier := NewVerifier(testSecret)
	if !verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier rejected a request whose query params were only reordered, not tampered")
	}
}

// Mutation test (b): a legacy (pre-SEC-2) signer never included the query
// string in the signed message at all, regardless of RawQuery. Simulate
// that peer directly by building the old-format message by hand, and assert
// the current Verify still accepts it — this is the rolling-upgrade
// compatibility path.
func TestVerify_AcceptsLegacySignatureWithQueryString(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo?tenant_id=acme&limit=10", nil)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "legacynonce"
	bodyHash := "" // no body

	// Pre-SEC-2 message format: method|path|timestamp|nonce|bodyHash|tenantID
	// — the query string never appeared in it, even though the request has one.
	legacyMessage := req.Method + "|" + req.URL.Path + "|" + ts + "|" + nonce + "|" + bodyHash + "|"
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(legacyMessage))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set(HeaderServiceCall, "true")
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodyHash, bodyHash)
	req.Header.Set(HeaderSignature, sig)

	// Opt-in only. The fallback is off by default now, so a verifier that wants
	// rolling-upgrade compatibility has to ask for it.
	verifier := NewVerifierWithLegacyQuery(testSecret, true)
	if !verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier rejected a legacy-format signature for a query-carrying request — breaks rolling upgrade")
	}

	// Same request, default verifier → rejected.
	if NewVerifierWithLegacyQuery(testSecret, false).Verify(newVerifyCtx(t, req)) {
		t.Fatal("legacy-format signature accepted with the fallback disabled")
	}
}

// The reason the fallback is off by default.
//
// The legacy message omits the query string entirely, so a signature captured
// from a request that carried NO query also validates for that same method,
// path, body and timestamp with ANY query string appended. Nothing here forges
// a signature — it replays a genuine one, which is what an attacker who can
// observe one internal call actually has, and the ±5m skew window plus the
// absence of nonce dedup gives them time to use it.
func TestVerify_RejectsCapturedNoQuerySignatureReplayedWithQuery(t *testing.T) {
	signer := NewSigner(testSecret)

	// A legitimate, correctly-signed internal call with no query string.
	captured := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	signer.SignRequest(captured)

	// Replay it verbatim — same headers, same signature — but append query
	// parameters of the attacker's choosing.
	replayed := httptest.NewRequest(http.MethodGet, "/api/v1/foo?tenant_id=victim&limit=100000", nil)
	for _, h := range []string{HeaderServiceCall, HeaderTimestamp, HeaderNonce, HeaderBodyHash, HeaderSignature} {
		replayed.Header.Set(h, captured.Header.Get(h))
	}

	if NewVerifierWithLegacyQuery(testSecret, false).Verify(newVerifyCtx(t, replayed)) {
		t.Fatal("captured no-query signature verified with attacker-chosen query params appended")
	}

	// And with the fallback enabled it DOES verify — which is the cost of
	// turning it on, stated here so nobody re-enables it by default believing
	// it is free.
	if !NewVerifierWithLegacyQuery(testSecret, true).Verify(newVerifyCtx(t, replayed)) {
		t.Fatal("expected the legacy fallback to accept this replay; if it no longer does, the fallback's risk note is stale")
	}
}

// The env var is the only thing that flips the default, so pin that wiring.
func TestNewVerifier_LegacyQueryDefaultsOffAndHonorsEnv(t *testing.T) {
	if NewVerifier(testSecret).allowLegacyQuery {
		t.Fatal("legacy query fallback is on with the env var unset — it must default off")
	}
	t.Setenv(LegacyQuerySignatureEnv, "true")
	if !NewVerifier(testSecret).allowLegacyQuery {
		t.Fatalf("%s=true did not enable the legacy fallback", LegacyQuerySignatureEnv)
	}
	t.Setenv(LegacyQuerySignatureEnv, "nonsense")
	if NewVerifier(testSecret).allowLegacyQuery {
		t.Fatal("an unrecognized value enabled the legacy fallback; only true/1/yes should")
	}
}

// Mutation test (c): requests without a query string are unaffected by
// SEC-2 — the message format is byte-identical to before, so there is
// nothing to fall back from and no new compatibility surface.
func TestVerify_NoQueryString_Unchanged(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	signer.SignRequest(req)

	verifier := NewVerifier(testSecret)
	if !verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("expected a legitimately signed no-query request to verify")
	}

	// Also confirm the legacy hand-built message (identical to the new
	// no-query message) verifies — proving there's no behavior change.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "n"
	bodyHash := ""
	legacyMessage := req2.Method + "|" + req2.URL.Path + "|" + ts + "|" + nonce + "|" + bodyHash + "|"
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(legacyMessage))
	sig := hex.EncodeToString(mac.Sum(nil))
	req2.Header.Set(HeaderServiceCall, "true")
	req2.Header.Set(HeaderTimestamp, ts)
	req2.Header.Set(HeaderNonce, nonce)
	req2.Header.Set(HeaderBodyHash, bodyHash)
	req2.Header.Set(HeaderSignature, sig)

	if !verifier.Verify(newVerifyCtx(t, req2)) {
		t.Fatal("no-query message format changed — legacy hand-built signature no longer verifies")
	}
}

// A tampered query string must still be rejected even when a tenant ID is
// also present, exercising the query-tamper check alongside the existing
// tenant-injection defense-in-depth path.
func TestVerify_RejectsQueryTamperingWithTenant(t *testing.T) {
	signer := NewSigner(testSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo?limit=10", nil)
	req.Header.Set(HeaderTenantID, "acme")
	signer.SignRequest(req)

	req.URL.RawQuery = "limit=9999"

	verifier := NewVerifier(testSecret)
	if verifier.Verify(newVerifyCtx(t, req)) {
		t.Fatal("verifier accepted tampered query string on a tenant-bound request")
	}
}
