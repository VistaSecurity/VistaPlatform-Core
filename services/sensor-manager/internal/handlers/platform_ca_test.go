package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// privatelySignedServer stands up HTTPS with a chain rooted in a CA no trust
// store knows — the shape a self-hosted platform presents by default.
func privatelySignedServer(t *testing.T) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Acme Internal Root CA", Organization: []string{"Acme Corp"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "vista.acme.internal"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, ca.Raw}, PrivateKey: leafKey}},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, ca
}

// TestProbePlatformCA_ReturnsFingerprintForPrivateCA covers the case the
// feature exists for: the operator needs a fingerprint to compare against what
// the agent shows at enrollment, and it must be the fingerprint of the CA the
// agent will actually be asked to approve.
func TestProbePlatformCA_ReturnsFingerprintForPrivateCA(t *testing.T) {
	srv, ca := privatelySignedServer(t)

	got := probePlatformCA(srv.URL)

	if !got.Available {
		t.Fatalf("fingerprint unavailable: %s", got.Reason)
	}
	if got.TrustedByDefault {
		t.Error("privately-signed platform reported as publicly trusted")
	}
	// The agent pins the issuer-most cert; the operator must be shown the same
	// one or the comparison is meaningless.
	if got.FingerprintSHA256 != certificates.FingerprintSHA256(ca) {
		t.Errorf("fingerprint = %s, want the CA's %s", got.FingerprintSHA256, certificates.FingerprintSHA256(ca))
	}
	if !got.SelfSigned {
		t.Error("self-signed root not reported as self-signed")
	}
	if !strings.Contains(got.Subject, "Acme Internal Root CA") {
		t.Errorf("subject = %q, want the CA subject", got.Subject)
	}
	// The display form is what a human actually compares; it must be grouped
	// and on one line for the dialog.
	if !strings.Contains(got.FingerprintDisplay, ":") || strings.Contains(got.FingerprintDisplay, "\n") {
		t.Errorf("display fingerprint not single-line colon-grouped: %q", got.FingerprintDisplay)
	}
}

// TestProbePlatformCA_MatchesWhatTheAgentComputes is the cross-check that makes
// the whole comparison workflow honest: the UI value and the value the agent
// prints at the prompt must be byte-identical, or an operator following the
// documented procedure sees a false mismatch.
func TestProbePlatformCA_MatchesWhatTheAgentComputes(t *testing.T) {
	srv, _ := privatelySignedServer(t)

	fromUI := probePlatformCA(srv.URL)
	fromAgent, err := certificates.FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("agent-side fetch: %v", err)
	}

	if fromUI.FingerprintSHA256 != fromAgent.FingerprintSHA256 {
		t.Fatalf("UI shows %s but the agent prompt shows %s — operators would see a false mismatch",
			fromUI.FingerprintSHA256, fromAgent.FingerprintSHA256)
	}
	if !certificates.FingerprintsEqual(fromUI.FingerprintDisplay, fromAgent.FingerprintSHA256) {
		t.Error("the displayed (colon-grouped) form does not compare equal to the agent's value")
	}
}

// TestProbePlatformCA_UnconfiguredPublicURL keeps the dialog from rendering an
// empty box: with no public URL configured the endpoint must say why.
func TestProbePlatformCA_UnconfiguredPublicURL(t *testing.T) {
	got := probePlatformCA("")
	if got.Available {
		t.Fatal("reported a fingerprint with no public URL configured")
	}
	if !strings.Contains(got.Reason, "WEB_UI_BASE_URL") {
		t.Errorf("reason does not name the missing setting: %q", got.Reason)
	}
}

// TestProbePlatformCA_PlainHTTP — there is no certificate to show, and saying
// so beats a generic failure.
func TestProbePlatformCA_PlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	got := probePlatformCA(srv.URL)
	if got.Available {
		t.Fatal("reported a fingerprint for a plain-HTTP platform")
	}
	if !strings.Contains(strings.ToLower(got.Reason), "http") {
		t.Errorf("reason does not explain the plain-HTTP case: %q", got.Reason)
	}
}

// TestProbePlatformCA_UnreachableIsReportedNotFatal — a platform that cannot
// reach its own front door (split DNS, egress policy) must degrade to an
// explanation rather than a broken dialog.
func TestProbePlatformCA_UnreachableIsReportedNotFatal(t *testing.T) {
	got := probePlatformCA("https://127.0.0.1:1")
	if got.Available {
		t.Fatal("reported a fingerprint for an unreachable endpoint")
	}
	if got.Reason == "" {
		t.Error("no reason given for an unreachable platform")
	}
}

// TestGetPlatformCA_HandlerServesWhatTheAgentWillShow drives the real gin
// handler, including the env-config read and the JSON envelope the registration
// dialog consumes, and cross-checks it against what the agent computes at the
// enrollment prompt. If these two ever disagree, an operator following the
// documented compare-the-fingerprint procedure sees a false mismatch — and
// either blocks a legitimate install or learns to ignore the warning.
func TestGetPlatformCA_HandlerServesWhatTheAgentWillShow(t *testing.T) {
	srv, ca := privatelySignedServer(t)

	// The handler takes its target from server config only — never the request.
	t.Setenv("WEB_UI_BASE_URL", srv.URL)
	resetPlatformCACache()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{}
	r.GET("/platform-ca", h.GetPlatformCA)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/platform-ca", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unavailability is reported in the body, not by status)", w.Code)
	}
	var got platformCAResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	if !got.Available || got.TrustedByDefault {
		t.Fatalf("unexpected availability: %+v", got)
	}

	agentAnchor, err := certificates.FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("agent-side fetch: %v", err)
	}
	if got.FingerprintSHA256 != agentAnchor.FingerprintSHA256 {
		t.Fatalf("dialog shows %s but the agent prompt shows %s", got.FingerprintSHA256, agentAnchor.FingerprintSHA256)
	}
	if got.FingerprintSHA256 != certificates.FingerprintSHA256(ca) {
		t.Fatal("neither side is showing the actual signing CA")
	}
}

// TestGetPlatformCA_UnconfiguredStillAnswers200 — the dialog must always get a
// renderable answer; a 500 here would break the registration flow over
// something that is only informational.
func TestGetPlatformCA_UnconfiguredStillAnswers200(t *testing.T) {
	t.Setenv("WEB_UI_BASE_URL", "")
	resetPlatformCACache()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{}
	r.GET("/platform-ca", h.GetPlatformCA)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/platform-ca", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got platformCAResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Available || got.Reason == "" {
		t.Fatalf("expected an explained unavailability, got %+v", got)
	}
}

// resetPlatformCACache clears the memoized probe between tests — without it the
// first test's answer would be served to the second and both would pass
// vacuously.
func resetPlatformCACache() {
	caCache.mu.Lock()
	caCache.value = nil
	caCache.expiresAt = time.Time{}
	caCache.mu.Unlock()
}
