package handlers

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// Platform-CA fingerprint for agent enrollment.
//
// An agent installing against a platform whose edge certificate is signed by a
// private CA is asked to approve that CA (see shared/certificates trust
// bootstrap). That prompt is only meaningful if the operator can compare the
// fingerprint against a source OTHER than the connection being validated —
// otherwise anything able to intercept the enrollment can present its own CA
// and have it accepted. This endpoint is that second source: the operator is
// already authenticated in a browser session when they mint a registration key,
// so the fingerprint shown next to the key travels over a channel the agent's
// connection cannot forge.
//
// SSRF note: the URL probed comes ONLY from server-side config
// (WEB_UI_BASE_URL, set by the chart from tls.dnsName). It is never taken from
// the request — not from a query parameter and not from the Host header — so
// this endpoint cannot be steered at an arbitrary host.

// platformCAResponse is the shape the registration dialog renders.
type platformCAResponse struct {
	// Available is false when the fingerprint could not be determined; Reason
	// then explains why, so the UI can say something useful instead of showing
	// an empty box.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// TrustedByDefault reports that the edge certificate verifies against the
	// public trust store. Agents will enroll with no trust prompt at all, and
	// the UI should say so rather than showing a fingerprint nobody needs.
	TrustedByDefault bool `json:"trusted_by_default"`

	PublicURL          string `json:"public_url,omitempty"`
	FingerprintSHA256  string `json:"fingerprint_sha256,omitempty"`
	FingerprintDisplay string `json:"fingerprint_display,omitempty"`
	Subject            string `json:"subject,omitempty"`
	Issuer             string `json:"issuer,omitempty"`
	NotAfter           string `json:"not_after,omitempty"`
	SelfSigned         bool   `json:"self_signed,omitempty"`
}

// platformCACache memoizes the probe. The edge certificate changes only on
// renewal, and every operator opening the registration dialog would otherwise
// trigger a fresh handshake against our own front door.
type platformCACache struct {
	mu        sync.Mutex
	value     *platformCAResponse
	expiresAt time.Time
}

var caCache platformCACache

const platformCACacheTTL = 5 * time.Minute

// GetPlatformCA returns the fingerprint of the CA that signed this platform's
// edge certificate, for the operator to compare against what the agent shows
// during enrollment.
func (h *Handler) GetPlatformCA(c *gin.Context) {
	caCache.mu.Lock()
	if caCache.value != nil && time.Now().Before(caCache.expiresAt) {
		cached := *caCache.value
		caCache.mu.Unlock()
		c.JSON(http.StatusOK, cached)
		return
	}
	caCache.mu.Unlock()

	resp := probePlatformCA(publicBaseURL())

	caCache.mu.Lock()
	caCache.value = &resp
	caCache.expiresAt = time.Now().Add(platformCACacheTTL)
	caCache.mu.Unlock()

	c.JSON(http.StatusOK, resp)
}

// publicBaseURL is the platform's own browser-facing origin, from server config
// only. The chart sets WEB_UI_BASE_URL from tls.dnsName for every backend.
func publicBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("WEB_UI_BASE_URL")), "/")
}

func probePlatformCA(publicURL string) platformCAResponse {
	if publicURL == "" {
		return platformCAResponse{
			Available: false,
			Reason:    "This platform's public URL is not configured (WEB_UI_BASE_URL), so its certificate cannot be inspected from here.",
		}
	}
	if strings.HasPrefix(publicURL, "http://") {
		return platformCAResponse{
			Available: false,
			PublicURL: publicURL,
			Reason:    "This platform is served over plain HTTP, so there is no certificate for an agent to verify.",
		}
	}

	// Does it already verify against the public trust store? If so no agent
	// will ever see the trust prompt, and showing a fingerprint would imply a
	// step that does not exist.
	if certificates.VerifiesAgainstSystemRoots(publicURL) {
		return platformCAResponse{
			Available:        true,
			TrustedByDefault: true,
			PublicURL:        publicURL,
			Reason:           "This platform's certificate is signed by a publicly-trusted CA. Agents verify it automatically and will not ask you to approve anything.",
		}
	}

	anchor, err := certificates.FetchServerTrustAnchor(publicURL)
	if err != nil {
		return platformCAResponse{
			Available: false,
			PublicURL: publicURL,
			Reason:    "Could not read this platform's certificate: " + err.Error(),
		}
	}

	return platformCAResponse{
		Available:          true,
		PublicURL:          publicURL,
		FingerprintSHA256:  anchor.FingerprintSHA256,
		FingerprintDisplay: strings.ReplaceAll(certificates.FormatFingerprint(anchor.FingerprintSHA256), "\n", " "),
		Subject:            anchor.Certificate.Subject.String(),
		Issuer:             anchor.Certificate.Issuer.String(),
		NotAfter:           anchor.Certificate.NotAfter.UTC().Format(time.RFC3339),
		SelfSigned:         anchor.SelfSigned,
	}
}
