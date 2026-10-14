// Package versions reads the platform's running versions from
// monitoring-service's GET /version — the same aggregator the tenant About page
// renders — over an HMAC-signed service call, so the admin console's About &
// Updates page and the tenant About page can never disagree about what runs.
package versions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// Path is monitoring-service's version aggregator route.
const Path = "/api/v1/monitoring-service/version"

// requestTimeout bounds the proxied call. The aggregator itself fans out to
// every service with a 3s probe timeout, so this leaves it room to answer.
const requestTimeout = 8 * time.Second

// maxBody caps what is read back; the aggregator's body is a few KB.
const maxBody = 1 << 20

// Source returns the aggregator's JSON body verbatim.
type Source interface {
	Versions(ctx context.Context) (json.RawMessage, error)
}

// Client is the monitoring-service Source.
type Client struct {
	base   string
	http   *http.Client
	signer *serviceauth.Signer
}

// New builds a client against base (scheme://host:port, no path).
func New(base string, httpClient *http.Client, internalSecret string) (*Client, error) {
	if strings.TrimSpace(internalSecret) == "" {
		return nil, errors.New("versions: INTERNAL_AUTH_SECRET is not set; the version aggregator call must be signed")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{base: strings.TrimRight(base, "/"), http: httpClient, signer: serviceauth.NewSigner(internalSecret)}, nil
}

// NewFromEnv builds the production client: monitoring-service's peer URL
// derived from USE_MTLS (MONITORING_SERVICE_URL overrides it), the mTLS client
// certificate when the mesh is on — a plain client would fail the handshake on
// :8443 and read as "monitoring-service down" — and INTERNAL_AUTH_SECRET for
// the signature.
func NewFromEnv() (*Client, error) {
	useMTLS := sharedconfig.MTLSEnabled()
	base := sharedconfig.PeerServiceURL("MONITORING_SERVICE_URL", "monitoring-service", useMTLS)
	httpClient := &http.Client{Timeout: requestTimeout}
	if useMTLS {
		c, err := sharedhttp.NewMTLSClient(
			sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
			sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
			sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
		)
		if err != nil {
			return nil, fmt.Errorf("versions: mTLS is on but the client certificate could not be loaded: %w", err)
		}
		c.Timeout = requestTimeout
		httpClient = c
	}
	return New(base, httpClient, os.Getenv("INTERNAL_AUTH_SECRET"))
}

// Versions implements Source.
func (c *Client) Versions(ctx context.Context) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+Path, nil)
	if err != nil {
		return nil, err
	}
	c.signer.SignRequest(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("versions: monitoring-service unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("versions: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("versions: monitoring-service answered HTTP %d", resp.StatusCode)
	}
	if !json.Valid(body) {
		return nil, errors.New("versions: monitoring-service answered a body that is not JSON")
	}
	return json.RawMessage(body), nil
}
