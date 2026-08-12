package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/certificates"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	// Aliased: the device-agent has its own `certificates` package, above.
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// OutboundClient handles outbound-only communication with the platform
type OutboundClient struct {
	config     *config.Config
	httpClient *http.Client
	agentID    uuid.UUID
	baseURL    string
	// agentVersion is the running binary's stamped version (main.Version),
	// reported on registration and on every heartbeat. Set via SetAgentVersion
	// at startup; empty is sent as-is and the platform treats it as
	// "not reported" rather than blanking the stored value.
	agentVersion string
}

// SetAgentVersion records the running binary's version for liveness reporting.
func (c *OutboundClient) SetAgentVersion(v string) { c.agentVersion = v }

// NewOutboundClient creates a new outbound API client
func NewOutboundClient(cfg *config.Config) *OutboundClient {
	// Parse agent ID if provided
	var agentID uuid.UUID
	if cfg.AgentID != "" {
		if id, err := uuid.Parse(cfg.AgentID); err == nil {
			agentID = id
		}
	}

	// Configure HTTP client with TLS if certificates are available
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Server anchor and client identity are configured independently: a pinned
	// ServerCACert must apply BEFORE the agent holds a client cert, because
	// registration — the call that issues that cert — is itself an HTTPS request
	// that has to verify the platform. Gating both on having a client cert made
	// the pin unreachable at the one moment it mattered, so an agent facing a
	// platform with a privately-signed edge cert could never get past x509.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	configured := false

	if cfg.Security.ServerCACert != "" {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM([]byte(cfg.Security.ServerCACert)) {
			tlsConfig.RootCAs = caPool
			configured = true
		} else {
			log.Printf("⚠️  Failed to parse server CA certificate; falling back to system trust store")
		}
	}

	if cfg.Security.UseTLS && cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		// Load client certificate from PEM strings (not files)
		cert, err := tls.X509KeyPair([]byte(cfg.Security.ClientCert), []byte(cfg.Security.ClientKey))
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
			configured = true
		}
	}

	if configured {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return &OutboundClient{
		config:     cfg,
		httpClient: httpClient,
		agentID:    agentID,
		baseURL:    cfg.PlatformURL,
	}
}

// Register registers the agent with the platform using CSR-based flow.
// version is reported to the platform (e.g. main.Version); empty defaults to "dev".
func (c *OutboundClient) Register(version string) error {
	if version == "" {
		version = "dev"
	}
	c.agentVersion = version
	// Generate agent ID (UUID) that will be used as certificate CN
	agentID := uuid.New()
	if c.config.AgentID != "" {
		// If agent ID already exists (from previous registration), use it
		var err error
		agentID, err = uuid.Parse(c.config.AgentID)
		if err != nil {
			// Invalid existing ID, generate new one
			agentID = uuid.New()
		}
	}

	// Generate keypair and CSR locally (private key never leaves agent)
	csrGen := certificates.NewCSRGenerator()
	privateKey, err := csrGen.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	csrPEM, err := csrGen.GenerateCSR(agentID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Store private key securely (will be saved to config)
	privateKeyPEM, err := csrGen.EncodePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/register", c.baseURL)

	reqBody := map[string]interface{}{
		"registration_key": c.config.RegistrationKey,
		"platform":         registrationPlatform(),
		"version":          version,
		"csr":              csrPEM,           // Include CSR in registration request
		"agent_id":         agentID.String(), // Proposed agent ID
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s (status: %d)", string(body), resp.StatusCode)
	}

	var result struct {
		AgentID              string `json:"agent_id"`
		ClientCert           string `json:"client_cert"`       // Signed certificate (no private key)
		ServerCACert         string `json:"server_ca_cert"`    // CA certificate for trust
		ControlPlaneURL      string `json:"control_plane_url"` // mTLS passthrough URL to switch to (#1033)
		CertificateExpiresAt string `json:"certificate_expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	parsedID, err := uuid.Parse(result.AgentID)
	if err != nil {
		return fmt.Errorf("invalid agent_id in registration response: %w", err)
	}
	c.agentID = parsedID
	c.config.AgentID = result.AgentID

	// Store certificate (signed by platform)
	if result.ClientCert != "" {
		c.config.Security.ClientCert = result.ClientCert
	}

	// Store private key locally (never sent to platform)
	c.config.Security.ClientKey = privateKeyPEM

	// ADD the platform's CA to the trust pool rather than replacing what is
	// there. The existing anchor is the one the operator approved at setup and
	// is what verifies the ordinary edge endpoint; the CA arriving here issues
	// the mTLS passthrough listener's certificate, which only exists when
	// agentMtls is enabled — not the chart default. Replacing left the agent
	// trusting a CA that had not signed the endpoint it was still talking to,
	// so enrollment succeeded and everything after it failed the handshake.
	if result.ServerCACert != "" {
		c.config.Security.ServerCACert = sharedcerts.MergeCAPEMs(
			c.config.Security.ServerCACert, result.ServerCACert)
	}

	if c.config.Security.ClientCert != "" && c.config.Security.ClientKey != "" {
		c.config.Security.UseTLS = true
	}

	// Switch to the advertised mTLS passthrough endpoint before
	// reconfiguring TLS. Registration happens on the edge-terminated public
	// host (no client cert held yet, and the passthrough listener requires one
	// at the handshake); every later call must reach the passthrough listener
	// or the proxy strips the client cert and fail-closed enforcement 401s.
	// The caller's saveConfigFile persists the switched platform_url.
	if u := applyAdvertisedPlatformURL(c.config, result.ControlPlaneURL); u {
		c.baseURL = c.config.PlatformURL
	}

	// Reconfigure HTTP client with new certificate
	if err := c.reconfigureTLS(); err != nil {
		return fmt.Errorf("failed to reconfigure TLS after registration: %w", err)
	}

	return nil
}

// applyAdvertisedPlatformURL validates and applies the mTLS passthrough URL
// advertised in a registration response; see Register for why the URL
// switches after registration. Returns true when the config URL changed. An
// empty advertised URL is the normal non-mTLS case; an invalid or non-https
// one is rejected so a misconfigured platform cannot break a working agent.
func applyAdvertisedPlatformURL(cfg *config.Config, advertised string) bool {
	advertised = strings.TrimRight(strings.TrimSpace(advertised), "/")
	if advertised == "" || advertised == cfg.PlatformURL {
		return false
	}
	u, err := url.Parse(advertised)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		log.Printf("⚠️  Ignoring invalid advertised platform URL %q (want https://host[:port])", advertised)
		return false
	}
	log.Printf("🔀 Platform advertised mTLS endpoint — switching from %s to %s", cfg.PlatformURL, advertised)
	cfg.PlatformURL = advertised
	return true
}

// GetNextJob polls the platform for the next available job
func (c *OutboundClient) GetNextJob() (*models.Job, error) {
	if c.agentID == uuid.Nil {
		return nil, fmt.Errorf("agent not registered")
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/jobs", c.baseURL, c.agentID.String())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// No job available
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get job: %s (status: %d)", string(body), resp.StatusCode)
	}

	var job models.Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, fmt.Errorf("failed to decode job: %w", err)
	}

	return &job, nil
}

// SubmitResult submits job results to the platform
func (c *OutboundClient) SubmitResult(result *models.JobResult) error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/results", c.baseURL, c.agentID.String())

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to submit result: %s (status: %d)", string(body), resp.StatusCode)
	}

	return nil
}

// ReportJobError reports a job execution error to the platform
func (c *OutboundClient) ReportJobError(jobID uuid.UUID, errorMsg string) error {
	result := &models.JobResult{
		JobID:       jobID,
		Success:     false,
		Error:       errorMsg,
		CompletedAt: time.Now(),
	}
	return c.SubmitResult(result)
}

// SendHeartbeat sends a heartbeat to the platform
func (c *OutboundClient) SendHeartbeat() error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/heartbeat", c.baseURL, c.agentID.String())

	// The agent's own address, and the rest of its bound addresses. Only the
	// agent can know these: by the time a request reaches the platform, NAT and
	// ingress have rewritten the connection source to a proxy or node address.
	// Resolved once so the primary flagged in interfaces matches ip_address.
	primaryIP := sharednetwork.PrimarySourceIPv4(c.baseURL)

	reqBody := map[string]interface{}{
		"status":    "active",
		"timestamp": time.Now(),
		// The binary's stamped version rides every heartbeat so an in-place
		// binary swap is reflected without re-enrollment (registration-only
		// recording left upgraded agents reporting their old version forever).
		"version":    c.agentVersion,
		"ip_address": primaryIP,
		"interfaces": sharednetwork.HostAddresses(primaryIP),
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed: %s (status: %d)", string(body), resp.StatusCode)
	}

	return nil
}

// registrationPlatform returns OS for device_agents.platform (linux, windows, darwin, etc.).
func registrationPlatform() string {
	return runtime.GOOS
}
