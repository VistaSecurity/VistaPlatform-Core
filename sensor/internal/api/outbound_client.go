package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// AvailableInterfaceNames returns the host's non-loopback NIC names. Single
// source of truth for the host interface inventory the sensor reports both at
// registration (SensorRegistration.AvailableInterfaces) and in every heartbeat
// (SensorHealth.AvailableInterfaces).
func AvailableInterfaceNames() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		names = append(names, iface.Name)
	}
	return names
}

// OutboundClient handles outbound-only communication with control plane
type OutboundClient struct {
	config     *config.Config
	httpClient *http.Client
	baseURL    string
	sensorID   string
}

// NewOutboundClient creates a new outbound-only client
func NewOutboundClient(cfg *config.Config) *OutboundClient {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	if transport := buildTLSTransport(cfg); transport != nil {
		httpClient.Transport = transport
	}

	return &OutboundClient{
		config:     cfg,
		httpClient: httpClient,
		baseURL:    cfg.ControlPlaneURL,
		sensorID:   cfg.SensorID,
	}
}

// buildTLSTransport builds the outbound transport from the PEM material in
// cfg.Security. The sensor presents its per-tenant client cert and trusts
// ServerCACert as the SERVER anchor — under fail-closed sensor mTLS
// that is the platform/mesh CA returned at registration, the issuer of the
// passthrough listener's server cert. Returns nil when neither is configured
// (plain HTTP / dev), so the caller leaves the default transport in place.
//
// The two halves are configured INDEPENDENTLY. A pinned ServerCACert must take
// effect even before the sensor holds a client certificate, because
// registration — the very call that obtains that certificate — is itself an
// HTTPS request that has to verify the platform. Gating the whole transport on
// already having a client cert made the pinned CA unreachable at exactly the
// moment it was needed: against a platform whose edge cert is signed by a CA
// the host doesn't know, registration failed x509 verification, so no client
// cert was ever issued, so the CA was never applied. Trust bootstrap
// (--ca-fingerprint / the interactive prompt) depends on this ordering.
func buildTLSTransport(cfg *config.Config) *http.Transport {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	configured := false

	// Server anchor — applies with or without a client cert.
	if cfg.Security.ServerCACert != "" {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM([]byte(cfg.Security.ServerCACert)) {
			tlsConfig.RootCAs = caPool
			configured = true
		} else {
			fmt.Printf("Warning: failed to parse sensor server CA certificate\n")
		}
	}

	// Client identity — only once registration has issued one.
	if cfg.Security.UseTLS && cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		// Certs are PEM content (as returned by registration), not file paths.
		cert, err := tls.X509KeyPair([]byte(cfg.Security.ClientCert), []byte(cfg.Security.ClientKey))
		if err != nil {
			fmt.Printf("Warning: failed to load sensor client certificate: %v\n", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
			configured = true
		}
	}

	if !configured {
		return nil
	}
	return &http.Transport{TLSClientConfig: tlsConfig}
}

// reconfigureTLS rebuilds the HTTP transport from the current cfg.Security.
// Called after registration stores fresh certs so subsequent outbound calls
// (heartbeat, command poll, discovery submit) use mTLS.
func (c *OutboundClient) reconfigureTLS() {
	if transport := buildTLSTransport(c.config); transport != nil {
		c.httpClient.Transport = transport
	}
}

// ActivateMTLS enables mTLS on this client's outbound transport from the cert
// material currently in cfg.Security, then rebuilds the transport.
//
// The sensor registers through SensorManagerClient, which stores the client
// cert/key + server CA on the shared *config.Config but does NOT touch this
// (the OutboundClient) transport — this client was constructed before
// registration with UseTLS still false, so its transport is plain HTTP. Without
// this call the first post-registration session submits heartbeats/discoveries
// over plain HTTP even though a valid client cert is held; under fail-closed
// sensor mTLS the platform then rejects every call with 401 until the
// sensor restarts and loads the certs from disk. main.register() calls this
// right after a successful registration so the outbound path presents the client
// cert immediately (mirrors OutboundClient.Register and device-agent's
// reconfigureTLS-after-register). Idempotent; a no-op when no cert is present.
func (c *OutboundClient) ActivateMTLS() {
	if c.config.Security.ClientCert != "" && c.config.Security.ClientKey != "" {
		c.config.Security.UseTLS = true
	}
	// Re-sync the base URL from the shared config: registration (and cert
	// rotation) may have switched it to the advertised mTLS passthrough
	// endpoint, and this client captured the pre-registration URL at
	// construction time.
	if c.config.ControlPlaneURL != "" {
		c.baseURL = c.config.ControlPlaneURL
	}
	c.reconfigureTLS()
}

// Register registers the sensor with the control plane (outbound only)
func (c *OutboundClient) Register() (*models.SensorConfig, error) {
	registration := models.SensorRegistration{
		RegistrationKey:     c.config.RegistrationKey,
		Name:                c.config.Name,
		Description:         c.config.Description,
		Platform:            c.config.Platform,
		Version:             c.config.Version,
		Profile:             c.config.Profile,
		NetworkInterfaces:   c.config.Capture.Interfaces,
		AvailableInterfaces: AvailableInterfaceNames(),
		IPAddress:           c.getRegistrationIPAddress(),
		ReportingInterval:   int(c.config.ReportingInterval.Seconds()), // report the install-configured cadence
	}

	jsonData, err := json.Marshal(registration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/register", c.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send registration request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var registrationResp struct {
		SensorID        string              `json:"sensor_id"`
		ClientCert      string              `json:"client_cert"`
		ClientKey       string              `json:"client_key"`
		ServerCACert    string              `json:"server_ca_cert"`
		ControlPlaneURL string              `json:"control_plane_url"` // mTLS passthrough URL to switch to (#1033)
		Config          models.SensorConfig `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&registrationResp); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %v", err)
	}

	// Update sensor ID in config
	c.sensorID = registrationResp.SensorID
	c.config.SensorID = registrationResp.SensorID

	// Update security config if certificates were provided
	if registrationResp.ClientCert != "" {
		c.config.Security.ClientCert = registrationResp.ClientCert
	}
	if registrationResp.ClientKey != "" {
		c.config.Security.ClientKey = registrationResp.ClientKey
	}
	// ADD the platform's CA to the trust pool; do not replace what is there.
	// The anchor already in Security.ServerCACert is the one the operator
	// approved at setup and is what verifies the ordinary edge endpoint. The CA
	// arriving here issues the mTLS passthrough listener's certificate, which
	// this sensor only talks to when the platform advertises it below — and it
	// does not when agentMtls is disabled, which is the chart default.
	// Overwriting therefore left the sensor on the edge endpoint trusting a CA
	// that never signed it, so registration succeeded and every call after it
	// failed the handshake.
	if registrationResp.ServerCACert != "" {
		c.config.Security.ServerCACert = certificates.MergeCAPEMs(
			c.config.Security.ServerCACert, registrationResp.ServerCACert)
	}

	// Switch to the advertised mTLS passthrough endpoint before
	// activating mTLS, so subsequent calls both present the client cert AND
	// reach the listener that can receive it.
	if applyAdvertisedControlPlaneURL(c.config, registrationResp.ControlPlaneURL) {
		c.baseURL = c.config.ControlPlaneURL
	}

	// Activate mTLS for subsequent outbound calls now that we hold a client
	// cert (presented to the server) and the server CA (used to verify the
	// platform's passthrough listener cert under fail-closed mTLS).
	if c.config.Security.ClientCert != "" && c.config.Security.ClientKey != "" {
		c.config.Security.UseTLS = true
	}
	c.reconfigureTLS()

	return &registrationResp.Config, nil
}

// GetSensorID returns the sensor ID (set during registration)
func (c *OutboundClient) GetSensorID() string {
	return c.sensorID
}

// getRegistrationIPAddress reports this host's address at enrollment. It returns
// "" when the address cannot be determined — the platform records that as
// "unknown". It used to return the literal "127.0.0.1" to satisfy a required
// field, which stated something false about the host and, once the platform
// began trusting the self-reported value, would have pinned the sensor to
// loopback forever.
func (c *OutboundClient) getRegistrationIPAddress() string {
	return c.config.CurrentIPAddress()
}

// Heartbeat sends a heartbeat and receives commands (outbound only)
func (c *OutboundClient) Heartbeat(health *models.SensorHealth) (*models.SensorCommands, error) {
	jsonData, err := json.Marshal(health)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal health: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/heartbeat", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send heartbeat: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("heartbeat failed with status %d: %s", resp.StatusCode, string(body))
	}

	var commands models.SensorCommands
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		return nil, fmt.Errorf("failed to decode commands: %v", err)
	}

	return &commands, nil
}

// SubmitDiscoveries submits discoveries (outbound only)
func (c *OutboundClient) SubmitDiscoveries(discoveries []*models.CryptoDiscovery) error {
	if len(discoveries) == 0 {
		return nil
	}

	batch := models.DiscoveryBatch{
		SensorID:    c.config.SensorID, // Use config.SensorID which is updated after registration
		Discoveries: make([]models.CryptoDiscovery, len(discoveries)),
		BatchID:     generateBatchID(),
		Timestamp:   time.Now(),
		Count:       len(discoveries),
	}

	// Convert pointers to values
	for i, discovery := range discoveries {
		batch.Discoveries[i] = *discovery
	}

	jsonData, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal discoveries: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/discoveries", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send discoveries: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// PollForCommands polls for commands from control plane (outbound only)
func (c *OutboundClient) PollForCommands() (*models.SensorCommands, error) {
	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/commands", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to poll commands: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("poll failed with status %d: %s", resp.StatusCode, string(body))
	}

	var commands models.SensorCommands
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		return nil, fmt.Errorf("failed to decode commands: %v", err)
	}

	return &commands, nil
}

// SubmitDiscoveryJobResults submits discovery job results to control plane
func (c *OutboundClient) SubmitDiscoveryJobResults(response *models.DiscoveryJobResponse) error {
	jsonData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal discovery job response: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/discovery/jobs/%s/results", c.baseURL, response.JobID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit discovery job results: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetConfig retrieves sensor configuration (outbound only)
func (c *OutboundClient) GetConfig() (*models.SensorConfig, error) {
	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/config", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("config request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var config models.SensorConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	return &config, nil
}

// AcknowledgeCommand sends command acknowledgment to control plane (outbound only)
func (c *OutboundClient) AcknowledgeCommand(commandID string, response *models.CommandResponse) error {
	jsonData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal command response: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/commands/%s/ack", c.baseURL, c.config.SensorID, commandID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send acknowledgment: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("acknowledgment failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Helper function to generate batch ID
func generateBatchID() string {
	return uuid.NewString()
}
