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
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/certificates"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	// Aliased: the sensor has its own `certificates` package, imported above.
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
)

// SensorManagerClient handles communication with the sensor manager service
type SensorManagerClient struct {
	config     *config.Config
	httpClient *http.Client
	baseURL    string
}

// NewSensorManagerClient creates a new sensor manager client
func NewSensorManagerClient(cfg *config.Config) *SensorManagerClient {
	// Configure HTTP client with TLS if configured
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Server anchor and client identity are configured independently. This is
	// the client that performs registration, so it is the one that most needs a
	// pinned ServerCACert to apply WITHOUT a client cert — at this point the
	// sensor has none, and registration is what issues it. See the note on
	// buildTLSTransport in outbound_client.go.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	configured := false

	if cfg.Security.ServerCACert != "" {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM([]byte(cfg.Security.ServerCACert)) {
			tlsConfig.RootCAs = caPool
			configured = true
		} else {
			fmt.Printf("Warning: Failed to parse server CA certificate\n")
		}
	}

	if cfg.Security.UseTLS && cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		// Load client certificate from PEM strings (not files)
		cert, err := tls.X509KeyPair([]byte(cfg.Security.ClientCert), []byte(cfg.Security.ClientKey))
		if err != nil {
			fmt.Printf("Warning: Failed to load client certificate: %v\n", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
			configured = true
		}
	}

	if configured {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return &SensorManagerClient{
		config:     cfg,
		httpClient: httpClient,
		baseURL:    cfg.ControlPlaneURL,
	}
}

// Register registers the sensor with the control plane using CSR-based flow
func (c *SensorManagerClient) Register() (*models.SensorConfig, error) {
	// Generate sensor ID (UUID) that will be used as certificate CN
	// The sensor "claims" its ID, and the platform will use it
	sensorID := uuid.New()
	if c.config.SensorID != "" {
		// If sensor ID already exists (from previous registration), use it
		var err error
		sensorID, err = uuid.Parse(c.config.SensorID)
		if err != nil {
			// Invalid existing ID, generate new one
			sensorID = uuid.New()
		}
	}

	// Generate keypair and CSR locally (private key never leaves sensor)
	csrGen := certificates.NewCSRGenerator()
	privateKey, err := csrGen.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	csrPEM, err := csrGen.GenerateCSR(sensorID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %v", err)
	}

	// Store private key securely (will be saved to config file)
	privateKeyPEM, err := csrGen.EncodePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %v", err)
	}

	// Registration request with CSR
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
		CSR:                 csrPEM,            // Include CSR in registration request
		SensorID:            sensorID.String(), // Proposed sensor ID
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var registrationResp struct {
		SensorID             string              `json:"sensor_id"`
		ClientCert           string              `json:"client_cert"`       // Signed certificate (no private key)
		ServerCACert         string              `json:"server_ca_cert"`    // CA certificate for trust
		ControlPlaneURL      string              `json:"control_plane_url"` // mTLS passthrough URL to switch to (#1033)
		CertificateExpiresAt string              `json:"certificate_expires_at"`
		ReportingInterval    int                 `json:"reporting_interval"` // Top-level field from server
		Features             map[string]bool     `json:"features"`           // Top-level field from server
		Config               models.SensorConfig `json:"config"`             // For backward compatibility
	}

	if err := json.NewDecoder(resp.Body).Decode(&registrationResp); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %v", err)
	}

	// Update sensor ID in config
	c.config.SensorID = registrationResp.SensorID

	// Store certificate (signed by platform)
	if registrationResp.ClientCert != "" {
		c.config.Security.ClientCert = registrationResp.ClientCert
	}

	// Store private key locally (never sent to platform)
	c.config.Security.ClientKey = privateKeyPEM

	// ADD the platform's CA to the trust pool; do not replace what is there.
	// This is the live registration path (cmd/main.go calls
	// SensorManagerClient.Register, not OutboundClient.Register). Replacing
	// dropped the operator-approved edge anchor, so registration succeeded and
	// every subsequent handshake failed when agentMtls is off (the chart default).
	if registrationResp.ServerCACert != "" {
		c.config.Security.ServerCACert = sharedcerts.MergeCAPEMs(
			c.config.Security.ServerCACert, registrationResp.ServerCACert)
	}

	// Switch to the advertised mTLS passthrough endpoint. The
	// OutboundClient picks the new URL up in ActivateMTLS (main.register calls
	// it right after this returns), and saveConfigFile persists it.
	if applyAdvertisedControlPlaneURL(c.config, registrationResp.ControlPlaneURL) {
		c.baseURL = c.config.ControlPlaneURL
	}
	if c.config.Security.ClientCert != "" && c.config.Security.ClientKey != "" {
		c.config.Security.UseTLS = true
	}
	if err := c.reconfigureTLS(); err != nil {
		// Log and continue — deliberately NOT fatal. This runs after the
		// platform has consumed the single-use registration key but before
		// saveCertificates/saveConfigFile, so returning an error here discards a
		// freshly issued certificate permanently and re-registration is refused
		// with "Registration key has already been used". A CA PEM that fails
		// AppendCertsFromPEM is only a warning in buildTLSTransport but a hard
		// error here, so that is a reachable path, not a theoretical one.
		//
		// A client left on its previous transport can still be rotated; a
		// sensor that threw away its enrollment cannot be recovered without
		// operator intervention. This matches OutboundClient.ActivateMTLS,
		// which is no-op-on-failure for the same reason.
		log.Printf("⚠️  sensor-manager client: TLS reconfigure after registration failed (%v); continuing on the existing transport — certificate rotation will retry", err)
	}

	// Build config from top-level fields (server returns these at top level, not nested)
	config := registrationResp.Config
	if registrationResp.ReportingInterval > 0 {
		config.ReportingInterval = registrationResp.ReportingInterval
	}
	if registrationResp.Features != nil {
		config.Features = registrationResp.Features
		// Sync CaptureConfig from features so updateConfig() applies the correct
		// active probing setting from the deployment profile at startup.
		if ap, ok := registrationResp.Features["active_probing"]; ok {
			config.CaptureConfig.ActiveProbing = ap
		}
		if nd, ok := registrationResp.Features["network_discovery"]; ok {
			config.CaptureConfig.NetworkDiscovery = nd
		}
	}

	return &config, nil
}

func (c *SensorManagerClient) getRegistrationIPAddress() string {
	if ip := c.config.Network.IPAddress; ip != "" {
		return ip
	}
	return "127.0.0.1"
}

// SubmitDiscoveries submits a batch of discoveries to the control plane
func (c *SensorManagerClient) SubmitDiscoveries(discoveries []*models.CryptoDiscovery) error {
	if len(discoveries) == 0 {
		return nil
	}

	batch := models.DiscoveryBatch{
		SensorID:    c.config.SensorID,
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ReportHealth reports sensor health to the control plane
func (c *SensorManagerClient) ReportHealth(health *models.SensorHealth) error {
	jsonData, err := json.Marshal(health)
	if err != nil {
		return fmt.Errorf("failed to marshal health: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/health", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send health report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health report failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetConfig retrieves sensor configuration from the control plane
func (c *SensorManagerClient) GetConfig() (*models.SensorConfig, error) {
	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/config", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %v", err)
	}
	defer resp.Body.Close()

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

// Helper function to generate batch ID
