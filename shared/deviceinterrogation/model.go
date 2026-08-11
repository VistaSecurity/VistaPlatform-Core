// Package deviceinterrogation is the single, shared capability core for
// vendor device interrogation. Both runtimes that interrogate customer devices
// — the standalone Interrogation Agent (device-agent, shipped to customer
// networks) and the in-cluster multi-tenant platform agent
// (device-interrogation-service) — consume this package so there is exactly
// one implementation of "how do I talk to a FortiGate / Cisco / PAN-OS / F5 /
// UniFi / database and extract its cryptographic posture."
//
// The two runtimes differ ONLY in their wrappers: how credentials arrive
// (locally-decrypted on the agent vs. a multi-tenant credential store in the
// service) and how results are delivered (POST-home over HMAC vs. in-cluster
// discovery findings). Every capability — vendor clients, certificate/cipher
// parsing, the SNMP/TLS/HTTP probers, and database interrogation — lives here.
//
// This package MUST stay free of any dependency on either consumer module and
// free of CGO, so it can be vendored into the standalone agent binary as
// easily as it is imported by the in-cluster service.
package deviceinterrogation

import (
	"context"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// CertificateInfo is the canonical extracted-certificate shape, re-exported
// from shared/certificates so callers of this package have a single import.
type CertificateInfo = certificates.CertificateInfo

// DeviceInfo carries the addressing/identity a vendor client needs to reach a
// device. Wrappers populate it from their own device records.
type DeviceInfo struct {
	DeviceType    string
	Hostname      string
	IPAddress     string
	ManagementURL string
	// Port is the management/SSH port when it differs from the vendor default
	// (0 means "use the vendor default").
	Port int
	// SiteID is vendor-specific (e.g. UniFi controller site).
	SiteID   string
	Metadata map[string]interface{}
}

// Credentials are decrypted, in-memory-only device credentials. Wrappers are
// responsible for decrypting before constructing this and for clearing it
// after use.
type Credentials struct {
	Username string
	Password string
	APIKey   string
	Token    string
	// InsecureSkipVerify, when true, disables TLS verification of the device's
	// management endpoint. Defaults to false (verify). Operators opt in
	// per-device for self-signed appliance management certs.
	InsecureSkipVerify bool
	// Custom holds any additional credential fields a vendor needs.
	Custom map[string]interface{}
}

// CryptoAsset is the superset cryptographic asset emitted by every
// interrogator. Optional crypto fields are pointers so an interrogator can
// leave a value genuinely unknown rather than fabricating a default.
type CryptoAsset struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	AssetType string `json:"asset_type,omitempty"` // server, appliance, firewall, load_balancer, vpn_gateway, database, etc.

	ProtocolVersion  *string  `json:"protocol_version,omitempty"`
	CipherSuite      *string  `json:"cipher_suite,omitempty"`
	SupportedCiphers []string `json:"supported_ciphers,omitempty"`
	KeySize          *int     `json:"key_size,omitempty"`
	KeyExchangeAlg   *string  `json:"key_exchange_algorithm,omitempty"`
	HashAlgorithm    *string  `json:"hash_algorithm,omitempty"`
	TLSVersions      []string `json:"tls_versions,omitempty"`

	// Certificate is the leaf certificate (backward-compat convenience);
	// Certificates is the full chain (index 0 = leaf, then intermediates).
	Certificate  *CertificateInfo  `json:"certificate,omitempty"`
	Certificates []CertificateInfo `json:"certificates,omitempty"`

	CertValidationStatus string `json:"cert_validation_status,omitempty"`
	CertValidationError  string `json:"cert_validation_error,omitempty"`

	SSHInfo      *SSHInfo      `json:"ssh_info,omitempty"`
	ServiceHints *ServiceHints `json:"service_hints,omitempty"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// SSHInfo captures SSH protocol negotiation details.
type SSHInfo struct {
	Banner               string   `json:"banner,omitempty"`
	KeyTypes             []string `json:"key_types,omitempty"`
	HostKeyType          string   `json:"host_key_type,omitempty"`
	HostKeyFingerprint   string   `json:"host_key_fingerprint,omitempty"`
	KexAlgorithm         string   `json:"kex_algorithm,omitempty"`
	EncryptionAlgC2S     string   `json:"encryption_alg_c2s,omitempty"`
	EncryptionAlgS2C     string   `json:"encryption_alg_s2c,omitempty"`
	MACAlgC2S            string   `json:"mac_alg_c2s,omitempty"`
	MACAlgS2C            string   `json:"mac_alg_s2c,omitempty"`
	CompressionAlgorithm string   `json:"compression_alg,omitempty"`
}

// ServiceHints holds an identified service name/version for inventory enrichment.
type ServiceHints struct {
	ServiceName          string `json:"service_name,omitempty"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence,omitempty"`
	IdentificationMethod string `json:"identification_method,omitempty"`
}

// DeviceIdentity captures hardware/software identity of the interrogated device.
type DeviceIdentity struct {
	Vendor          string `json:"vendor,omitempty"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	SerialNumber    string `json:"serial_number,omitempty"`
	OSVersion       string `json:"os_version,omitempty"`
}

// InterrogateResult is the raw output of a single interrogation. Wrappers map
// Assets onto their own downstream asset/finding model.
type InterrogateResult struct {
	Assets []CryptoAsset `json:"assets"`
	// DeviceInfo is freeform vendor system info (version/model/serial, raw
	// certificate dumps, etc.).
	DeviceInfo map[string]interface{} `json:"device_info"`
	// DeviceIdentity, when populated, is the structured device identity shared
	// across every asset from this interrogation.
	DeviceIdentity *DeviceIdentity `json:"device_identity,omitempty"`
}

// DeviceInterrogator is implemented by every vendor/protocol client.
type DeviceInterrogator interface {
	// Interrogate connects to the device and returns its discovered crypto assets.
	Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error)
	// SupportedDeviceTypes returns the device_type strings this interrogator handles.
	SupportedDeviceTypes() []string
}

// strPtr / intPtr are small helpers for populating the optional pointer fields.
func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
