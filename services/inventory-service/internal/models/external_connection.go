package models

import (
	"time"

	"github.com/google/uuid"
)

// ExternalConnection is a deduplicated row in the external_connections table.
// One row per (tenant_id, source_ip, dest_ip, dest_port, protocol) tuple;
// updated in-place on repeat observations.
type ExternalConnection struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// Source (internal host that initiated the connection)
	SourceIP       string     `json:"source_ip" db:"source_ip"`
	SourceHostname *string    `json:"source_hostname,omitempty" db:"source_hostname"`
	SourceAssetID  *uuid.UUID `json:"source_asset_id,omitempty" db:"source_asset_id"`

	// Destination (3rd party / public internet endpoint)
	DestIP       string  `json:"dest_ip" db:"dest_ip"`
	DestHostname *string `json:"dest_hostname,omitempty" db:"dest_hostname"`
	DestPort     int     `json:"dest_port" db:"dest_port"`

	// Observed connection crypto details
	Protocol             string  `json:"protocol" db:"protocol"`
	ProtocolVersion      *string `json:"protocol_version,omitempty" db:"protocol_version"`
	CipherSuite          *string `json:"cipher_suite,omitempty" db:"cipher_suite"`
	KeyExchangeAlgorithm *string `json:"key_exchange_algorithm,omitempty" db:"key_exchange_algorithm"`
	KeySize              *int    `json:"key_size,omitempty" db:"key_size"`

	// Enumerated TLS versions the server accepts (from active probing)
	SupportedTLSVersions []string `json:"supported_tls_versions,omitempty" db:"supported_tls_versions"`

	// Pre-computed assessment
	CryptoStrength string   `json:"crypto_strength" db:"crypto_strength"` // good | weak | unknown
	IsPQCResistant bool     `json:"is_pqc_resistant" db:"is_pqc_resistant"`
	WeakReasons    []string `json:"weak_reasons,omitempty" db:"weak_reasons"`

	// Certificate snapshot (leaf cert)
	CertSubject            *string    `json:"cert_subject,omitempty" db:"cert_subject"`
	CertIssuer             *string    `json:"cert_issuer,omitempty" db:"cert_issuer"`
	CertSAN                []string   `json:"cert_san,omitempty" db:"cert_san"`
	CertNotBefore          *time.Time `json:"cert_not_before,omitempty" db:"cert_not_before"`
	CertNotAfter           *time.Time `json:"cert_not_after,omitempty" db:"cert_not_after"`
	CertFingerprintSHA256  *string    `json:"cert_fingerprint_sha256,omitempty" db:"cert_fingerprint_sha256"`
	CertPublicKeyAlgorithm *string    `json:"cert_public_key_algorithm,omitempty" db:"cert_public_key_algorithm"`
	CertPublicKeySize      *int       `json:"cert_public_key_size,omitempty" db:"cert_public_key_size"`
	CertSignatureAlgorithm *string    `json:"cert_signature_algorithm,omitempty" db:"cert_signature_algorithm"`
	CertIsExpired          bool       `json:"cert_is_expired" db:"cert_is_expired"`
	CertValidationStatus   *string    `json:"cert_validation_status,omitempty" db:"cert_validation_status"`
	CertPEM                *string    `json:"cert_pem,omitempty" db:"cert_pem"`

	// Service identification
	ServiceName                 *string `json:"service_name,omitempty" db:"service_name"`
	ServiceVersion              *string `json:"service_version,omitempty" db:"service_version"`
	ServiceConfidence           *string `json:"service_confidence,omitempty" db:"service_confidence"`
	ServiceIdentificationMethod *string `json:"service_identification_method,omitempty" db:"service_identification_method"`

	// Observation tracking
	FirstSeenAt      time.Time  `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at" db:"last_seen_at"`
	ObservationCount int64      `json:"observation_count" db:"observation_count"`
	SensorID         *uuid.UUID `json:"sensor_id,omitempty" db:"sensor_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Elevation: non-nil once a tenant promoted this 3rd-party connection
	// to a managed/monitored asset. Drives the "Elevated" badge in the lens.
	ElevatedAssetID *uuid.UUID `json:"elevated_asset_id,omitempty" db:"elevated_asset_id"`
}

// ExternalConnectionHistory is one row in the external_connection_history table.
// Written only when meaningful crypto state changes on upsert.
type ExternalConnectionHistory struct {
	ID                   uuid.UUID `json:"id" db:"id"`
	ExternalConnectionID uuid.UUID `json:"external_connection_id" db:"external_connection_id"`
	TenantID             uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// first_seen | cert_rotated | cipher_changed | protocol_upgraded | protocol_downgraded | crypto_strength_changed
	ChangeType string `json:"change_type" db:"change_type"`

	// Previous state snapshot (nil on first_seen)
	PreviousProtocolVersion       *string    `json:"previous_protocol_version,omitempty" db:"previous_protocol_version"`
	PreviousCipherSuite           *string    `json:"previous_cipher_suite,omitempty" db:"previous_cipher_suite"`
	PreviousCryptoStrength        *string    `json:"previous_crypto_strength,omitempty" db:"previous_crypto_strength"`
	PreviousIsPQCResistant        *bool      `json:"previous_is_pqc_resistant,omitempty" db:"previous_is_pqc_resistant"`
	PreviousCertFingerprintSHA256 *string    `json:"previous_cert_fingerprint_sha256,omitempty" db:"previous_cert_fingerprint_sha256"`
	PreviousCertNotAfter          *time.Time `json:"previous_cert_not_after,omitempty" db:"previous_cert_not_after"`

	// New state snapshot
	NewProtocolVersion       *string    `json:"new_protocol_version,omitempty" db:"new_protocol_version"`
	NewCipherSuite           *string    `json:"new_cipher_suite,omitempty" db:"new_cipher_suite"`
	NewCryptoStrength        *string    `json:"new_crypto_strength,omitempty" db:"new_crypto_strength"`
	NewIsPQCResistant        *bool      `json:"new_is_pqc_resistant,omitempty" db:"new_is_pqc_resistant"`
	NewCertFingerprintSHA256 *string    `json:"new_cert_fingerprint_sha256,omitempty" db:"new_cert_fingerprint_sha256"`
	NewCertNotAfter          *time.Time `json:"new_cert_not_after,omitempty" db:"new_cert_not_after"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ExternalConnectionUpsert is the write payload accepted by POST /external-connections.
type ExternalConnectionUpsert struct {
	SourceIP             string     `json:"source_ip"`
	SourceHostname       *string    `json:"source_hostname,omitempty"`
	DestIP               string     `json:"dest_ip"`
	DestHostname         *string    `json:"dest_hostname,omitempty"`
	DestPort             int        `json:"dest_port"`
	Protocol             string     `json:"protocol"`
	ProtocolVersion      *string    `json:"protocol_version,omitempty"`
	CipherSuite          *string    `json:"cipher_suite,omitempty"`
	KeyExchangeAlgorithm *string    `json:"key_exchange_algorithm,omitempty"`
	KeySize              *int       `json:"key_size,omitempty"`
	SupportedTLSVersions []string   `json:"supported_tls_versions,omitempty"`
	SensorID             *uuid.UUID `json:"sensor_id,omitempty"`

	CertSubject            *string    `json:"cert_subject,omitempty"`
	CertIssuer             *string    `json:"cert_issuer,omitempty"`
	CertSAN                []string   `json:"cert_san,omitempty"`
	CertNotBefore          *time.Time `json:"cert_not_before,omitempty"`
	CertNotAfter           *time.Time `json:"cert_not_after,omitempty"`
	CertFingerprintSHA256  *string    `json:"cert_fingerprint_sha256,omitempty"`
	CertPublicKeyAlgorithm *string    `json:"cert_public_key_algorithm,omitempty"`
	CertPublicKeySize      *int       `json:"cert_public_key_size,omitempty"`
	CertSignatureAlgorithm *string    `json:"cert_signature_algorithm,omitempty"`
	CertValidationStatus   *string    `json:"cert_validation_status,omitempty"`
	CertPEM                *string    `json:"cert_pem,omitempty"`

	// Sensor-level certificate quality flags
	CertHasSCT        *bool   `json:"cert_has_sct,omitempty"`
	CertKnownBadCA    *string `json:"cert_known_bad_ca,omitempty"`
	CertNoSubject     bool    `json:"cert_no_subject,omitempty"`
	CertNoCommonName  bool    `json:"cert_no_common_name,omitempty"`
	CertIsEV          bool    `json:"cert_is_ev,omitempty"`
	CertLargeSANCount *int    `json:"cert_large_san_count,omitempty"`
	OCSPStatus        *string `json:"ocsp_status,omitempty"`
}

// ExternalConnectionFilters are the query parameters for listing external connections.
type ExternalConnectionFilters struct {
	Search         string `form:"search"`          // ILIKE on dest_hostname and dest_ip
	CryptoStrength string `form:"crypto_strength"` // good | weak | unknown
	IsPQCResistant *bool  `form:"is_pqc_resistant"`
	CertExpired    *bool  `form:"cert_expired"`
	// CertTrustIssue when true: cert_validation_status is set and not "valid" (self-signed, hostname mismatch, untrusted CA, etc.)
	CertTrustIssue *bool      `form:"cert_trust_issue"`
	HasLegacyTLS   *bool      `form:"has_legacy_tls"` // true = supported_tls_versions contains TLS 1.0/1.1
	SourceAssetID  *uuid.UUID `form:"source_asset_id"`
	Page           int        `form:"page"`
	PageSize       int        `form:"page_size"`
	SortBy         string     `form:"sort_by"`
	SortOrder      string     `form:"sort_order"`
}

// ExternalConnectionsSummary holds aggregate counts for the summary card row.
type ExternalConnectionsSummary struct {
	Total        int `json:"total"`
	WeakCrypto   int `json:"weak_crypto"`
	PQCResistant int `json:"pqc_resistant"`
	ExpiredCerts int `json:"expired_certs"`
	LegacyTLS    int `json:"legacy_tls"`
	// SourceHosts is the number of distinct internal hosts (by source_ip) observed
	// making outbound 3rd-party connections.
	SourceHosts int `json:"source_hosts"`
}
