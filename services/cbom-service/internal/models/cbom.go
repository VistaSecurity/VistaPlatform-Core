// Package models defines data structures for the report generator service.
package models

import "time"

// CBOMComponentType identifies the kind of cryptographic asset in a CBOM component.
type CBOMComponentType string

const (
	CBOMComponentTypeCertificate CBOMComponentType = "certificate"
	CBOMComponentTypeAlgorithm   CBOMComponentType = "algorithm"
	CBOMComponentTypeProtocol    CBOMComponentType = "protocol"
	CBOMComponentTypeKey         CBOMComponentType = "related-crypto-material"
	CBOMComponentTypeLibrary     CBOMComponentType = "library"
)

// ========================================================================
// Certificate Details (CycloneDX: certificateProperties)
// ========================================================================

// CBOMCertificateState represents a lifecycle state entry per the CycloneDX spec.
type CBOMCertificateState struct {
	// Pre-defined state: "pre-activation", "active", "suspended", "deactivated", "revoked", "destroyed"
	State string `json:"state,omitempty"`
	// Custom state name (when using domain-specific states instead of pre-defined)
	Name string `json:"name,omitempty"`
	// Human-readable description (for custom states)
	Description string `json:"description,omitempty"`
	// Reason for the state (e.g., "key compromise detected")
	Reason string `json:"reason,omitempty"`
}

// CBOMCertificateExtension represents a certificate extension (common or custom).
type CBOMCertificateExtension struct {
	// "common" or "custom"
	Type string `json:"type"`
	// Extension name: "basicConstraints", "keyUsage", etc. (common) or custom name
	Name string `json:"name"`
	// Extension value
	Value string `json:"value"`
	// Whether the extension is marked critical
	IsCritical bool `json:"is_critical,omitempty"`
	// ASN.1 OID if applicable
	OID string `json:"oid,omitempty"`
}

// CBOMRelatedCryptoAssetRef links a certificate to its related crypto assets.
type CBOMRelatedCryptoAssetRef struct {
	Type string `json:"type"` // "algorithm", "publicKey", "privateKey"
	Ref  string `json:"ref"`  // bom-ref of the related asset
}

// CBOMCertificateDetails holds X.509 certificate-specific fields aligned with CycloneDX.
type CBOMCertificateDetails struct {
	SerialNumber       string    `json:"serial_number,omitempty"`
	SubjectName        string    `json:"subject_name"` // CycloneDX: subjectName (was SubjectDN)
	IssuerName         string    `json:"issuer_name"`  // CycloneDX: issuerName (was IssuerDN)
	CommonName         string    `json:"common_name,omitempty"`
	SANs               []string  `json:"sans,omitempty"`
	NotValidBefore     time.Time `json:"not_valid_before,omitempty"`    // CycloneDX: notValidBefore
	NotValidAfter      time.Time `json:"not_valid_after,omitempty"`     // CycloneDX: notValidAfter
	FingerprintAlg     string    `json:"fingerprint_alg,omitempty"`     // CycloneDX: fingerprint.alg ("SHA-256")
	FingerprintContent string    `json:"fingerprint_content,omitempty"` // CycloneDX: fingerprint.content
	FingerprintSHA1    string    `json:"fingerprint_sha1,omitempty"`

	// Key and signature info
	KeyAlgorithm       string `json:"key_algorithm,omitempty"`
	KeySize            int    `json:"key_size,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	SignatureAlgOID    string `json:"signature_algorithm_oid,omitempty"`
	PublicKeyAlgOID    string `json:"public_key_algorithm_oid,omitempty"`

	// Certificate properties
	CertificateFormat string `json:"certificate_format,omitempty"` // "X.509", "PGP", "PKCS#7"
	IsSelfSigned      bool   `json:"is_self_signed"`
	IsCA              bool   `json:"is_ca"`
	DataSource        string `json:"data_source,omitempty"`

	// CycloneDX lifecycle states (array — a cert can have multiple state entries)
	CertificateStates []CBOMCertificateState `json:"certificate_states,omitempty"`

	// Lifecycle timestamps
	CreationDate     *time.Time `json:"creation_date,omitempty"`
	ActivationDate   *time.Time `json:"activation_date,omitempty"`
	DeactivationDate *time.Time `json:"deactivation_date,omitempty"`
	RevocationDate   *time.Time `json:"revocation_date,omitempty"`
	DestructionDate  *time.Time `json:"destruction_date,omitempty"`

	// Certificate extensions (CycloneDX: certificateExtensions)
	Extensions []CBOMCertificateExtension `json:"extensions,omitempty"`

	// Related cryptographic assets (signing algorithm, public key)
	RelatedCryptoAssets []CBOMRelatedCryptoAssetRef `json:"related_crypto_assets,omitempty"`
}

// IsExpired returns true when the certificate validity period has ended.
func (c *CBOMCertificateDetails) IsExpired() bool {
	return !c.NotValidAfter.IsZero() && time.Now().After(c.NotValidAfter)
}

// DaysUntilExpiry returns the number of days until (or since, if negative) expiration.
func (c *CBOMCertificateDetails) DaysUntilExpiry() int {
	if c.NotValidAfter.IsZero() {
		return 0
	}
	return int(time.Until(c.NotValidAfter).Hours() / 24)
}

// ========================================================================
// Algorithm Details (CycloneDX: algorithmProperties)
// ========================================================================

// CBOMAlgorithmDetails holds algorithm-specific fields aligned with CycloneDX.
type CBOMAlgorithmDetails struct {
	// Identity (CycloneDX algorithmProperties)
	Code                     string   `json:"code"`
	AlgorithmFamily          string   `json:"algorithm_family,omitempty"`            // "AES", "RSA", "ML-KEM", "ECDH"
	Primitive                string   `json:"primitive,omitempty"`                   // "ae", "signature", "hash", "kem", "key-agree", etc.
	Mode                     string   `json:"mode,omitempty"`                        // "gcm", "cbc", "ctr", etc.
	Padding                  string   `json:"padding,omitempty"`                     // "pkcs1v15", "oaep", "pss"
	ParameterSetIdentifier   string   `json:"parameter_set_identifier,omitempty"`    // Key/block size variant
	Curve                    string   `json:"curve,omitempty"`                       // "secp256r1", "x25519", "ed25519"
	OID                      string   `json:"oid,omitempty"`                         // ASN.1 Object Identifier
	CryptoFunctions          []string `json:"crypto_functions,omitempty"`            // ["keygen","encrypt","decrypt","sign","verify"]
	ClassicalSecurityLevel   int      `json:"classical_security_level,omitempty"`    // Bits of classical security
	NistQuantumSecurityLevel int      `json:"nist_quantum_security_level,omitempty"` // NIST PQC level 0-5

	// Assessment (VistaPlatform-specific enrichment)
	Role                     string   `json:"role,omitempty"`
	Category                 string   `json:"category"`
	Strength                 string   `json:"strength,omitempty"`           // weak/acceptable/strong/recommended
	DeprecationStatus        string   `json:"deprecation_status,omitempty"` // current/deprecated/obsolete
	IsPQC                    bool     `json:"is_pqc"`
	PQCStandardizationStatus string   `json:"pqc_standardization_status,omitempty"`
	KeySize                  int      `json:"key_size,omitempty"`
	RiskScore                int      `json:"risk_score,omitempty"`
	MigrationGuidance        string   `json:"migration_guidance,omitempty"`
	RecommendedAlternatives  []string `json:"recommended_alternatives,omitempty"`
}

// IsWeak returns true for algorithms with known weaknesses.
func (a *CBOMAlgorithmDetails) IsWeak() bool {
	return a.Strength == "weak"
}

// IsDeprecated returns true when the algorithm is deprecated or obsolete.
func (a *CBOMAlgorithmDetails) IsDeprecated() bool {
	return a.DeprecationStatus == "deprecated" || a.DeprecationStatus == "obsolete"
}

// ========================================================================
// Protocol Details (CycloneDX: protocolProperties)
// ========================================================================

// CBOMCipherSuite represents a structured cipher suite with algorithm references.
type CBOMCipherSuite struct {
	Name        string   `json:"name"`                  // "TLS_AES_256_GCM_SHA384"
	Algorithms  []string `json:"algorithms,omitempty"`  // bom-refs to algorithm components
	Identifiers []string `json:"identifiers,omitempty"` // e.g., ["0x13,0x02"]
}

// CBOMProtocolDetails holds TLS/SSH protocol configuration fields aligned with CycloneDX.
type CBOMProtocolDetails struct {
	// CycloneDX protocolProperties
	Type    string `json:"type"` // "tls", "ssh", "ipsec", "ike", etc.
	Version string `json:"version,omitempty"`

	// Cipher suites — structured per CycloneDX (name + algorithm refs + identifiers)
	CipherSuites []CBOMCipherSuite `json:"cipher_suites,omitempty"`

	// Legacy string array (kept for backward compat during transition)
	CipherSuiteNames []string `json:"cipher_suite_names,omitempty"`

	KeyExchangeAlgorithm string  `json:"key_exchange_algorithm,omitempty"`
	PFSSupport           bool    `json:"pfs_support"`
	TLSCompression       bool    `json:"tls_compression_enabled"`
	ChainValid           bool    `json:"certificate_chain_valid"`
	DiscoveryMethod      string  `json:"discovery_method,omitempty"`
	ConfidenceScore      float64 `json:"confidence_score,omitempty"`

	// CycloneDX OID
	OID string `json:"oid,omitempty"` // e.g., "1.3.6.1.5.5.7.3.1"
}

// ========================================================================
// Key / Related Crypto Material Details (CycloneDX: relatedCryptoMaterialProperties)
// ========================================================================

// CBOMSecuredBy describes how a key is protected.
type CBOMSecuredBy struct {
	Mechanism    string `json:"mechanism"`               // "HSM", "TPM", "Software", "None"
	AlgorithmRef string `json:"algorithm_ref,omitempty"` // bom-ref to protecting algorithm
}

// CBOMKeyDetails holds cryptographic key/material metadata aligned with CycloneDX.
type CBOMKeyDetails struct {
	// CycloneDX relatedCryptoMaterialProperties
	MaterialType string `json:"material_type"` // "private-key", "public-key", "secret-key",
	// "shared-secret", "password", "credential", "token", etc.

	ID    string `json:"id,omitempty"`    // Unique identifier for this material
	State string `json:"state,omitempty"` // NIST SP 800-57: "pre-activation", "active",
	// "suspended", "deactivated", "compromised", "destroyed"
	StateReason string `json:"state_reason,omitempty"` // Reason for current state

	SizeBits     int            `json:"size_bits,omitempty"`
	Curve        string         `json:"curve,omitempty"`
	Format       string         `json:"format,omitempty"`        // "PEM", "PKCS#8", "JWK", "DER"
	AlgorithmRef string         `json:"algorithm_ref,omitempty"` // bom-ref to associated algorithm
	SecuredBy    *CBOMSecuredBy `json:"secured_by,omitempty"`

	// CycloneDX fingerprint
	FingerprintAlg     string `json:"fingerprint_alg,omitempty"`     // "SHA-256"
	FingerprintContent string `json:"fingerprint_content,omitempty"` // hex hash

	// Legacy fields (still useful)
	KeyType           string   `json:"key_type"`
	KeyUsage          []string `json:"key_usage,omitempty"`
	PublicFingerprint string   `json:"public_fingerprint,omitempty"`
	JWKThumbprint     string   `json:"jwk_thumbprint,omitempty"`
	Provenance        string   `json:"provenance,omitempty"`

	// Lifecycle timestamps
	CreatedAt        *time.Time `json:"created_at,omitempty"`
	ActivationDate   *time.Time `json:"activation_date,omitempty"`
	RotatedAt        *time.Time `json:"rotated_at,omitempty"`
	DeactivationDate *time.Time `json:"deactivation_date,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	DestructionDate  *time.Time `json:"destruction_date,omitempty"`

	// Related cryptographic assets
	RelatedCryptoAssets []CBOMRelatedCryptoAssetRef `json:"related_crypto_assets,omitempty"`
}

// ========================================================================
// Library Details (CycloneDX: component type "library")
// ========================================================================

// CBOMLibraryDetails holds crypto library metadata.
type CBOMLibraryDetails struct {
	Name                    string                   `json:"name"`
	Version                 string                   `json:"version"`
	Vendor                  string                   `json:"vendor,omitempty"`
	CPE                     string                   `json:"cpe,omitempty"`
	PURL                    string                   `json:"purl,omitempty"`                // Package URL
	CertificationLevel      []string                 `json:"certification_level,omitempty"` // ["fips140-3-l1"]
	BuildMetadata           map[string]interface{}   `json:"build_metadata,omitempty"`
	KnownVulnerabilityCount int                      `json:"known_vulnerability_count,omitempty"`
	KnownVulnerabilities    []map[string]interface{} `json:"known_vulnerabilities,omitempty"`

	// CycloneDX "provides" — algorithm bom-refs this library implements
	ProvidesAlgorithms []string `json:"provides_algorithms,omitempty"`
}

// ========================================================================
// CBOM Component (wraps all asset types)
// ========================================================================

// CBOMComponent represents a single cryptographic asset in the bill of materials.
type CBOMComponent struct {
	// Unique identifier for this CBOM entry (UUID string).
	ID string `json:"id"`

	// CycloneDX bom-ref (stable, unique reference for cross-linking)
	BOMRef string `json:"bom-ref"`

	// Human-readable name for the component.
	Name string `json:"name"`

	// Type of cryptographic asset.
	Type CBOMComponentType `json:"type"`

	// CycloneDX OID at the component level
	OID string `json:"oid,omitempty"`

	// Asset association
	AssetID     string `json:"asset_id,omitempty"`
	AssetName   string `json:"asset_name,omitempty"`
	AssetType   string `json:"asset_type,omitempty"`
	Environment string `json:"environment,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	RiskLevel   string `json:"risk_level,omitempty"`

	// Type-specific details — only one will be populated per component.
	CertificateDetails *CBOMCertificateDetails `json:"certificate_details,omitempty"`
	AlgorithmDetails   *CBOMAlgorithmDetails   `json:"algorithm_details,omitempty"`
	ProtocolDetails    *CBOMProtocolDetails    `json:"protocol_details,omitempty"`
	KeyDetails         *CBOMKeyDetails         `json:"key_details,omitempty"`
	LibraryDetails     *CBOMLibraryDetails     `json:"library_details,omitempty"`

	// CycloneDX dependency references
	DependsOn []string `json:"depends_on,omitempty"` // bom-refs this component depends on
	Provides  []string `json:"provides,omitempty"`   // bom-refs this component provides/implements

	// Source metadata
	DiscoveredAt time.Time `json:"discovered_at,omitempty"`
	LastVerified time.Time `json:"last_verified,omitempty"`
}

// ========================================================================
// CBOM Summary and Root Document
// ========================================================================

// CBOMSummary aggregates counts across all components.
type CBOMSummary struct {
	TotalComponents  int `json:"total_components"`
	CertificateCount int `json:"certificate_count"`
	AlgorithmCount   int `json:"algorithm_count"`
	ProtocolCount    int `json:"protocol_count"`
	KeyCount         int `json:"key_count"`
	LibraryCount     int `json:"library_count"`

	// Risk indicators
	ExpiredCertificates  int `json:"expired_certificates"`
	ExpiringIn30Days     int `json:"expiring_in_30_days"`
	ExpiringIn90Days     int `json:"expiring_in_90_days"`
	WeakAlgorithms       int `json:"weak_algorithms"`
	DeprecatedAlgorithms int `json:"deprecated_algorithms"`
	PQCReadyCount        int `json:"pqc_ready_count"`

	// Key state indicators
	CompromisedKeys int `json:"compromised_keys"`
	ExpiredKeys     int `json:"expired_keys"`

	// Breakdowns
	ByEnvironment       map[string]int `json:"by_environment"`
	ByRiskLevel         map[string]int `json:"by_risk_level"`
	ByAlgorithmCategory map[string]int `json:"by_algorithm_category"`
	ByPrimitive         map[string]int `json:"by_primitive"`
	ByMaterialType      map[string]int `json:"by_material_type"`
}

// CBOMData is the intermediate representation assembled from inventory service data.
// Both CycloneDX and SPDX generators consume this model.
type CBOMData struct {
	// BOM metadata
	SerialNumber string    `json:"serial_number"` // UUID for this BOM instance
	BOMVersion   int       `json:"bom_version"`
	GeneratedAt  time.Time `json:"generated_at"`
	ReportTitle  string    `json:"report_title"`
	TenantID     string    `json:"tenant_id,omitempty"`

	// CycloneDX spec version
	SpecVersion string `json:"spec_version,omitempty"` // defaults to formatters.SpecVersion

	// Generation parameters (recorded for audit)
	Parameters map[string]interface{} `json:"parameters,omitempty"`

	// Aggregated summary
	Summary CBOMSummary `json:"summary"`

	// Full component list
	Components []CBOMComponent `json:"components"`
}
