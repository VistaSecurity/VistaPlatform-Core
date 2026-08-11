package models

import (
	"time"

	"github.com/google/uuid"
)

// Key represents a cryptographic key's metadata (no private material).
// Aligned with CycloneDX relatedCryptoMaterialProperties.
type Key struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	TenantID          uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	KeyType           string                 `json:"key_type" db:"key_type"`
	KeyUsage          []string               `json:"key_usage" db:"key_usage"`
	PublicFingerprint *string                `json:"public_fingerprint,omitempty" db:"public_fingerprint"`
	JWKThumbprint     *string                `json:"jwk_thumbprint,omitempty" db:"jwk_thumbprint"`
	SizeBits          *int                   `json:"size_bits,omitempty" db:"size_bits"`
	Curve             *string                `json:"curve,omitempty" db:"curve"`
	CreatedAt         *time.Time             `json:"created_at,omitempty" db:"created_at"`
	RotatedAt         *time.Time             `json:"rotated_at,omitempty" db:"rotated_at"`
	ExpiresAt         *time.Time             `json:"expires_at,omitempty" db:"expires_at"`
	Provenance        *string                `json:"provenance,omitempty" db:"provenance"`
	Metadata          map[string]interface{} `json:"metadata" db:"metadata"`

	// CycloneDX relatedCryptoMaterialProperties fields
	MaterialType     string     `json:"material_type" db:"material_type"`         // private-key, public-key, secret-key, etc.
	State            string     `json:"state" db:"state"`                         // NIST SP 800-57: pre-activation, active, suspended, deactivated, compromised, destroyed
	StateReason      *string    `json:"state_reason,omitempty" db:"state_reason"` // Reason for current state
	Format           *string    `json:"format,omitempty" db:"format"`             // PEM, PKCS#8, JWK, DER
	AlgorithmRef     *string    `json:"algorithm_ref,omitempty" db:"algorithm_ref"`
	SecuredBy        *string    `json:"secured_by,omitempty" db:"secured_by"` // HSM, TPM, Software, None
	ActivationDate   *time.Time `json:"activation_date,omitempty" db:"activation_date"`
	DeactivationDate *time.Time `json:"deactivation_date,omitempty" db:"deactivation_date"`
	DestructionDate  *time.Time `json:"destruction_date,omitempty" db:"destruction_date"`

	// DeploymentCount is the number of distinct non-deleted assets that use this
	// key via implementation_keys → crypto_implementations. Not a stored column;
	// populated by list/detail queries via a correlated subquery so the frontend
	// can show a "used by N assets" / "Unlinked" signal without hydrating each key.
	DeploymentCount *int `json:"deployment_count,omitempty" db:"deployment_count"`
}

// KeyImplementation is a single crypto configuration that references a key,
// flattened with just enough asset context for the Keys-lens drawer to render a
// row and push the asset drawer. Returned by GetKeyImplementations.
type KeyImplementation struct {
	ImplementationID uuid.UUID `json:"implementation_id" db:"implementation_id"`
	AssetID          uuid.UUID `json:"asset_id" db:"asset_id"`
	AssetHostname    *string   `json:"asset_hostname,omitempty" db:"asset_hostname"`
	Protocol         *string   `json:"protocol,omitempty" db:"protocol"`
	ProtocolVersion  *string   `json:"protocol_version,omitempty" db:"protocol_version"`
}

// CryptoLibrary represents a crypto library and version present on an implementation.
// Enhanced with CycloneDX fields for CBOM export.
type CryptoLibrary struct {
	ID                   uuid.UUID                `json:"id" db:"id"`
	TenantID             uuid.UUID                `json:"tenant_id" db:"tenant_id"`
	Name                 string                   `json:"name" db:"name"`
	Version              string                   `json:"version" db:"version"`
	Vendor               *string                  `json:"vendor,omitempty" db:"vendor"`
	CPE                  *string                  `json:"cpe,omitempty" db:"cpe"`
	BuildMetadata        map[string]interface{}   `json:"build_metadata" db:"build_metadata"`
	KnownVulnerabilities []map[string]interface{} `json:"known_vulnerabilities" db:"known_vulnerabilities"`
	CreatedAt            time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at" db:"updated_at"`

	// CycloneDX fields
	PURL               *string  `json:"purl,omitempty" db:"purl"`                               // Package URL
	CertificationLevel []string `json:"certification_level,omitempty" db:"certification_level"` // e.g., ["fips140-3-l1"]
}

// ExternalAssetMapping maps local entities to external systems
type ExternalAssetMapping struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	TenantID       uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	LocalType      string     `json:"local_type" db:"local_type"`
	LocalID        uuid.UUID  `json:"local_id" db:"local_id"`
	ExternalSystem string     `json:"external_system" db:"external_system"`
	ExternalID     string     `json:"external_id" db:"external_id"`
	SyncStatus     *string    `json:"sync_status,omitempty" db:"sync_status"`
	LastSyncedAt   *time.Time `json:"last_synced_at,omitempty" db:"last_synced_at"`
	LastSyncError  *string    `json:"last_sync_error,omitempty" db:"last_sync_error"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}
