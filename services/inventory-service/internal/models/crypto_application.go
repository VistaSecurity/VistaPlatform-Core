package models

import "time"

// CryptoApplication is one resource's cryptographic posture in ONE encryption
// context — the at-rest sibling of CryptoImplementation. It is the API shape of
// a public.crypto_applications row, flattened: the measured posture lives in
// the row's configuration_data jsonb, and the fields below are the allowlisted
// projection of it that the Data Protection lens renders.
//
// POSTURE ONLY. KMSKeyID is a key IDENTIFIER (an ARN or key id, the same string
// the provider prints in its own console), never key material.
type CryptoApplication struct {
	ID                 string  `json:"id"`
	AssetID            *string `json:"asset_id"`
	ResourceType       string  `json:"resource_type"`
	ResourceName       string  `json:"resource_name"`
	ResourceIdentifier string  `json:"resource_identifier"`
	EncryptionContext  string  `json:"encryption_context"`

	// Encrypted is only meaningful when EncryptionDetermined is true. When we
	// could not measure the posture (AccessDenied, transport failure) this is
	// false and EncryptionDetermined is false — which is NOT the same claim as
	// "unencrypted", and must not be rendered as one.
	Encrypted            bool    `json:"encrypted"`
	EncryptionDetermined bool    `json:"encryption_determined"`
	EncryptionType       string  `json:"encryption_type"`
	Algorithm            *string `json:"algorithm"`

	// KeyManager is "customer", "provider", or null when there is no key to
	// attribute (unencrypted or unmeasured).
	KeyManager *string `json:"key_manager"`
	KMSKeyID   *string `json:"kms_key_id"`

	CloudProvider *string `json:"cloud_provider"`
	CloudRegion   *string `json:"cloud_region"`

	// RiskScore 0 means NOT ASSESSED, not safe (CLAUDE.md). RiskLevel is
	// derived from it by models.GetRiskLevel — never by a second ladder.
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`

	LastVerifiedAt *time.Time `json:"last_verified_at"`
}
