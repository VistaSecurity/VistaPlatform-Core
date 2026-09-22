// Package services: cloud-KMS half of the cryptographic-key inventory producer.
//
// The certificate half lives in key_producer.go. This one takes a key that a
// cloud provider holds — an AWS KMS CMK, an Azure Key Vault key, a GCP Cloud
// KMS crypto key — and lands it in the SAME `keys` table the Inventory → Keys
// lens reads, so a discovered cloud key is something a person can actually see.
//
// Why here and not in device-interrogation-service, which does the discovery:
// inventory-service owns what a key row IS — the dedup identity, the lifecycle
// vocabulary, and the resolution of an algorithm against the catalogue. The
// discovery service reports what the provider said (see the CloudKeyRecord wire
// shape); this decides what that means for inventory. Same division as the
// agent-host approval route.
//
// METADATA ONLY — no key material is ever stored, and none is even available: a
// KMS key's private/secret half cannot leave the provider. Fingerprint and
// thumbprint columns are left NULL rather than filled with something that is not
// a fingerprint of the key.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// CloudKeyRecord is one key as the PROVIDER describes it. Deliberately
// provider-native: the caller reports observations, this file decides what they
// mean. Field names match the KMS discovery finding so the wire hop is a
// straight marshal on the other side.
type CloudKeyRecord struct {
	// Provider is "aws", "azure" or "gcp".
	Provider string `json:"provider"`
	// KeyID is the provider's key identifier (a KMS key id, a Key Vault key
	// name, a Cloud KMS crypto-key id).
	KeyID string `json:"key_id"`
	// KeyARN is the fully-qualified provider reference (ARN / resource id).
	// Preferred as external_ref; KeyID is the fallback.
	KeyARN string `json:"key_arn,omitempty"`
	// KeyName is a human label — the first alias, where there is one.
	KeyName string `json:"key_name,omitempty"`
	// KeySpec is the provider's normalised spec: SYMMETRIC_DEFAULT, RSA_2048,
	// ECC_NIST_P256, HMAC_256, ML_DSA_44, …
	KeySpec string `json:"key_spec,omitempty"`
	// KeyUsage is the provider's usage enum: ENCRYPT_DECRYPT, SIGN_VERIFY,
	// GENERATE_VERIFY_MAC, KEY_AGREEMENT.
	KeyUsage string `json:"key_usage,omitempty"`
	// KeyState is the provider's lifecycle state: Enabled, Disabled,
	// PendingDeletion, …
	KeyState string `json:"key_state,omitempty"`
	// KeyManager is who holds the key, as the provider words it: AWS or
	// CUSTOMER.
	KeyManager string `json:"key_manager,omitempty"`
	// Origin is where the material came from: AWS_KMS, AWS_CLOUDHSM, EXTERNAL,
	// EXTERNAL_KEY_STORE.
	Origin string `json:"origin,omitempty"`
	// Description is the provider-side description, if any.
	Description string `json:"description,omitempty"`
	// Region / AccountID locate the key in the provider's own coordinates.
	Region    string `json:"region,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	// IntegrationID is the cloud integration the key was discovered through.
	IntegrationID string `json:"integration_id,omitempty"`
	// CreationDate is when the provider created the key.
	CreationDate *time.Time `json:"creation_date,omitempty"`
	// RotationEnabled / RotationPeriodDays describe automatic rotation. They are
	// posture, not a timestamp: neither says when the key last rotated, so
	// `keys.rotated_at` stays NULL rather than being guessed at.
	RotationEnabled    bool `json:"rotation_enabled,omitempty"`
	RotationPeriodDays int  `json:"rotation_period_days,omitempty"`
	// MultiRegion marks an AWS multi-Region key.
	MultiRegion bool `json:"multi_region,omitempty"`
	// Aliases are the provider's alias names for the key.
	Aliases []string `json:"aliases,omitempty"`
}

// ---------------------------------------------------------------------------
// Mapping. Every function below is pure and unit-tested; nothing here invents a
// value it did not read.
// ---------------------------------------------------------------------------

// CloudKeyCustody normalises the provider's key-manager wording to the custody
// vocabulary the `keys.key_custody` CHECK admits: "customer", "provider", or ""
// for "we did not establish it" (written as NULL).
//
// This is the attribute that used to be a FILTER. AWS-managed keys were dropped
// at discovery, which is why anything AWS holds could only ever read as
// custody-unknown in the Data Protection ladder.
func CloudKeyCustody(keyManager string) string {
	switch strings.ToUpper(strings.TrimSpace(keyManager)) {
	case "CUSTOMER":
		return "customer"
	case "AWS", "PROVIDER", "AZURE", "GCP", "GOOGLE":
		return "provider"
	default:
		return ""
	}
}

// cloudKeyType is the key_type column: the algorithm FAMILY, matching the
// vocabulary the certificate producer writes ("RSA", "ECDSA", …).
func cloudKeyType(keySpec, keyUsage string) string {
	spec := strings.ToUpper(strings.TrimSpace(keySpec))
	switch {
	case spec == "":
		return "unknown"
	case spec == "SYMMETRIC_DEFAULT":
		return "AES"
	case strings.HasPrefix(spec, "RSA"):
		return "RSA"
	case strings.HasPrefix(spec, "ECC"), strings.HasPrefix(spec, "EC_"):
		if strings.ToUpper(keyUsage) == "KEY_AGREEMENT" {
			return "ECDH"
		}
		return "ECDSA"
	case strings.HasPrefix(spec, "HMAC"):
		return "HMAC"
	case strings.HasPrefix(spec, "ML_DSA"), strings.HasPrefix(spec, "ML-DSA"):
		return "ML-DSA"
	case strings.HasPrefix(spec, "ML_KEM"), strings.HasPrefix(spec, "ML-KEM"):
		return "ML-KEM"
	case strings.HasPrefix(spec, "SM2"):
		return "SM2"
	default:
		return spec
	}
}

// cloudKeySize returns the key size in bits, or 0 when the spec does not carry
// one. Zero is written as NULL — an unknown modulus is not a modulus of zero.
func cloudKeySize(keySpec string) int {
	spec := strings.ToUpper(strings.TrimSpace(keySpec))
	switch {
	// SYMMETRIC_DEFAULT is AES-256-GCM, fixed by AWS.
	case spec == "SYMMETRIC_DEFAULT":
		return 256
	case strings.Contains(spec, "2048"):
		return 2048
	case strings.Contains(spec, "3072"):
		return 3072
	case strings.Contains(spec, "4096"):
		return 4096
	case strings.Contains(spec, "P521"), strings.Contains(spec, "P-521"):
		return 521
	case strings.Contains(spec, "P384"), strings.Contains(spec, "P-384"):
		return 384
	// P256K1 before P256: the secp256k1 spelling contains "P256".
	case strings.Contains(spec, "P256"), strings.Contains(spec, "P-256"):
		return 256
	case strings.HasPrefix(spec, "HMAC_224"):
		return 224
	case strings.HasPrefix(spec, "HMAC_256"):
		return 256
	case strings.HasPrefix(spec, "HMAC_384"):
		return 384
	case strings.HasPrefix(spec, "HMAC_512"):
		return 512
	default:
		return 0
	}
}

// cloudKeyCurve returns the named curve for an elliptic-curve spec, or "".
func cloudKeyCurve(keySpec string) string {
	switch strings.ToUpper(strings.TrimSpace(keySpec)) {
	case "ECC_NIST_P256":
		return "P-256"
	case "ECC_NIST_P384":
		return "P-384"
	case "ECC_NIST_P521":
		return "P-521"
	case "ECC_SECG_P256K1":
		return "secp256k1"
	default:
		return ""
	}
}

// cloudKeyMaterialType maps to the CycloneDX relatedCryptoMaterial type enum
// (the `valid_material_type` CHECK).
//
//   - a symmetric CMK and an HMAC key are 'secret-key': one secret, held by the
//     provider, never exported.
//   - an asymmetric CMK is 'private-key'. The INVENTORIED object is the half
//     that exists inside KMS and does the signing/decrypting; its public half is
//     derivable but is not the thing being held. Calling it 'public-key' would
//     understate what the key is.
func cloudKeyMaterialType(keySpec string) string {
	spec := strings.ToUpper(strings.TrimSpace(keySpec))
	switch {
	case spec == "SYMMETRIC_DEFAULT", strings.HasPrefix(spec, "HMAC"):
		return "secret-key"
	case spec == "":
		return "key"
	default:
		return "private-key"
	}
}

// cloudKeyState maps a provider lifecycle state onto the NIST SP 800-57 states
// `valid_key_state` admits. "" means the provider said something this does not
// recognise, and is written as NULL — the honest answer, and one the read path
// already tolerates (keys.state is nullable and scans into *string).
//
// Deliberately NOT defaulted to 'active': an unrecognised state rendered as
// active is a live-key claim nobody made. Same reason GCP's IMPORT_FAILED and
// GENERATION_FAILED map to nothing — a key that never came into existence is
// not in any of the six lifecycle states.
//
// Spelling is normalised (case, spaces, underscores, hyphens) so all three
// providers' conventions land on the same cases: AWS PascalCase
// (`PendingDeletion`), GCP SCREAMING_SNAKE (`DESTROY_SCHEDULED`), Azure's
// enabled/disabled.
func cloudKeyState(providerState string) string {
	switch normalizeProviderWord(providerState) {
	// Not usable yet, by design.
	case "CREATING", "PENDINGIMPORT", "PENDINGGENERATION":
		return "pre-activation"
	case "ENABLED", "UPDATING", "ACTIVE":
		return "active"
	// Reversible withdrawal from service — exactly what SP 800-57 calls
	// suspended. `Unavailable` (a disconnected custom key store) is the same
	// shape: the key exists and may come back.
	case "DISABLED", "UNAVAILABLE", "SUSPENDED":
		return "suspended"
	// Scheduled for destruction but not yet destroyed. 'deactivated', not
	// 'destroyed': the key still exists and the deletion is cancellable.
	case "PENDINGDELETION", "PENDINGREPLICADELETION", "DESTROYSCHEDULED", "PENDINGEXTERNALDESTRUCTION":
		return "deactivated"
	case "DESTROYED":
		return "destroyed"
	default:
		return ""
	}
}

// normalizeProviderWord folds a provider enum to one comparable spelling:
// upper-case, with spaces, underscores and hyphens removed.
func normalizeProviderWord(s string) string {
	out := strings.ToUpper(strings.TrimSpace(s))
	for _, sep := range []string{" ", "_", "-"} {
		out = strings.ReplaceAll(out, sep, "")
	}
	return out
}

// cloudKeyFunctions maps the provider's usage/purpose enum to CycloneDX
// cryptoFunctions verbs, which is what `keys.key_usage` carries.
//
// Covers all three providers: AWS KeyUsage, GCP CryptoKeyPurpose, and the bare
// Key Vault key operation the Azure path reports. An unrecognised word yields
// no usage rather than a guessed one.
func cloudKeyFunctions(keyUsage string) []string {
	switch normalizeProviderWord(keyUsage) {
	// AWS ENCRYPT_DECRYPT; GCP ENCRYPT_DECRYPT / RAW_ENCRYPT_DECRYPT.
	case "ENCRYPTDECRYPT", "RAWENCRYPTDECRYPT":
		return []string{"encrypt", "decrypt"}
	// AWS SIGN_VERIFY; GCP ASYMMETRIC_SIGN.
	case "SIGNVERIFY", "ASYMMETRICSIGN":
		return []string{"sign", "verify"}
	// AWS GENERATE_VERIFY_MAC; GCP MAC.
	case "GENERATEVERIFYMAC", "MAC":
		return []string{"tag", "verify"}
	case "KEYAGREEMENT":
		return []string{"keyderive"}
	// GCP ASYMMETRIC_DECRYPT decrypts only: the public half encrypts, and the
	// key inventoried here is the half that cannot.
	case "ASYMMETRICDECRYPT":
		return []string{"decrypt"}
	// Azure reports one key operation at a time, already a CycloneDX-shaped verb.
	case "SIGN":
		return []string{"sign"}
	case "VERIFY":
		return []string{"verify"}
	case "ENCRYPT":
		return []string{"encrypt"}
	case "DECRYPT":
		return []string{"decrypt"}
	case "WRAPKEY":
		return []string{"encrypt"}
	case "UNWRAPKEY":
		return []string{"decrypt"}
	case "DERIVEKEY":
		return []string{"keyderive"}
	default:
		return nil
	}
}

// cloudKeySecuredBy describes what protects the key, for the lens's "Secured by"
// row. Origin is a statement about where the material lives, which is the same
// question.
func cloudKeySecuredBy(provider, origin string) string {
	switch strings.ToUpper(strings.TrimSpace(origin)) {
	case "AWS_CLOUDHSM":
		return "AWS CloudHSM key store"
	case "EXTERNAL":
		return "Imported key material"
	case "EXTERNAL_KEY_STORE":
		return "External key store"
	case "AWS_KMS":
		return "AWS KMS"
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return "AWS KMS"
	case "azure":
		return "Azure Key Vault"
	case "gcp":
		return "Google Cloud KMS"
	default:
		return ""
	}
}

// CloudKeyAlgorithmCode returns the `algorithms.code` to resolve `algorithm_id`
// against, or "" when the catalogue has no row that is ABOUT this key.
//
// A miss is not a failure — algorithm_id is a LEFT JOIN on the read side and an
// unresolved key is honestly unscored. Borrowing a row that is about something
// else is the failure, which is why:
//
//   - HMAC_* resolves to nothing. The catalogue's `hmac-sha2-*` rows are SSH MAC
//     negotiation algorithms (name "hmac-sha2-256 (SSH)"), not an assessment of
//     a standalone HMAC key.
//   - RSA_* resolves to the SIZED rows only, never the bare `RSA` row — that one
//     is "RSA key transport (static)", a TLS key-exchange assessment. Same trap
//     documented at algorithmCodeForKey in key_producer.go.
//   - SM2 resolves to nothing; the catalogue has no SM2 row.
func CloudKeyAlgorithmCode(keySpec, keyUsage string) string {
	spec := strings.ToUpper(strings.TrimSpace(keySpec))
	switch {
	case spec == "SYMMETRIC_DEFAULT":
		return "AES256"
	case strings.HasPrefix(spec, "RSA"):
		if n := cloudKeySize(spec); n > 0 {
			return fmt.Sprintf("RSA-%d", n)
		}
		return ""
	case strings.HasPrefix(spec, "ECC"), strings.HasPrefix(spec, "EC_"):
		if strings.ToUpper(keyUsage) == "KEY_AGREEMENT" {
			return "ECDH"
		}
		return "ECDSA"
	case strings.HasPrefix(spec, "ML_DSA"), strings.HasPrefix(spec, "ML-DSA"):
		// ML_DSA_44 → ML-DSA-44.
		return strings.ReplaceAll(spec, "_", "-")
	case strings.HasPrefix(spec, "ML_KEM"), strings.HasPrefix(spec, "ML-KEM"):
		return strings.ReplaceAll(spec, "_", "-")
	default:
		return ""
	}
}

// cloudKeyExternalRef is the dedup identity: the provider's own fully-qualified
// name for the key, falling back to the bare key id.
func cloudKeyExternalRef(r CloudKeyRecord) string {
	if s := strings.TrimSpace(r.KeyARN); s != "" {
		return s
	}
	return strings.TrimSpace(r.KeyID)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// upsertCloudKey is keyed on (tenant_id, external_ref) — the partial UNIQUE
// index keys_tenant_external_ref_uniq — so re-running discovery converges on one
// row per provider key instead of accumulating duplicates.
//
// public_fingerprint / jwk_thumbprint / fingerprint_* are absent from the column
// list on purpose: a KMS key exports no public material, so there is nothing to
// fingerprint and nothing that would be true to put there.
const upsertCloudKey = `
	INSERT INTO keys (
		tenant_id, key_type, key_usage, size_bits, curve,
		material_type, state, state_reason, algorithm_id,
		secured_by_mechanism, key_custody, external_ref,
		provenance, metadata, created_at, activation_date
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8,
		(SELECT id FROM algorithms WHERE code ILIKE $9 ORDER BY code LIMIT 1),
		$10, $11, $12,
		$13, $14, COALESCE($15::timestamptz, NOW()), $15::timestamptz
	)
	ON CONFLICT (tenant_id, external_ref) WHERE external_ref IS NOT NULL
	DO UPDATE SET
		key_type             = EXCLUDED.key_type,
		key_usage            = EXCLUDED.key_usage,
		size_bits            = EXCLUDED.size_bits,
		curve                = EXCLUDED.curve,
		material_type        = EXCLUDED.material_type,
		state                = EXCLUDED.state,
		state_reason         = EXCLUDED.state_reason,
		algorithm_id         = COALESCE(EXCLUDED.algorithm_id, keys.algorithm_id),
		secured_by_mechanism = EXCLUDED.secured_by_mechanism,
		key_custody          = EXCLUDED.key_custody,
		provenance           = EXCLUDED.provenance,
		metadata             = EXCLUDED.metadata,
		activation_date      = COALESCE(EXCLUDED.activation_date, keys.activation_date)
	RETURNING id`

// UpsertCloudKeys materialises discovered cloud KMS keys into the `keys` table
// the Inventory → Keys lens reads. Returns the number of rows written.
//
// Each record is written in its own tenant-scoped transaction so one malformed
// key cannot cost the rest of the batch; the error returned is the first
// failure, after every record has been attempted.
func (s *AssetService) UpsertCloudKeys(tenantID uuid.UUID, records []CloudKeyRecord) (int, error) {
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("cloud key upsert: tenant id is required")
	}
	written := 0
	var firstErr error
	for _, r := range records {
		ref := cloudKeyExternalRef(r)
		if ref == "" {
			// Nothing stable to dedup on — skip rather than write a row that
			// re-discovery would duplicate.
			if firstErr == nil {
				firstErr = fmt.Errorf("cloud key upsert: record has neither key_arn nor key_id")
			}
			continue
		}

		keyType := cloudKeyType(r.KeySpec, r.KeyUsage)
		var sizeBits *int
		if n := cloudKeySize(r.KeySpec); n > 0 {
			sizeBits = &n
		}
		var curve *string
		if c := cloudKeyCurve(r.KeySpec); c != "" {
			curve = &c
		}
		var state *string
		var stateReason *string
		if st := cloudKeyState(r.KeyState); st != "" {
			state = &st
		}
		if raw := strings.TrimSpace(r.KeyState); raw != "" {
			// Always carried, so the lens can show what the provider actually
			// said — including when the state mapped to NULL.
			reason := fmt.Sprintf("%s key state: %s", cloudProviderLabel(r.Provider), raw)
			stateReason = &reason
		}
		var custody *string
		if cst := CloudKeyCustody(r.KeyManager); cst != "" {
			custody = &cst
		}
		var securedBy *string
		if sb := cloudKeySecuredBy(r.Provider, r.Origin); sb != "" {
			securedBy = &sb
		}
		var activation *time.Time
		if r.CreationDate != nil && !r.CreationDate.IsZero() {
			t := *r.CreationDate
			activation = &t
		}

		meta := map[string]interface{}{
			"source":      "cloud-kms",
			"provider":    strings.ToLower(strings.TrimSpace(r.Provider)),
			"key_id":      r.KeyID,
			"key_spec":    r.KeySpec,
			"key_usage":   r.KeyUsage,
			"key_state":   r.KeyState,
			"key_manager": r.KeyManager,
			// Rotation posture, not a rotation timestamp. `rotated_at` stays
			// NULL: nothing here says WHEN the key last rotated.
			"rotation_enabled": r.RotationEnabled,
		}
		if r.RotationPeriodDays > 0 {
			meta["rotation_period_days"] = r.RotationPeriodDays
		}
		if r.MultiRegion {
			meta["multi_region"] = true
		}
		for k, v := range map[string]string{
			"key_name":       r.KeyName,
			"description":    r.Description,
			"region":         r.Region,
			"account_id":     r.AccountID,
			"origin":         r.Origin,
			"integration_id": r.IntegrationID,
		} {
			if strings.TrimSpace(v) != "" {
				meta[k] = v
			}
		}
		if len(r.Aliases) > 0 {
			meta["aliases"] = r.Aliases
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("cloud key upsert: encode metadata: %w", err)
			}
			continue
		}

		provenance := cloudKeyProvenance(r.Provider)
		usage := pq.StringArray(cloudKeyFunctions(r.KeyUsage))
		algoCode := CloudKeyAlgorithmCode(r.KeySpec, r.KeyUsage)

		// RLS-scoped write over `keys` under the known tenant.
		err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var id uuid.UUID
			return tx.QueryRow(upsertCloudKey,
				tenantID, keyType, usage, sizeBits, curve,
				cloudKeyMaterialType(r.KeySpec), state, stateReason, algoCode,
				securedBy, custody, ref,
				provenance, string(metaJSON), activation,
			).Scan(&id)
		})
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("cloud key upsert %s: %w", ref, err)
			}
			continue
		}
		written++
	}
	return written, firstErr
}

// cloudKeyProvenance is the `provenance` column — where the row came from, in
// the same shape the certificate producer uses ("certificate").
func cloudKeyProvenance(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		return "cloud-kms"
	}
	return "cloud-kms:" + p
}

// cloudProviderLabel is the provider's display name, for state_reason text.
func cloudProviderLabel(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return "AWS KMS"
	case "azure":
		return "Azure Key Vault"
	case "gcp":
		return "Google Cloud KMS"
	default:
		return "Cloud KMS"
	}
}
