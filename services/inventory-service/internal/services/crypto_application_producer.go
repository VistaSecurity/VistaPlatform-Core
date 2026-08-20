// Package services: at-rest encryption posture producer.
//
// This file is the at-rest sibling of key_producer.go. Where
// crypto_implementations records what a network endpoint negotiates IN TRANSIT,
// public.crypto_applications records what a managed resource does AT REST —
// the same asset spine, a different encryption context.
//
// Cloud discovery (device-interrogation-service's StorageEncryptionService and
// its Azure/GCP siblings) already measures this: whether a bucket/database is
// encrypted, with which algorithm, under whose key. Until now that measurement
// landed in sensor_discoveries.metadata and stopped there — nothing read it,
// nothing rendered it. This derives a first-class, queryable row from it.
//
// POSTURE ONLY — never key material. A KMS key ARN/id is an identifier (it is
// what the provider prints in its own console), not the key. Nothing here
// touches key bytes, and there is no path by which it could: the source fields
// are an explicit allowlist read off the discovery metadata.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// Risk scores for at-rest posture. Owner rule: "unencrypted data is a fail,
// 100% fail" — but encryption is a LADDER, not a bit, and "could not determine"
// must never score as a fail.
//
//   - NOT ASSESSED  -> 0.  Per CLAUDE.md, "score 0 means NOT ASSESSED, not
//     safe". An AccessDenied on GetBucketEncryption is not evidence of
//     anything; scoring it as either a pass or a fail invents a measurement we
//     never made.
//   - unencrypted    -> 90 (Critical band).
//   - provider key   -> 40 (Medium). Encrypted, but the customer neither holds
//     nor can revoke the key, so they cannot answer "who can decrypt this".
//   - customer key   -> 10 (Low). Encrypted under a key the tenant controls.
//
// The numbers are band ANCHORS, chosen to sit inside models.RiskBands —
// nothing here re-derives a band from a threshold. Anything that needs the
// label calls models.GetRiskLevel, and anything filtering in SQL uses
// models.RiskAtLeastSQL.
const (
	atRestRiskNotAssessed   = 0
	atRestRiskUnencrypted   = 90
	atRestRiskProviderKey   = 40
	atRestRiskCustomerKey   = 10
	atRestConfidenceKnown   = 1.0
	atRestConfidenceUnknown = 0.0
)

// Key-manager classification, as surfaced to the API.
const (
	keyManagerCustomer = "customer"
	keyManagerProvider = "provider"
)

// atRestPosture is the projection of a discovery finding onto the fields
// crypto_applications actually stores. It is an explicit ALLOWLIST: nothing
// from the vendor payload reaches the database except through a field named
// here (the "collect posture, never key material" rule in CLAUDE.md).
type atRestPosture struct {
	ResourceType       string // crypto_applications.resource_type
	ResourceIdentifier string // ARN / fully-qualified id — the natural key
	ResourceName       string
	Encrypted          bool
	Determined         bool
	EncryptionType     string
	Algorithm          string
	KMSKeyID           string
	KeyManager         string
	CloudProvider      string
	CloudRegion        string
	EncryptionError    string
	AdditionalDetail   map[string]interface{}
}

// atRestResourceTypes maps the cloud collectors' `resource_type` metadata value
// onto the crypto_applications.resource_type CHECK vocabulary. A finding whose
// resource_type is absent from this map is not an at-rest finding, and this
// producer does not touch it.
//
// Keyed on the collector's resource_type rather than on device_type because
// that is the field every STORAGE/DATABASE collector writes with the same
// meaning (StorageEncryptionFinding.ResourceType), so a new region/service
// wiring does not have to remember to update a device-type list.
//
// B-22: "every provider's collector writes" was too strong. The three cloud
// key-store collectors (aws_kms, azure_keyvault_key, gcp_kms_crypto_key) write
// no resource_type at all, so they are not routed here — and used to be
// materialized as phantom TLS endpoints instead. inventory-service now drops
// them at the AT-REST sentinel (isAtRestProtocol in asset_service.go) rather
// than fabricating a measurement. Adding them to this map is not merely a map
// entry: this table's whole vocabulary answers "is this resource's DATA
// encrypted, and whose key", and none of its rungs describes a resource that IS
// the key. That needs a product decision, not a mapping.
var atRestResourceTypes = map[string]string{
	// object / blob storage
	"s3_bucket":       "cloud_storage",
	"storage_account": "cloud_storage",
	"gcs_bucket":      "cloud_storage",
	// managed databases
	"rds_instance":      "database",
	"sql_database":      "database",
	"cloudsql_instance": "database",
}

// atRestPostureFromFinding projects a discovery finding onto an at-rest posture,
// reporting false when the finding is not an at-rest resource at all.
//
// Pure: no DB, no clock. The whole classification ladder is testable from a
// literal map, which is the point — this is where a wrong answer becomes a
// wrong compliance verdict.
func atRestPostureFromFinding(f IngestFinding) (atRestPosture, bool) {
	if f.RawData == nil {
		return atRestPosture{}, false
	}
	rawType, _ := f.RawData["resource_type"].(string)
	mapped, ok := atRestResourceTypes[rawType]
	if !ok {
		return atRestPosture{}, false
	}

	p := atRestPosture{
		ResourceType:       mapped,
		ResourceIdentifier: strings.TrimSpace(stringField(f.RawData, "arn")),
		Encrypted:          boolField(f.RawData, "encrypted"),
		EncryptionType:     stringField(f.RawData, "encryption_type"),
		Algorithm:          stringField(f.RawData, "algorithm"),
		KMSKeyID:           stringField(f.RawData, "kms_key_id"),
		CloudProvider:      stringField(f.RawData, "cloud_provider"),
		CloudRegion:        stringField(f.RawData, "cloud_region"),
		EncryptionError:    stringField(f.RawData, "encryption_error"),
	}
	if p.CloudRegion == "" {
		// The collectors write the resource's own region as "region"; the
		// sensor-discovery envelope re-stamps it as "cloud_region". Prefer the
		// envelope, fall back to the collector's own field.
		p.CloudRegion = stringField(f.RawData, "region")
	}
	if detail, ok := f.RawData["additional_detail"].(map[string]interface{}); ok {
		p.AdditionalDetail = detail
	}

	// encryption_determined is written explicitly only by the S3 collector,
	// which is the only one that can fail to measure: GetBucketEncryption is a
	// separate, separately-authorized call. Every other collector derives the
	// posture from the same DescribeX response that produced the resource, so
	// having the resource IS having the measurement. Absent key therefore means
	// determined — but an explicit false is always honoured.
	if v, present := f.RawData["encryption_determined"]; present {
		b, isBool := v.(bool)
		p.Determined = isBool && b
	} else {
		p.Determined = true
	}

	// Resource name: prefer the finding's hostname (the collectors set it to
	// the bucket name / db identifier), fall back to the tail of the ARN.
	if f.Hostname != nil && *f.Hostname != "" {
		p.ResourceName = *f.Hostname
	} else if p.ResourceIdentifier != "" {
		parts := strings.Split(p.ResourceIdentifier, ":")
		p.ResourceName = strings.TrimPrefix(parts[len(parts)-1], "/")
	}

	if p.ResourceIdentifier == "" {
		// Nothing stable to upsert on. A row keyed on a blank identifier would
		// collapse every such resource onto one row, which is the same bug the
		// 0.0.0.0 placeholder caused for assets. Skip rather than corrupt.
		return atRestPosture{}, false
	}

	p.KeyManager = p.classifyKeyManager()
	return p, true
}

// providerManagedEncryptionTypes are the encryption types where the provider
// holds the key. Listed positively (rather than "anything not customer") so a
// new, unrecognised encryption type falls through to "unknown key manager"
// instead of being silently asserted as provider-managed.
var providerManagedEncryptionTypes = map[string]bool{
	"sse-s3":              true, // AWS S3, explicitly configured
	"sse-s3-default":      true, // AWS S3, no bucket config; AWS default applies
	"microsoft-managed":   true, // Azure Storage
	"google-managed":      true, // GCS / Cloud SQL
	"tde-service-managed": true, // Azure SQL TDE, service-managed key
}

// customerManagedEncryptionTypes are the encryption types where the tenant
// holds (and can revoke) the key.
var customerManagedEncryptionTypes = map[string]bool{
	"sse-kms":      true, // AWS S3 + KMS
	"sse-kms-dsse": true, // AWS S3 dual-layer + KMS
	"cmk":          true, // Azure Storage customer-managed key
	"cmek":         true, // GCS / Cloud SQL customer-managed key
	"tde-cmk":      true, // Azure SQL TDE, Key Vault key
}

// classifyKeyManager decides who holds the key for an encrypted resource.
// Returns "" when the resource is unencrypted or unmeasured — there is no key
// to attribute, and inventing one would be the same class of error as scoring
// an unmeasured bucket as a pass.
func (p atRestPosture) classifyKeyManager() string {
	if !p.Determined || !p.Encrypted {
		return ""
	}
	t := strings.ToLower(strings.TrimSpace(p.EncryptionType))
	switch {
	case customerManagedEncryptionTypes[t]:
		return keyManagerCustomer
	case providerManagedEncryptionTypes[t]:
		return keyManagerProvider
	case p.KMSKeyID != "":
		// RDS ("rds-storage-encryption") and anything else that reports a key:
		// an encrypted resource naming a specific key is customer-attributable.
		return keyManagerCustomer
	default:
		// Encrypted, but we cannot say by whose key. Treat as provider-managed
		// for scoring (the weaker of the two encrypted rungs) rather than
		// claiming customer control we have not evidenced.
		return keyManagerProvider
	}
}

// riskScore applies the owner's at-rest ladder. Deliberately NOT a threshold
// ladder over some other score: each rung is a distinct, nameable posture.
func (p atRestPosture) riskScore() int {
	if !p.Determined {
		return atRestRiskNotAssessed
	}
	if !p.Encrypted {
		return atRestRiskUnencrypted
	}
	if p.KeyManager == keyManagerCustomer {
		return atRestRiskCustomerKey
	}
	return atRestRiskProviderKey
}

func (p atRestPosture) confidence() float64 {
	if p.Determined {
		return atRestConfidenceKnown
	}
	return atRestConfidenceUnknown
}

// algorithmCodeForAtRest maps a collector's algorithm string onto an
// algorithms.code for catalogue resolution. The collectors report display
// names ("AES-256", "AES-256-KMS"); the catalogue keys on codes ("AES256").
// A miss returns "", which matches nothing and leaves algorithm_id NULL — the
// read path LEFT JOINs, so that is harmless.
func algorithmCodeForAtRest(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case a == "":
		return ""
	case strings.HasPrefix(a, "AES-256"), strings.HasPrefix(a, "AES256"):
		return "AES256"
	case strings.HasPrefix(a, "AES-128"), strings.HasPrefix(a, "AES128"):
		return "AES128"
	case strings.HasPrefix(a, "AES-192"), strings.HasPrefix(a, "AES192"):
		return "AES192"
	default:
		return ""
	}
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func boolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// upsertCryptoApplicationSQL is the only production INSERT into
// crypto_applications. Idempotent on the natural key
// (tenant_id, resource_identifier, encryption_context) — a re-discovery of the
// same bucket updates its posture in place rather than accumulating a row per
// run. first_discovered_at is preserved; last_verified_at moves.
const upsertCryptoApplicationSQL = `
	INSERT INTO crypto_applications (
		tenant_id, asset_id, resource_type, resource_identifier, resource_name,
		encryption_context, algorithm_id, configuration_source, configuration_data,
		discovery_method, confidence_score, risk_score,
		first_discovered_at, last_verified_at, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5,
		'at_rest',
		(SELECT id FROM algorithms WHERE code ILIKE $6 ORDER BY code LIMIT 1),
		$7, $8::jsonb,
		'cloud_api', $9, $10,
		NOW(), NOW(), NOW(), NOW()
	)
	ON CONFLICT (tenant_id, resource_identifier, encryption_context) WHERE deleted_at IS NULL
	DO UPDATE SET
		asset_id             = COALESCE(EXCLUDED.asset_id, crypto_applications.asset_id),
		resource_type        = EXCLUDED.resource_type,
		resource_name        = EXCLUDED.resource_name,
		algorithm_id         = COALESCE(EXCLUDED.algorithm_id, crypto_applications.algorithm_id),
		configuration_source = EXCLUDED.configuration_source,
		configuration_data   = EXCLUDED.configuration_data,
		discovery_method     = EXCLUDED.discovery_method,
		confidence_score     = EXCLUDED.confidence_score,
		risk_score           = EXCLUDED.risk_score,
		last_verified_at     = NOW(),
		updated_at           = NOW()`

// produceAtRestApplication derives (or refreshes) the crypto_applications row
// for an at-rest cloud resource. Best-effort by design, exactly like the key
// producer: a failure is logged and swallowed so it can never fail ingest of
// the rest of a batch.
func (s *AssetService) produceAtRestApplication(tenantID, assetID uuid.UUID, p atRestPosture) {
	config := map[string]interface{}{
		"encrypted":             p.Encrypted,
		"encryption_determined": p.Determined,
		"encryption_type":       p.EncryptionType,
		"algorithm":             p.Algorithm,
		"kms_key_id":            p.KMSKeyID,
		"key_manager":           p.KeyManager,
		"cloud_provider":        p.CloudProvider,
		"cloud_region":          p.CloudRegion,
	}
	if p.EncryptionError != "" {
		config["encryption_error"] = p.EncryptionError
	}
	if len(p.AdditionalDetail) > 0 {
		config["additional_detail"] = p.AdditionalDetail
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		log.Printf("[AssetService] Warning: failed to marshal at-rest posture for %s: %v", p.ResourceIdentifier, err)
		return
	}

	var assetArg interface{}
	if assetID != uuid.Nil {
		assetArg = assetID
	}

	// RLS-scoped write over crypto_applications.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(
			upsertCryptoApplicationSQL,
			tenantID, assetArg, p.ResourceType, p.ResourceIdentifier, p.ResourceName,
			algorithmCodeForAtRest(p.Algorithm), "cloud_api", string(configJSON),
			p.confidence(), p.riskScore(),
		)
		if e != nil {
			return fmt.Errorf("upsert crypto_application: %w", e)
		}
		return nil
	}); err != nil {
		log.Printf("[AssetService] Warning: failed to produce at-rest posture for %s (asset %s): %v",
			p.ResourceIdentifier, assetID, err)
	}
}
