package services

// The Key Store asset of a discovered cloud KMS key ( WP6 F13, decision D3
// as amended).
//
// A cloud KMS key used to reach inventory twice: as a `keys` row through
// POST /keys/cloud (UpsertCloudKeys), and as an at-rest sensor_discoveries row
// that device-interrogation wrote, discovery-processor classified and
// rule-evaluated, and this service's IngestFindings turned into an
// endpoint-less `key_store` asset. The discovery queue no longer carries KMS
// rows. The key-inventory ingest creates or refreshes the Key Store asset
// itself, and does it by handing IngestFindings the SAME finding the old row
// became on the far side of the processor:
//
//   - the same identity: the provider's resource id (`arn` for AWS,
//     `cloud_resource_id` for Azure and GCP, exactly the keys the collector
//     wrote), under the tenant's platform-managed device-interrogation sensor
//     with `source: cloud_discovery` — which is what makes
//     cloudCollectorAuthoritative admit it as the cloud collector's
//     authoritative, active, api-channel listing, so an asset an earlier run
//     created MATCHES rather than being duplicated;
//   - the same class (`device_type` → key_store), name, region, account and
//     provider attributes, and the same cloud segment attribution;
//   - the same approval decision: the tenant's active auto-approval rules,
//     evaluated over the same projection and classification the processor
//     built for the row (a region-scoped key classifies into its cloud
//     segment, as classify-asset answered; a key with no region keeps the
//     unknown/private placeholder classification). Matched → `monitoring`,
//     otherwise `pending_approval`.
//
// One asset per key, as before: each key carries its own resource id.
//
// The `keys` row is NOT linked to the asset. The old path never linked them
// (the `keys` table has no asset reference), and this change keeps behaviour.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/approval"
)

// kmsKeyStoreConfidence is the confidence the old at-rest fallback row carried
// (device-interrogation's writeSensorDiscoveriesTx: 0.8 for a resource with no
// crypto configuration). Rules can read it (`confidence >= …`).
const kmsKeyStoreConfidence = 0.8

// kmsPlaceholderAddress is the address the old row carried: a key has none,
// and the writer stored the unspecified address. Kept so an address-reading
// rule answers exactly as it did.
const kmsPlaceholderAddress = "0.0.0.0"

// kmsKeyStoreDeviceType is the collector's device_type per provider — the
// value shared/assetclass maps to the key_store class.
func kmsKeyStoreDeviceType(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return "aws_kms"
	case "azure":
		return "azure_keyvault_key"
	case "gcp":
		return "gcp_kms_crypto_key"
	}
	return ""
}

// kmsKeyStoreName is the asset name the collector gave the key: the first
// alias (else the key id) for AWS, the last path segment of the key id for
// Azure and GCP.
func kmsKeyStoreName(r CloudKeyRecord) string {
	if strings.EqualFold(strings.TrimSpace(r.Provider), "aws") {
		if len(r.Aliases) > 0 && r.Aliases[0] != "" {
			return r.Aliases[0]
		}
		return r.KeyID
	}
	if i := strings.LastIndex(r.KeyID, "/"); i >= 0 && i < len(r.KeyID)-1 {
		return r.KeyID[i+1:]
	}
	return r.KeyID
}

// kmsKeyStoreResourceMetadata is the collector's device metadata for the key,
// key for key (device-interrogation kmsKeyDevices / keyStoreDeviceMetadata).
// It carries the resource id under the name identity reads, and posture
// fields only — a KMS key exports no key material and none is carried.
func kmsKeyStoreResourceMetadata(r CloudKeyRecord) map[string]interface{} {
	var created interface{}
	if r.CreationDate != nil && !r.CreationDate.IsZero() {
		created = r.CreationDate.UTC().Format(time.RFC3339Nano)
	}
	if strings.EqualFold(strings.TrimSpace(r.Provider), "aws") {
		var aliases interface{}
		if len(r.Aliases) > 0 {
			list := make([]interface{}, len(r.Aliases))
			for i, a := range r.Aliases {
				list[i] = a
			}
			aliases = list
		}
		return map[string]interface{}{
			"key_id":           r.KeyID,
			"arn":              r.KeyARN,
			"key_state":        r.KeyState,
			"key_usage":        r.KeyUsage,
			"key_spec":         r.KeySpec,
			"origin":           r.Origin,
			"rotation_enabled": r.RotationEnabled,
			"region":           r.Region,
			"creation_date":    created,
			"aliases":          aliases,
		}
	}
	accountKey := "project_id"
	if strings.EqualFold(strings.TrimSpace(r.Provider), "azure") {
		accountKey = "subscription_id"
	}
	return map[string]interface{}{
		"cloud_resource_id": r.KeyARN,
		"key_id":            r.KeyID,
		"resource_name":     r.KeyARN,
		"key_state":         r.KeyState,
		"key_usage":         r.KeyUsage,
		"key_spec":          r.KeySpec,
		"protection_level":  r.Origin,
		"rotation_enabled":  r.RotationEnabled,
		"location":          r.Region,
		accountKey:          r.AccountID,
		"creation_date":     created,
	}
}

// kmsKeyStoreEnvelope is the sensor_discoveries metadata envelope the old row
// carried (device-interrogation's fallback branch for an at-rest device). Its
// cloud_region is the device's `region` key, which only the AWS shape has — so
// Azure and GCP keys had no region, no cloud segment and no classify hint, and
// still have none.
func kmsKeyStoreEnvelope(r CloudKeyRecord) map[string]interface{} {
	region := ""
	if strings.EqualFold(strings.TrimSpace(r.Provider), "aws") {
		region = r.Region
	}
	env := map[string]interface{}{
		"discovery_method": "cloud_api",
		"cloud_provider":   strings.ToLower(strings.TrimSpace(r.Provider)),
		"cloud_region":     region,
		"device_type":      kmsKeyStoreDeviceType(r.Provider),
		"raw_metadata":     kmsKeyStoreResourceMetadata(r),
		"at_rest":          true,
	}
	if r.IntegrationID != "" {
		env["integration_id"] = r.IntegrationID
	}
	return env
}

// kmsKeyStoreFinding is the finding discovery-processor's converter made of
// the old row: the nested resource metadata promoted to the top level (outer
// envelope keys win), the source stamps, `source: cloud_discovery`, the
// `service` asset type, and the processor's ownership labels.
func kmsKeyStoreFinding(r CloudKeyRecord, sensorID uuid.UUID, observedAt time.Time, ownership, networkType string) IngestFinding {
	envelope := kmsKeyStoreEnvelope(r)
	raw := map[string]interface{}{}
	if nested, ok := envelope["raw_metadata"].(map[string]interface{}); ok {
		for k, v := range nested {
			raw[k] = v
		}
	}
	for k, v := range envelope {
		if k != "raw_metadata" {
			raw[k] = v
		}
	}
	sid := sensorID.String()
	raw["sensor_id"] = sid
	raw["confidence"] = kmsKeyStoreConfidence
	raw["timestamp"] = observedAt.UTC().Format(time.RFC3339Nano)
	raw["pqc_kex_detected"] = false
	raw["source"] = "cloud_discovery"
	raw["network_ownership"] = ownership
	raw["network_type"] = networkType
	// The collector named the key; nothing resolved the name.
	raw["dest_hostname_source_kind"] = "measured"

	name := kmsKeyStoreName(r)
	addr := kmsPlaceholderAddress
	port := 0
	f := IngestFinding{
		IPAddress:      &addr,
		Port:           &port,
		AssetType:      "service",
		Protocol:       "",
		SourceSensorID: &sid,
		RawData:        raw,
	}
	if name != "" {
		f.Hostname = &name
	}
	return f
}

// kmsKeyStoreClassification is the network classification discovery-processor
// computed for the old row: a key with a provider and region classified into
// that region's cloud segment (classify-asset's cloud branch, which is
// FindOrCreateCloudSegment); one without fell to the address branch, whose
// unspecified placeholder the processor then kept on the managed path as
// unknown/private (shouldKeepCloudPlaceholderManaged).
func (s *AssetService) kmsKeyStoreClassification(tenantID uuid.UUID, f IngestFinding) (*approval.Classification, error) {
	provider, _ := f.RawData["cloud_provider"].(string)
	region, _ := f.RawData["cloud_region"].(string)
	if s.networkSegmentService != nil && provider != "" && region != "" {
		seg, err := s.networkSegmentService.FindOrCreateCloudSegment(tenantID, provider, region, "", "production")
		if err != nil {
			return nil, fmt.Errorf("classify key store: %w", err)
		}
		if seg != nil {
			c := &approval.Classification{Ownership: "internal", Type: seg.NetworkType}
			if c.Type == "" {
				c.Type = "private"
			}
			id, name := seg.ID, seg.Name
			c.SegmentID, c.SegmentName = &id, &name
			return c, nil
		}
	}

	c := &approval.Classification{Ownership: "third_party", Type: NetworkTypeForAddress(kmsPlaceholderAddress)}
	if s.networkSegmentService != nil {
		seg, err := s.networkSegmentService.GetSegmentForIP(tenantID, f.IPAddress, f.Hostname)
		if err != nil {
			return nil, fmt.Errorf("classify key store: %w", err)
		}
		ownership, err := s.networkSegmentService.ClassifyAsset(tenantID, f.IPAddress, f.Hostname, nil)
		if err != nil {
			return nil, fmt.Errorf("classify key store: %w", err)
		}
		if ownership == "internal" {
			c.Ownership = "internal"
		}
		if seg != nil {
			id, name := seg.ID, seg.Name
			c.SegmentID, c.SegmentName = &id, &name
			if seg.NetworkType != "" {
				c.Type = seg.NetworkType
			}
		}
	}
	if c.Ownership == "third_party" {
		// A placeholder address is not a connection to anybody: the
		// processor kept such a cloud row managed.
		c.Ownership, c.Type = "unknown", "private"
	}
	return c, nil
}

// kmsKeyStoreApprovalInput is the rule-evaluation projection of the old row
// (SensorDiscovery.ApprovalInput().WithKind("crypto")).
func kmsKeyStoreApprovalInput(tenantID uuid.UUID, f IngestFinding, observedAt time.Time) (approval.Discovery, error) {
	envelope := map[string]interface{}{}
	for _, k := range []string{"discovery_method", "cloud_provider", "cloud_region", "device_type", "integration_id", "at_rest"} {
		if v, ok := f.RawData[k]; ok {
			envelope[k] = v
		}
	}
	meta, err := json.Marshal(envelope)
	if err != nil {
		return approval.Discovery{}, err
	}
	return approval.Discovery{
		TenantID:  tenantID,
		Metadata:  meta,
		Hostname:  derefString(f.Hostname),
		Address:   kmsPlaceholderAddress,
		FirstSeen: observedAt,
	}.WithConfidence(kmsKeyStoreConfidence).WithKind("crypto"), nil
}

// kmsPlatformCollectorSensor is the tenant's platform-managed
// device-interrogation sensor — the sensor the cloud collector's rows were
// written under, and the trust anchor cloudCollectorAuthoritative checks.
// Selected exactly as device-interrogation selected it.
func (s *AssetService) kmsPlatformCollectorSensor(tenantID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT id FROM sensors
			 WHERE tenant_id = $1 AND profile = 'device_interrogation' AND platform_managed
			   AND deleted_at IS NULL
			 ORDER BY created_at, id
			 LIMIT 1`, tenantID).Scan(&id)
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("no platform device-interrogation sensor for tenant %s: %w", tenantID, err)
	}
	return id, nil
}

// RecordCloudKeyStores creates or refreshes the Key Store asset of every
// record, through IngestFindings, and returns how many reached an asset
// decision. See the file comment for what "the same observation" means here.
func (s *AssetService) RecordCloudKeyStores(tenantID uuid.UUID, records []CloudKeyRecord) (int, error) {
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("key store record: tenant id is required")
	}
	if len(records) == 0 {
		return 0, nil
	}
	sensorID, err := s.kmsPlatformCollectorSensor(tenantID)
	if err != nil {
		return 0, err
	}
	evaluator := approval.NewService(s.db.DB.DB)
	rules, err := evaluator.GetActiveRulesForTenant(tenantID)
	if err != nil {
		return 0, fmt.Errorf("key store record: load auto-approval rules: %w", err)
	}

	observedAt := time.Now().UTC()
	byStatus := map[string][]IngestFinding{}
	var firstErr error
	for _, r := range records {
		if kmsKeyStoreDeviceType(r.Provider) == "" || strings.TrimSpace(r.KeyARN) == "" {
			// No class to give it, or no resource id to know it by next time:
			// creating an asset would mint a duplicate on every run.
			if firstErr == nil {
				firstErr = fmt.Errorf("key store record: key %q has no provider class or resource id", r.KeyID)
			}
			continue
		}
		f := kmsKeyStoreFinding(r, sensorID, observedAt, "", "")
		c, err := s.kmsKeyStoreClassification(tenantID, f)
		if err != nil {
			return 0, err
		}
		f.RawData["network_ownership"] = c.Ownership
		f.RawData["network_type"] = c.Type
		in, err := kmsKeyStoreApprovalInput(tenantID, f, observedAt)
		if err != nil {
			return 0, err
		}
		status := "pending_approval"
		if ok, _, evalErr := evaluator.EvaluateAutoApprovalWithRules(rules, in, c); evalErr == nil && ok {
			status = "monitoring"
		}
		byStatus[status] = append(byStatus[status], f)
	}

	recorded := 0
	for _, status := range []string{"monitoring", "pending_approval"} {
		findings := byStatus[status]
		if len(findings) == 0 {
			continue
		}
		report, err := s.IngestFindingsReport(tenantID, findings, status)
		if err != nil {
			return recorded, fmt.Errorf("key store record: %w", err)
		}
		recorded += report.Imported
	}
	return recorded, firstErr
}
