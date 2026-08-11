package services

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// DiscoverGCPCloudSQLInstances discovers at-rest encryption configuration for
// Cloud SQL instances, mirroring the AWS RDS path. All Cloud SQL data is
// encrypted at rest with AES-256; we surface Google-managed vs customer-managed
// CMEK (diskEncryptionConfiguration.kmsKeyName). Returns device records in the
// same shape as DiscoverRDSEncryption.
func (s *StorageEncryptionService) DiscoverGCPCloudSQLInstances(ctx context.Context, tenantID uuid.UUID, gcpCli *gcpclient.Client) ([]models.Device, error) {
	instances, err := gcpCli.ListSQLInstances(ctx)
	if err != nil {
		return nil, err
	}

	var devices []models.Device
	for _, inst := range instances {
		finding := gcpSQLInstanceToFinding(inst)
		engine, _ := finding.AdditionalDetail["engine"].(string)

		vendor := "Google Cloud"
		hostname := inst.Name
		engineVal := engine
		dbVersion := inst.DatabaseVersion
		devices = append(devices, models.Device{
			ID:               uuid.New(),
			TenantID:         tenantID,
			DeviceType:       "gcp_cloudsql_instance",
			Vendor:           &vendor,
			Hostname:         &hostname,
			Model:            &engineVal,
			FirmwareVersion:  &dbVersion,
			DiscoveryMethod:  "cloud_api",
			ConnectionStatus: "discovered",
			Metadata: models.JSONB{
				"arn":               finding.ResourceARN,
				"region":            finding.Region,
				"encrypted":         finding.Encrypted,
				"encryption_type":   finding.EncryptionType,
				"algorithm":         finding.Algorithm,
				"kms_key_id":        finding.KMSKeyID,
				"resource_type":     "cloudsql_instance",
				"additional_detail": finding.AdditionalDetail,
				"discovery_method":  "cloud_api",
				"discovered_at":     time.Now().Format(time.RFC3339),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})
	}
	return devices, nil
}

// gcpSQLInstanceToFinding maps a Cloud SQL instance to a provider-neutral storage
// encryption finding. Cloud SQL always encrypts at rest with AES-256; a CMEK key
// (diskEncryptionConfiguration.kmsKeyName) marks customer-managed encryption.
func gcpSQLInstanceToFinding(inst gcpclient.SQLInstance) StorageEncryptionFinding {
	finding := StorageEncryptionFinding{
		ResourceType: "cloudsql_instance",
		ResourceName: inst.Name,
		ResourceARN:  "gcp:cloudsql:" + inst.Name,
		Region:       inst.Region,
		Encrypted:    true,
		Algorithm:    "AES-256",
	}
	if inst.DiskEncryptionConfiguration != nil && inst.DiskEncryptionConfiguration.KmsKeyName != "" {
		finding.EncryptionType = "cmek"
		finding.KMSKeyID = inst.DiskEncryptionConfiguration.KmsKeyName
	} else {
		finding.EncryptionType = "google-managed"
	}
	finding.AdditionalDetail = map[string]interface{}{
		"engine":           engineFromDatabaseVersion(inst.DatabaseVersion),
		"database_version": inst.DatabaseVersion,
		"instance_type":    inst.InstanceType,
		"backend_type":     inst.BackendType,
	}
	if inst.Settings != nil {
		finding.AdditionalDetail["tier"] = inst.Settings.Tier
	}
	return finding
}

// engineFromDatabaseVersion extracts a short engine name from a Cloud SQL
// databaseVersion enum (e.g. "POSTGRES_14" → "postgres", "SQLSERVER_2019_STANDARD"
// → "sqlserver").
func engineFromDatabaseVersion(v string) string {
	if v == "" {
		return ""
	}
	prefix := v
	if i := strings.Index(v, "_"); i >= 0 {
		prefix = v[:i]
	}
	return strings.ToLower(prefix)
}
