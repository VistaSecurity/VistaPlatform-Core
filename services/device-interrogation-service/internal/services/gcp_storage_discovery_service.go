package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// DiscoverGCPStorageBuckets discovers at-rest encryption configuration for Cloud
// Storage buckets, mirroring the AWS S3 path. Every GCS bucket is encrypted at
// rest with AES-256; the distinction we surface is Google-managed default keys
// vs a customer-managed CMEK (defaultKmsKeyName set). Returns device records in
// the same shape as DiscoverS3BucketEncryption so downstream processing is
// identical across clouds.
func (s *StorageEncryptionService) DiscoverGCPStorageBuckets(ctx context.Context, tenantID uuid.UUID, gcpCli *gcpclient.Client) ([]models.Device, error) {
	buckets, err := gcpCli.ListStorageBuckets(ctx)
	if err != nil {
		return nil, err
	}

	var devices []models.Device
	for _, b := range buckets {
		finding := gcpBucketToFinding(b)

		vendor := "Google Cloud"
		hostname := b.Name
		devices = append(devices, models.Device{
			ID:               uuid.New(),
			TenantID:         tenantID,
			DeviceType:       "gcp_storage_bucket",
			Vendor:           &vendor,
			Hostname:         &hostname,
			DiscoveryMethod:  "cloud_api",
			ConnectionStatus: "discovered",
			Metadata: models.JSONB{
				"arn":               finding.ResourceARN,
				"region":            finding.Region,
				"encrypted":         finding.Encrypted,
				"encryption_type":   finding.EncryptionType,
				"algorithm":         finding.Algorithm,
				"kms_key_id":        finding.KMSKeyID,
				"resource_type":     "gcs_bucket",
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

// gcpBucketToFinding maps a Cloud Storage bucket to a provider-neutral storage
// encryption finding. GCS always encrypts at rest with AES-256; a non-empty
// defaultKmsKeyName marks a customer-managed CMEK, otherwise Google-managed.
func gcpBucketToFinding(b gcpclient.StorageBucket) StorageEncryptionFinding {
	finding := StorageEncryptionFinding{
		ResourceType: "gcs_bucket",
		ResourceName: b.Name,
		ResourceARN:  "gs://" + b.Name,
		Region:       b.Location,
		Encrypted:    true,
		Algorithm:    "AES-256",
	}
	if b.Encryption != nil && b.Encryption.DefaultKmsKeyName != "" {
		finding.EncryptionType = "cmek"
		finding.KMSKeyID = b.Encryption.DefaultKmsKeyName
	} else {
		finding.EncryptionType = "google-managed"
	}
	finding.AdditionalDetail = map[string]interface{}{
		"storage_class": b.StorageClass,
		"time_created":  b.TimeCreated,
	}
	return finding
}
