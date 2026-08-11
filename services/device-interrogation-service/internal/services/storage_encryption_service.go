package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// StorageEncryptionService discovers encryption configuration on cloud storage resources
type StorageEncryptionService struct {
	db *sql.DB
	// bypassDB is carried for symmetry with the other cloud sub-services; this
	// service builds Device structs in memory and performs no direct Postgres
	// access (persistence happens via CloudDiscoveryService.insertDevice).
	bypassDB  *sql.DB
	masterKey string
}

// NewStorageEncryptionService creates a new storage encryption discovery service.
func NewStorageEncryptionService(db, bypassDB *sql.DB, masterKey string) *StorageEncryptionService {
	return &StorageEncryptionService{
		db:        db,
		bypassDB:  bypassDB,
		masterKey: masterKey,
	}
}

// StorageEncryptionFinding represents a single storage encryption discovery
type StorageEncryptionFinding struct {
	ResourceType     string                 `json:"resource_type"` // "s3_bucket", "rds_instance"
	ResourceName     string                 `json:"resource_name"` // bucket name, DB identifier
	ResourceARN      string                 `json:"resource_arn"`
	Region           string                 `json:"region"`
	Encrypted        bool                   `json:"encrypted"`
	Algorithm        string                 `json:"algorithm"` // AES256, aws:kms, etc.
	KMSKeyID         string                 `json:"kms_key_id,omitempty"`
	EncryptionType   string                 `json:"encryption_type"` // sse-s3, sse-kms, sse-kms-dsse, tde, none
	AdditionalDetail map[string]interface{} `json:"additional_detail,omitempty"`
}

// DiscoverS3BucketEncryption discovers encryption configuration for S3 buckets
func (s *StorageEncryptionService) DiscoverS3BucketEncryption(ctx context.Context, tenantID uuid.UUID, awsClient *awsclient.Client) ([]models.Device, error) {
	cfg := awsClient.GetConfig()
	s3Client := s3.NewFromConfig(cfg)

	// List all buckets
	listOutput, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	var devices []models.Device

	for _, bucket := range listOutput.Buckets {
		bucketName := aws.ToString(bucket.Name)

		finding := StorageEncryptionFinding{
			ResourceType: "s3_bucket",
			ResourceName: bucketName,
			ResourceARN:  fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			Region:       awsClient.GetRegion(),
		}

		// Get bucket encryption configuration
		encOutput, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// No encryption configuration means default encryption (AES256 SSE-S3 since Jan 2023)
			finding.Encrypted = true
			finding.Algorithm = "AES-256"
			finding.EncryptionType = "sse-s3-default"
			log.Printf("S3 bucket %s: using default SSE-S3 encryption", bucketName)
		} else if encOutput.ServerSideEncryptionConfiguration != nil {
			for _, rule := range encOutput.ServerSideEncryptionConfiguration.Rules {
				if rule.ApplyServerSideEncryptionByDefault != nil {
					finding.Encrypted = true
					defaults := rule.ApplyServerSideEncryptionByDefault

					switch defaults.SSEAlgorithm {
					case s3types.ServerSideEncryptionAes256:
						finding.Algorithm = "AES-256"
						finding.EncryptionType = "sse-s3"
					case s3types.ServerSideEncryptionAwsKms:
						finding.Algorithm = "AES-256-KMS"
						finding.EncryptionType = "sse-kms"
						if defaults.KMSMasterKeyID != nil {
							finding.KMSKeyID = aws.ToString(defaults.KMSMasterKeyID)
						}
					case s3types.ServerSideEncryptionAwsKmsDsse:
						finding.Algorithm = "AES-256-KMS-DSSE"
						finding.EncryptionType = "sse-kms-dsse"
						if defaults.KMSMasterKeyID != nil {
							finding.KMSKeyID = aws.ToString(defaults.KMSMasterKeyID)
						}
					}

					if rule.BucketKeyEnabled != nil {
						finding.AdditionalDetail = map[string]interface{}{
							"bucket_key_enabled": *rule.BucketKeyEnabled,
						}
					}
					break // only process first rule
				}
			}
		}

		vendor := "AWS"
		hostname := bucketName
		device := models.Device{
			ID:               uuid.New(),
			TenantID:         tenantID,
			DeviceType:       "aws_s3_bucket",
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
				"resource_type":     "s3_bucket",
				"additional_detail": finding.AdditionalDetail,
				"discovery_method":  "cloud_api",
				"discovered_at":     time.Now().Format(time.RFC3339),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// DiscoverRDSEncryption discovers encryption configuration for RDS instances
func (s *StorageEncryptionService) DiscoverRDSEncryption(ctx context.Context, tenantID uuid.UUID, awsClient *awsclient.Client, regions []string) ([]models.Device, error) {
	var devices []models.Device

	for _, region := range regions {
		cfg := awsClient.GetConfig()
		cfg.Region = region
		rdsClient := rds.NewFromConfig(cfg)

		paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				log.Printf("Warning: failed to list RDS instances in %s: %v", region, err)
				break
			}

			for _, instance := range page.DBInstances {
				dbID := aws.ToString(instance.DBInstanceIdentifier)
				dbARN := aws.ToString(instance.DBInstanceArn)
				engine := aws.ToString(instance.Engine)
				engineVersion := aws.ToString(instance.EngineVersion)

				finding := StorageEncryptionFinding{
					ResourceType: "rds_instance",
					ResourceName: dbID,
					ResourceARN:  dbARN,
					Region:       region,
					Encrypted:    instance.StorageEncrypted != nil && *instance.StorageEncrypted,
				}

				if finding.Encrypted {
					finding.EncryptionType = "rds-storage-encryption"
					finding.Algorithm = "AES-256"
					if instance.KmsKeyId != nil {
						finding.KMSKeyID = aws.ToString(instance.KmsKeyId)
					}
				} else {
					finding.EncryptionType = "none"
				}

				finding.AdditionalDetail = map[string]interface{}{
					"engine":         engine,
					"engine_version": engineVersion,
					"instance_class": aws.ToString(instance.DBInstanceClass),
					"multi_az":       instance.MultiAZ != nil && *instance.MultiAZ,
				}

				// Check Performance Insights encryption
				if instance.PerformanceInsightsEnabled != nil && *instance.PerformanceInsightsEnabled {
					if instance.PerformanceInsightsKMSKeyId != nil {
						finding.AdditionalDetail["performance_insights_kms_key"] = aws.ToString(instance.PerformanceInsightsKMSKeyId)
					}
				}

				vendor := "AWS"
				hostname := dbID
				device := models.Device{
					ID:               uuid.New(),
					TenantID:         tenantID,
					DeviceType:       "aws_rds_instance",
					Vendor:           &vendor,
					Hostname:         &hostname,
					Model:            &engine,
					FirmwareVersion:  &engineVersion,
					DiscoveryMethod:  "cloud_api",
					ConnectionStatus: "discovered",
					Metadata: models.JSONB{
						"arn":               dbARN,
						"region":            region,
						"encrypted":         finding.Encrypted,
						"encryption_type":   finding.EncryptionType,
						"algorithm":         finding.Algorithm,
						"kms_key_id":        finding.KMSKeyID,
						"resource_type":     "rds_instance",
						"additional_detail": finding.AdditionalDetail,
						"discovery_method":  "cloud_api",
						"discovered_at":     time.Now().Format(time.RFC3339),
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				devices = append(devices, device)
			}
		}
	}

	return devices, nil
}
