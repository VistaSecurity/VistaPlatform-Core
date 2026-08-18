package services

import (
	"context"
	"database/sql"
	"errors"
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
	ResourceType string `json:"resource_type"` // "s3_bucket", "rds_instance"
	ResourceName string `json:"resource_name"` // bucket name, DB identifier
	ResourceARN  string `json:"resource_arn"`
	Region       string `json:"region"`
	Encrypted    bool   `json:"encrypted"`
	// EncryptionDetermined is false when we could not measure the encryption
	// posture at all (AccessDenied, throttling, any API failure). An
	// undetermined bucket is NOT a compliant bucket: per the platform's
	// "score 0 means NOT ASSESSED, not safe" rule, callers must render this
	// as unknown rather than as encrypted.
	EncryptionDetermined bool                   `json:"encryption_determined"`
	EncryptionError      string                 `json:"encryption_error,omitempty"`
	Algorithm            string                 `json:"algorithm"` // AES256, aws:kms, etc.
	KMSKeyID             string                 `json:"kms_key_id,omitempty"`
	EncryptionType       string                 `json:"encryption_type"` // sse-s3, sse-kms, sse-kms-dsse, tde, none
	AdditionalDetail     map[string]interface{} `json:"additional_detail,omitempty"`
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

		// ListBuckets is global and returns buckets from every region, but it
		// does not say which. Stamping every bucket with the integration's
		// default region put buckets in the wrong region (and therefore the
		// wrong cloud network segment). Resolve the bucket's home region.
		region := resolveBucketRegion(ctx, s3Client, bucketName, awsClient.GetRegion())

		finding := StorageEncryptionFinding{
			ResourceType: "s3_bucket",
			ResourceName: bucketName,
			ResourceARN:  fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			Region:       region,
		}

		// Get bucket encryption configuration
		encOutput, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// An error here is NOT evidence of encryption. The old code
			// assumed default SSE-S3 on any failure, so an AccessDenied — or
			// a throttle, or a network blip — was reported as a measured
			// encrypted bucket. Record it honestly as undetermined.
			//
			// The genuine "no bucket-level configuration" case is
			// ServerSideEncryptionConfigurationNotFoundError; since Jan 2023
			// such a bucket does get SSE-S3 by default, and that one case is
			// reported as such, flagged as an AWS default rather than an
			// explicit tenant configuration.
			if isNoEncryptionConfigurationError(err) {
				finding.Encrypted = true
				finding.EncryptionDetermined = true
				finding.Algorithm = "AES-256"
				finding.EncryptionType = "sse-s3-default"
				log.Printf("S3 bucket %s: no bucket-level configuration; AWS default SSE-S3 applies", bucketName)
			} else {
				finding.Encrypted = false
				finding.EncryptionDetermined = false
				finding.EncryptionType = "unknown"
				finding.Algorithm = ""
				finding.EncryptionError = err.Error()
				log.Printf("Warning: S3 bucket %s: could not determine encryption posture: %v", bucketName, err)
			}
		} else if encOutput.ServerSideEncryptionConfiguration != nil {
			for _, rule := range encOutput.ServerSideEncryptionConfiguration.Rules {
				if rule.ApplyServerSideEncryptionByDefault != nil {
					finding.Encrypted = true
					finding.EncryptionDetermined = true
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
				"arn":                   finding.ResourceARN,
				"region":                finding.Region,
				"encrypted":             finding.Encrypted,
				"encryption_determined": finding.EncryptionDetermined,
				"encryption_error":      finding.EncryptionError,
				"encryption_type":       finding.EncryptionType,
				"algorithm":             finding.Algorithm,
				"kms_key_id":            finding.KMSKeyID,
				"resource_type":         "s3_bucket",
				"additional_detail":     finding.AdditionalDetail,
				"discovery_method":      "cloud_api",
				"discovered_at":         time.Now().Format(time.RFC3339),
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
					// DescribeDBInstances returns StorageEncrypted
					// authoritatively; if we got the instance we measured it.
					EncryptionDetermined: true,
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

// resolveBucketRegion returns the bucket's home region.
//
// GetBucketLocation has two well-known quirks that make the raw response
// unusable as-is:
//   - us-east-1 is returned as an EMPTY LocationConstraint (the legacy
//     default), so "" means us-east-1 and NOT "unknown".
//   - eu-west-1 is returned as the legacy alias "EU".
//
// Cost: this is one extra API call per bucket. On an account with thousands of
// buckets that is thousands of calls per discovery run; S3 throttles well
// above that rate for this operation, but it is a real per-run cost and it
// requires the s3:GetBucketLocation IAM action. If the call fails (typically
// AccessDenied on a cross-account bucket) we fall back to the integration's
// default region, which is the pre-existing behaviour for every bucket.
func resolveBucketRegion(ctx context.Context, s3Client *s3.Client, bucketName, defaultRegion string) string {
	out, err := s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Printf("Warning: could not resolve region for S3 bucket %s (%v); falling back to %s", bucketName, err, defaultRegion)
		return defaultRegion
	}

	return normalizeBucketLocation(string(out.LocationConstraint))
}

// normalizeBucketLocation turns a raw S3 LocationConstraint into a region name.
// Split out from resolveBucketRegion so the two legacy special cases are
// testable without an S3 client.
func normalizeBucketLocation(constraint string) string {
	switch constraint {
	case "":
		// Legacy default. NOT "unknown" — us-east-1 buckets report empty.
		return "us-east-1"
	case "EU":
		// Legacy alias predating the eu-west-1 name.
		return "eu-west-1"
	default:
		return constraint
	}
}

// isNoEncryptionConfigurationError reports whether the GetBucketEncryption
// error is S3's "this bucket has no bucket-level encryption configuration"
// response, as opposed to a permission or transport failure. Only the former
// licenses the "AWS default SSE-S3 applies" conclusion.
func isNoEncryptionConfigurationError(err error) bool {
	if err == nil {
		return false
	}
	// Matched structurally rather than by importing smithy-go, which is only
	// an indirect dependency of this module. Every AWS SDK modelled error
	// implements ErrorCode().
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
	}
	return false
}
