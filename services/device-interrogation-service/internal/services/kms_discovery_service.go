package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
)

// KMSDiscoveryService discovers encryption keys from cloud KMS providers
type KMSDiscoveryService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used for the AWS
	// integration lookup (by id, may be a shared platform integration).
	bypassDB  *sql.DB
	masterKey string
	// keyPublisher lands discovered keys in the key inventory (Inventory →
	// Keys), their only destination. nil when the mTLS client cannot be built,
	// which PublishKMSKeyFindings reports as an error. Tests substitute a
	// recorder via SetCloudKeyPublisher.
	keyPublisher CloudKeyPublisher
}

// SetCloudKeyPublisher overrides where discovered keys are published. Tests
// use it; production takes the env-derived publisher from the constructor.
func (s *KMSDiscoveryService) SetCloudKeyPublisher(p CloudKeyPublisher) {
	s.keyPublisher = p
}

// NewKMSDiscoveryService creates a new KMS discovery service. db is the
// RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass)
// connection for the integration lookup. Pre-flip both handles resolve to the
// same connection.
func NewKMSDiscoveryService(db, bypassDB *sql.DB, masterKey string) *KMSDiscoveryService {
	return &KMSDiscoveryService{
		db:           db,
		bypassDB:     bypassDB,
		masterKey:    masterKey,
		keyPublisher: NewInventoryCloudKeyPublisherFromEnv(),
	}
}

// KMSKeyFinding represents a discovered KMS key
type KMSKeyFinding struct {
	KeyID                string
	KeyARN               string
	KeyState             string
	KeyUsage             string
	KeySpec              string
	KeyManager           string
	Origin               string
	CreationDate         time.Time
	Description          string
	Enabled              bool
	MultiRegion          bool
	RotationEnabled      bool
	RotationPeriodDays   int
	SigningAlgorithms    []string
	EncryptionAlgorithms []string
	AliasNames           []string
	Region               string
	AccountID            string
}

// DiscoverAWSKMSKeys discovers all KMS keys in the given AWS regions.
// If existingClient is non-nil, it is used instead of creating a new client (same credentials as cloud discovery).
func (s *KMSDiscoveryService) DiscoverAWSKMSKeys(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	regions []string,
	existingClient *awsclient.Client,
) ([]KMSKeyFinding, error) {
	var client *awsclient.Client
	var err error
	if existingClient != nil {
		client = existingClient
	} else {
		if _, err := authorizeCloudIntegration(ctx, s.bypassDB, tenantID, integrationID, "aws"); err != nil {
			return nil, fmt.Errorf("AWS integration not authorized: %w", err)
		}

		client, err = awsclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS client: %w", err)
		}
	}

	if len(regions) == 0 {
		regions = []string{client.GetRegion()}
	}

	var allFindings []KMSKeyFinding
	var regionErrs []error

	for _, region := range regions {
		findings, err := s.discoverKMSKeysInRegion(ctx, client, region)
		if err != nil {
			// Returned, not only logged ( slice E). This `continue` was
			// the deepest of the three swallow sites: a region that denied
			// kms:ListKeys produced no findings and no error, so the caller —
			// and the stored job result — reported "0 keys" with
			// `success: true`. "There are no keys" and "we were not allowed to
			// look" are different answers.
			log.Printf("Warning: KMS discovery failed in %s: %v", region, err)
			regionErrs = append(regionErrs, fmt.Errorf("%s: %w", region, err))
			continue
		}
		for i := range findings {
			findings[i].AccountID = client.GetAccountID()
		}
		allFindings = append(allFindings, findings...)
	}

	// Findings AND error: whatever the working regions produced is still
	// returned, so one bad region does not discard the rest.
	return allFindings, errors.Join(regionErrs...)
}

// discoverKMSKeysInRegion discovers KMS keys in a specific region
func (s *KMSDiscoveryService) discoverKMSKeysInRegion(
	ctx context.Context,
	client *awsclient.Client,
	region string,
) ([]KMSKeyFinding, error) {
	// Create a region-specific KMS client
	cfg := client.GetConfig()
	cfg.Region = region
	kmsClient := kms.NewFromConfig(cfg)

	var findings []KMSKeyFinding
	var marker *string

	for {
		listOutput, err := kmsClient.ListKeys(ctx, &kms.ListKeysInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list KMS keys: %w", err)
		}

		for _, keyEntry := range listOutput.Keys {
			finding, err := s.describeKMSKey(ctx, kmsClient, *keyEntry.KeyId, region)
			if err != nil {
				log.Printf("Warning: failed to describe KMS key %s: %v", *keyEntry.KeyId, err)
				continue
			}
			findings = append(findings, *finding)
		}

		if !listOutput.Truncated {
			break
		}
		marker = listOutput.NextMarker
	}

	// Fetch aliases and map to keys
	aliases, err := s.listAliases(ctx, kmsClient)
	if err == nil {
		for i := range findings {
			for _, alias := range aliases {
				if alias.targetKeyID == findings[i].KeyID {
					findings[i].AliasNames = append(findings[i].AliasNames, alias.name)
				}
			}
		}
	}

	return findings, nil
}

// kmsKeyDescriber is the slice of the AWS KMS client describeKMSKey uses.
// *kms.Client satisfies it; the tests pass a fake, which is what lets the
// collection POLICY below be driven rather than eyeballed.
type kmsKeyDescriber interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// describeKMSKey gets detailed information about a single KMS key.
//
// EVERY key is collected, including AWS-managed ones (aws/s3, aws/ebs, …).
// Custody is an ATTRIBUTE — recorded on the finding as KeyManager and carried
// into inventory as `keys.key_custody` — not a filter to discard on. A bucket
// encrypted under SSE-S3 is a materially different posture from one under a
// customer-managed CMK, and the protection ladder in the Data Protection lens
// exists to say so; dropping the AWS-managed keys threw away the only input
// that could populate it and guaranteed "custody unknown" for everything AWS
// holds. (It also meant an account whose keys are ALL AWS-managed discovered
// exactly nothing, which is what happens on a default account.)
func (s *KMSDiscoveryService) describeKMSKey(
	ctx context.Context,
	kmsClient kmsKeyDescriber,
	keyID string,
	region string,
) (*KMSKeyFinding, error) {
	describeOutput, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe key: %w", err)
	}

	key := describeOutput.KeyMetadata
	if key == nil {
		return nil, fmt.Errorf("describe key %s: no key metadata in response", keyID)
	}

	finding := &KMSKeyFinding{
		KeyID:       aws.ToString(key.KeyId),
		KeyARN:      aws.ToString(key.Arn),
		KeyState:    string(key.KeyState),
		KeyUsage:    string(key.KeyUsage),
		KeySpec:     string(key.KeySpec),
		KeyManager:  string(key.KeyManager),
		Origin:      string(key.Origin),
		Description: aws.ToString(key.Description),
		Enabled:     key.Enabled,
		MultiRegion: key.MultiRegion != nil && *key.MultiRegion,
		Region:      region,
	}

	if key.CreationDate != nil {
		finding.CreationDate = *key.CreationDate
	}

	// Get signing algorithms
	for _, alg := range key.SigningAlgorithms {
		finding.SigningAlgorithms = append(finding.SigningAlgorithms, string(alg))
	}

	// Get encryption algorithms
	for _, alg := range key.EncryptionAlgorithms {
		finding.EncryptionAlgorithms = append(finding.EncryptionAlgorithms, string(alg))
	}

	// Check rotation status
	rotationOutput, err := kmsClient.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyID),
	})
	if err == nil {
		finding.RotationEnabled = rotationOutput.KeyRotationEnabled
		if rotationOutput.RotationPeriodInDays != nil {
			finding.RotationPeriodDays = int(*rotationOutput.RotationPeriodInDays)
		}
	}

	return finding, nil
}

type kmsAlias struct {
	name        string
	targetKeyID string
}

// listAliases fetches all key aliases
func (s *KMSDiscoveryService) listAliases(ctx context.Context, kmsClient *kms.Client) ([]kmsAlias, error) {
	var aliases []kmsAlias
	var marker *string

	for {
		output, err := kmsClient.ListAliases(ctx, &kms.ListAliasesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		for _, alias := range output.Aliases {
			if alias.TargetKeyId != nil {
				aliases = append(aliases, kmsAlias{
					name:        aws.ToString(alias.AliasName),
					targetKeyID: aws.ToString(alias.TargetKeyId),
				})
			}
		}

		if !output.Truncated {
			break
		}
		marker = output.NextMarker
	}

	return aliases, nil
}

// MapKeySpecToAlgorithm maps an AWS KMS key spec to the algorithm name used in the algorithms table
func MapKeySpecToAlgorithm(keySpec string) string {
	spec := strings.ToUpper(keySpec)
	switch {
	case spec == "SYMMETRIC_DEFAULT":
		return "AES-256"
	case strings.HasPrefix(spec, "RSA_2048"):
		return "RSA-2048"
	case strings.HasPrefix(spec, "RSA_3072"):
		return "RSA-3072"
	case strings.HasPrefix(spec, "RSA_4096"):
		return "RSA-4096"
	case spec == "ECC_NIST_P256":
		return "ECC-P256"
	case spec == "ECC_NIST_P384":
		return "ECC-P384"
	case spec == "ECC_NIST_P521":
		return "ECC-P521"
	case spec == "ECC_SECG_P256K1":
		return "ECC-SECP256K1"
	case strings.HasPrefix(spec, "HMAC"):
		return "HMAC-SHA256"
	case strings.HasPrefix(spec, "SM2"):
		return "SM2"
	default:
		return keySpec
	}
}

// PublishKMSKeyFindings lands discovered keys for the given provider ("aws",
// "gcp", "azure") in the key inventory, through inventory-service's internal
// cloud-key intake (POST /api/v1/inventory-service/keys/cloud). That `keys` row
// — what Inventory → Keys shows — is the key's ONE home ( decision D3).
//
// It used to be one of three. The same keys were also written to the
// `kms_keys` table, whose only readers are the /experimental/kms-keys and
// /experimental/stats endpoints that no UI calls, and emitted into
// sensor_discoveries as at-rest devices (see keyInventoryDeviceTypes). Neither
// is written any more; `kms_keys` is left in place for a later drop.
//
// Because nothing else holds the keys now, a publish that does not land is an
// ERROR, returned to the collector so the job's per-type outcome says so. It
// used to be a log line, which was tolerable only while `kms_keys` kept a copy.
// The next run re-publishes: the intake upserts on the provider's key identity.
//
// METADATA ONLY: cloudKeyRecordsFrom carries the provider's description of
// each key, never key material, which a KMS key does not release anyway.
func (s *KMSDiscoveryService) PublishKMSKeyFindings(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	provider string,
	findings []KMSKeyFinding,
) error {
	if len(findings) == 0 {
		return nil
	}
	if s.keyPublisher == nil {
		// NewInventoryCloudKeyPublisherFromEnv logged why at construction.
		return fmt.Errorf("%d %s KMS keys found but not recorded: the key inventory client is not configured", len(findings), provider)
	}
	records := cloudKeyRecordsFrom(provider, integrationID, findings)
	written, err := s.keyPublisher.PublishCloudKeys(ctx, tenantID, records)
	if err != nil {
		return fmt.Errorf("%d %s KMS keys found but not recorded in the key inventory: %w", len(records), provider, err)
	}
	log.Printf("Published %d/%d %s KMS keys to the key inventory", written, len(records), provider)
	return nil
}

// keySpecToSize maps AWS KMS key spec to key size in bits
func keySpecToSize(spec string) int {
	s := strings.ToUpper(spec)
	switch {
	case s == "SYMMETRIC_DEFAULT":
		return 256
	case strings.Contains(s, "2048"):
		return 2048
	case strings.Contains(s, "3072"):
		return 3072
	case strings.Contains(s, "4096"):
		return 4096
	case strings.Contains(s, "P256"), strings.Contains(s, "P256K1"):
		return 256
	case strings.Contains(s, "P384"):
		return 384
	case strings.Contains(s, "P521"):
		return 521
	case strings.HasPrefix(s, "HMAC_224"):
		return 224
	case strings.HasPrefix(s, "HMAC_256"):
		return 256
	case strings.HasPrefix(s, "HMAC_384"):
		return 384
	case strings.HasPrefix(s, "HMAC_512"):
		return 512
	default:
		return 0
	}
}
