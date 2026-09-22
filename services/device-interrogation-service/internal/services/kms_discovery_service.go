package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// KMSDiscoveryService discovers encryption keys from cloud KMS providers
type KMSDiscoveryService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used for the AWS
	// integration lookup (by id, may be a shared platform integration). The
	// kms_keys write runs under the known tenantID via WithTenantTx.
	bypassDB  *sql.DB
	masterKey string
	// keyPublisher lands discovered keys in the first-class key inventory
	// (Inventory → Keys). nil disables that hop — `kms_keys` is still written,
	// which is what happens when the mTLS client cannot be built. Tests
	// substitute a recorder via SetCloudKeyPublisher.
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

// StoreKMSKeyFindings stores discovered KMS keys into the database for the given
// provider ("aws", "gcp", "azure"). The kms_keys table is keyed by
// (tenant_id, provider, key_id), so providers coexist in one table.
func (s *KMSDiscoveryService) StoreKMSKeyFindings(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	provider string,
	findings []KMSKeyFinding,
) error {
	query := `
		INSERT INTO kms_keys (
			tenant_id, integration_id, provider, key_id, key_arn, key_name,
			description, key_spec, key_usage, key_size, key_state,
			creation_date, rotation_enabled, rotation_period_days,
			origin, key_manager, multi_region,
			region, account_id, metadata, discovery_method,
			first_discovered_at, last_verified_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14,
			$15, $16, $17,
			$18, $19, $20, 'cloud_api',
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id, provider, key_id) WHERE deleted_at IS NULL
		DO UPDATE SET
			key_state = EXCLUDED.key_state,
			rotation_enabled = EXCLUDED.rotation_enabled,
			rotation_period_days = EXCLUDED.rotation_period_days,
			metadata = EXCLUDED.metadata,
			last_verified_at = NOW(),
			updated_at = NOW()
	`

	for _, f := range findings {
		keyName := f.KeyID
		if len(f.AliasNames) > 0 {
			keyName = f.AliasNames[0]
		}

		keySize := keySpecToSize(f.KeySpec)

		meta := map[string]interface{}{
			"signing_algorithms":    f.SigningAlgorithms,
			"encryption_algorithms": f.EncryptionAlgorithms,
			"aliases":               f.AliasNames,
		}
		metadataBytes, err := json.Marshal(meta)
		if err != nil {
			log.Printf("Warning: failed to marshal KMS metadata for key %s: %v", f.KeyID, err)
			continue
		}
		metadata := string(metadataBytes)

		// RLS-scoped write on `kms_keys` under the known tenantID.
		err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, query,
				tenantID, integrationID, provider, f.KeyID, f.KeyARN, keyName,
				f.Description, f.KeySpec, f.KeyUsage, keySize, f.KeyState,
				f.CreationDate, f.RotationEnabled, f.RotationPeriodDays,
				f.Origin, f.KeyManager, f.MultiRegion,
				f.Region, f.AccountID, metadata,
			)
			return e
		})
		if err != nil {
			log.Printf("Warning: failed to store KMS key %s: %v", f.KeyID, err)
		}
	}

	// Then land the same keys in the FIRST-CLASS key inventory, which is the
	// only one a person can see. `kms_keys` above is a parallel table whose one
	// reader is an experimental endpoint no UI calls; without this hop a
	// discovered key is invisible no matter how well it was discovered.
	//
	// Deliberately after the kms_keys write and non-fatal: publishing is how
	// the key becomes VISIBLE, not how it is stored, so an inventory-service
	// that is down must not lose the discovery.
	s.publishToKeyInventory(ctx, tenantID, integrationID, provider, findings)

	return nil
}

// publishToKeyInventory hands the findings to inventory-service's internal
// cloud-key intake. Failures are logged, never returned: see StoreKMSKeyFindings.
func (s *KMSDiscoveryService) publishToKeyInventory(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	provider string,
	findings []KMSKeyFinding,
) {
	if s.keyPublisher == nil || len(findings) == 0 {
		return
	}
	records := cloudKeyRecordsFrom(provider, integrationID, findings)
	written, err := s.keyPublisher.PublishCloudKeys(ctx, tenantID, records)
	if err != nil {
		log.Printf("Warning: %s KMS keys stored but not published to key inventory: %v", provider, err)
		return
	}
	log.Printf("Published %d/%d %s KMS keys to the key inventory", written, len(records), provider)
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
