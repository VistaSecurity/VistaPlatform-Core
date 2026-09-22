package services

// Collection POLICY for cloud KMS discovery: every key is collected, and
// custody is recorded as an attribute rather than used as a filter.
//
// The regression this pins: describeKMSKey used to return an error for any key
// whose KeyManager was AWS ("skipping AWS-managed key"), so on an account whose
// keys are all AWS-managed — which is every account that has not created a CMK —
// KMS discovery found precisely nothing. Restore that skip and
// TestDescribeKMSKey_CollectsAWSManagedKeys fails: the describe returns an
// error and there is no finding to assert on.

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
)

// fakeKMS answers DescribeKey/GetKeyRotationStatus from a fixture, so the real
// describeKMSKey path runs without AWS.
type fakeKMS struct {
	meta     *kmstypes.KeyMetadata
	rotation bool
	rotErr   error
}

func (f *fakeKMS) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: f.meta}, nil
}

func (f *fakeKMS) GetKeyRotationStatus(_ context.Context, _ *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	if f.rotErr != nil {
		return nil, f.rotErr
	}
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.rotation}, nil
}

func awsManagedKeyMetadata() *kmstypes.KeyMetadata {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	return &kmstypes.KeyMetadata{
		KeyId:        aws.String("11111111-2222-3333-4444-555555555555"),
		Arn:          aws.String("arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"),
		KeyState:     kmstypes.KeyStateEnabled,
		KeyUsage:     kmstypes.KeyUsageTypeEncryptDecrypt,
		KeySpec:      kmstypes.KeySpecSymmetricDefault,
		KeyManager:   kmstypes.KeyManagerTypeAws,
		Origin:       kmstypes.OriginTypeAwsKms,
		Description:  aws.String("Default key that protects my S3 objects when no other key is defined"),
		Enabled:      true,
		CreationDate: &created,
	}
}

// The load-bearing test: an AWS-MANAGED key must come back as a finding.
func TestDescribeKMSKey_CollectsAWSManagedKeys(t *testing.T) {
	s := &KMSDiscoveryService{}
	f := &fakeKMS{meta: awsManagedKeyMetadata()}

	finding, err := s.describeKMSKey(context.Background(), f, "11111111-2222-3333-4444-555555555555", "us-east-1")
	if err != nil {
		t.Fatalf("an AWS-managed key must be COLLECTED, not discarded: %v", err)
	}
	if finding == nil {
		t.Fatal("describeKMSKey returned no finding for an AWS-managed key")
	}
	// Custody is recorded, not filtered on. This is the value that lets the key
	// land in inventory as provider-managed instead of custody-unknown.
	if finding.KeyManager != string(kmstypes.KeyManagerTypeAws) {
		t.Errorf("KeyManager = %q, want %q — custody must be recorded on the finding",
			finding.KeyManager, kmstypes.KeyManagerTypeAws)
	}
	if finding.KeySpec != string(kmstypes.KeySpecSymmetricDefault) {
		t.Errorf("KeySpec = %q, want SYMMETRIC_DEFAULT", finding.KeySpec)
	}
	if finding.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", finding.Region)
	}
}

func TestDescribeKMSKey_CollectsCustomerManagedKeys(t *testing.T) {
	meta := awsManagedKeyMetadata()
	meta.KeyManager = kmstypes.KeyManagerTypeCustomer
	meta.KeySpec = kmstypes.KeySpecRsa4096
	meta.KeyUsage = kmstypes.KeyUsageTypeSignVerify
	s := &KMSDiscoveryService{}

	finding, err := s.describeKMSKey(context.Background(), &fakeKMS{meta: meta, rotation: true}, "k", "eu-west-1")
	if err != nil {
		t.Fatalf("describeKMSKey: %v", err)
	}
	if finding.KeyManager != string(kmstypes.KeyManagerTypeCustomer) {
		t.Errorf("KeyManager = %q, want CUSTOMER", finding.KeyManager)
	}
	if !finding.RotationEnabled {
		t.Error("RotationEnabled = false, want true — the rotation read must still be wired")
	}
}

// cloudKeyRecordsFrom is the projection that crosses the wire to the key
// inventory. It must carry custody and the provider's identity, and must not
// invent a creation date.
func TestCloudKeyRecordsFrom_CarriesCustodyAndIdentity(t *testing.T) {
	integration := uuid.New()
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	records := cloudKeyRecordsFrom("aws", integration, []KMSKeyFinding{
		{
			KeyID:        "key-1",
			KeyARN:       "arn:aws:kms:us-east-1:111122223333:key/key-1",
			KeyState:     "Enabled",
			KeyUsage:     "ENCRYPT_DECRYPT",
			KeySpec:      "SYMMETRIC_DEFAULT",
			KeyManager:   "AWS",
			Origin:       "AWS_KMS",
			CreationDate: created,
			AliasNames:   []string{"alias/aws/s3"},
			Region:       "us-east-1",
			AccountID:    "111122223333",
		},
		// No creation date: the zero time must NOT become a timestamp.
		{KeyID: "key-2", KeyManager: "CUSTOMER"},
	})

	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 — every key is published, whoever manages it", len(records))
	}
	if records[0].KeyManager != "AWS" {
		t.Errorf("record[0].KeyManager = %q, want AWS", records[0].KeyManager)
	}
	if records[0].KeyName != "alias/aws/s3" {
		t.Errorf("record[0].KeyName = %q, want the first alias", records[0].KeyName)
	}
	if records[0].IntegrationID != integration.String() {
		t.Errorf("record[0].IntegrationID = %q, want %s", records[0].IntegrationID, integration)
	}
	if records[0].CreationDate == nil || !records[0].CreationDate.Equal(created) {
		t.Errorf("record[0].CreationDate = %v, want %v", records[0].CreationDate, created)
	}
	if records[1].CreationDate != nil {
		t.Errorf("record[1].CreationDate = %v, want nil — a zero time is not a date", records[1].CreationDate)
	}
	if records[0].Provider != "aws" || records[1].Provider != "aws" {
		t.Errorf("provider not stamped on every record: %q / %q", records[0].Provider, records[1].Provider)
	}
}
