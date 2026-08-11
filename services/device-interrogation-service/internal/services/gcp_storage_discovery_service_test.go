package services

import (
	"testing"

	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

func TestGCPBucketToFinding(t *testing.T) {
	// Google-managed (no default KMS key).
	gm := gcpBucketToFinding(gcpclient.StorageBucket{Name: "logs", Location: "US", StorageClass: "STANDARD"})
	if !gm.Encrypted || gm.Algorithm != "AES-256" {
		t.Errorf("google-managed: encrypted/algorithm = %v/%q", gm.Encrypted, gm.Algorithm)
	}
	if gm.EncryptionType != "google-managed" {
		t.Errorf("EncryptionType = %q, want google-managed", gm.EncryptionType)
	}
	if gm.KMSKeyID != "" {
		t.Errorf("KMSKeyID = %q, want empty for google-managed", gm.KMSKeyID)
	}
	if gm.ResourceARN != "gs://logs" {
		t.Errorf("ResourceARN = %q, want gs://logs", gm.ResourceARN)
	}

	// CMEK (customer-managed key).
	kek := "projects/p/locations/us/keyRings/kr/cryptoKeys/bucket-key"
	cmek := gcpBucketToFinding(gcpclient.StorageBucket{
		Name:       "secure",
		Location:   "us-east1",
		Encryption: &gcpclient.StorageBucketEncryption{DefaultKmsKeyName: kek},
	})
	if cmek.EncryptionType != "cmek" {
		t.Errorf("EncryptionType = %q, want cmek", cmek.EncryptionType)
	}
	if cmek.KMSKeyID != kek {
		t.Errorf("KMSKeyID = %q, want %q", cmek.KMSKeyID, kek)
	}
}
