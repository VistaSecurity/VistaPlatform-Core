package services

import (
	"testing"

	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

func TestMapGCPKMSAlgorithmToKeySpec(t *testing.T) {
	cases := []struct {
		alg      string
		wantSpec string
		wantSize int // via keySpecToSize on the mapped spec
	}{
		{"GOOGLE_SYMMETRIC_ENCRYPTION", "SYMMETRIC_DEFAULT", 256},
		{"RSA_SIGN_PSS_2048_SHA256", "RSA_2048", 2048},
		{"RSA_DECRYPT_OAEP_3072_SHA256", "RSA_3072", 3072},
		{"RSA_SIGN_PKCS1_4096_SHA512", "RSA_4096", 4096},
		{"EC_SIGN_P256_SHA256", "ECC_NIST_P256", 256},
		{"EC_SIGN_P384_SHA384", "ECC_NIST_P384", 384},
		{"EC_SIGN_SECP256K1_SHA256", "ECC_SECG_P256K1", 256},
		{"HMAC_SHA256", "HMAC_256", 256},
		{"HMAC_SHA512", "HMAC_512", 512},
		{"", "", 0},
	}
	for _, tc := range cases {
		gotSpec := mapGCPKMSAlgorithmToKeySpec(tc.alg)
		if gotSpec != tc.wantSpec {
			t.Errorf("mapGCPKMSAlgorithmToKeySpec(%q) = %q, want %q", tc.alg, gotSpec, tc.wantSpec)
		}
		if gotSize := keySpecToSize(gotSpec); gotSize != tc.wantSize {
			t.Errorf("keySpecToSize(%q) = %d, want %d (alg %q)", gotSpec, gotSize, tc.wantSize, tc.alg)
		}
	}
}

func TestParseGCPRotationPeriod(t *testing.T) {
	cases := []struct {
		period      string
		wantEnabled bool
		wantDays    int
	}{
		{"7776000s", true, 90},
		{"86400s", true, 1},
		{"", false, 0},
		{"0s", false, 0},
		{"garbage", false, 0},
	}
	for _, tc := range cases {
		enabled, days := parseGCPRotationPeriod(tc.period)
		if enabled != tc.wantEnabled || days != tc.wantDays {
			t.Errorf("parseGCPRotationPeriod(%q) = (%v, %d), want (%v, %d)", tc.period, enabled, days, tc.wantEnabled, tc.wantDays)
		}
	}
}

func TestGCPCryptoKeyToFinding(t *testing.T) {
	key := gcpclient.KMSCryptoKey{
		Name:           "projects/p/locations/us-east1/keyRings/kr/cryptoKeys/signing-key",
		Purpose:        "ASYMMETRIC_SIGN",
		RotationPeriod: "7776000s",
		CreateTime:     "2026-01-02T15:04:05Z",
		VersionTemplate: &gcpclient.KMSCryptoKeyVersionTpl{
			ProtectionLevel: "HSM",
			Algorithm:       "EC_SIGN_P384_SHA384",
		},
		Primary: &gcpclient.KMSCryptoKeyVersion{State: "ENABLED"},
	}

	f := gcpCryptoKeyToFinding(key, "us-east1", "my-project")

	if f.KeyID != key.Name || f.KeyARN != key.Name {
		t.Errorf("KeyID/KeyARN = %q/%q, want %q", f.KeyID, f.KeyARN, key.Name)
	}
	if f.KeySpec != "ECC_NIST_P384" {
		t.Errorf("KeySpec = %q, want ECC_NIST_P384", f.KeySpec)
	}
	if f.Origin != "HSM" {
		t.Errorf("Origin = %q, want HSM (protection level)", f.Origin)
	}
	if f.KeyManager != "CUSTOMER" {
		t.Errorf("KeyManager = %q, want CUSTOMER", f.KeyManager)
	}
	if !f.RotationEnabled || f.RotationPeriodDays != 90 {
		t.Errorf("rotation = (%v, %d), want (true, 90)", f.RotationEnabled, f.RotationPeriodDays)
	}
	if f.Region != "us-east1" || f.AccountID != "my-project" {
		t.Errorf("Region/AccountID = %q/%q", f.Region, f.AccountID)
	}
	if len(f.SigningAlgorithms) != 1 || f.SigningAlgorithms[0] != "EC_SIGN_P384_SHA384" {
		t.Errorf("SigningAlgorithms = %v, want [EC_SIGN_P384_SHA384]", f.SigningAlgorithms)
	}
	if f.CreationDate.IsZero() {
		t.Error("CreationDate should be parsed from RFC3339 createTime")
	}
}
