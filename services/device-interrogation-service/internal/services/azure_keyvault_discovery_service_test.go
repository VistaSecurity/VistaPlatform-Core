package services

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
)

func TestMapAzureKeyToKeySpec(t *testing.T) {
	i32 := func(v int32) *int32 { return &v }
	cases := []struct {
		kty      string
		keySize  *int32
		curve    string
		wantSpec string
		wantSize int
	}{
		{"RSA", i32(2048), "", "RSA_2048", 2048},
		{"RSA-HSM", i32(4096), "", "RSA_4096", 4096},
		{"RSA", nil, "", "RSA_2048", 2048},
		{"EC", nil, "P-256", "ECC_NIST_P256", 256},
		{"EC-HSM", nil, "P-384", "ECC_NIST_P384", 384},
		{"EC", nil, "P-521", "ECC_NIST_P521", 521},
		{"EC", nil, "P-256K", "ECC_SECG_P256K1", 256},
		{"", nil, "", "", 0},
	}
	for _, tc := range cases {
		gotSpec := mapAzureKeyToKeySpec(tc.kty, tc.keySize, tc.curve)
		if gotSpec != tc.wantSpec {
			t.Errorf("mapAzureKeyToKeySpec(%q,%v,%q) = %q, want %q", tc.kty, tc.keySize, tc.curve, gotSpec, tc.wantSpec)
		}
		if gotSize := keySpecToSize(gotSpec); gotSize != tc.wantSize {
			t.Errorf("keySpecToSize(%q) = %d, want %d", gotSpec, gotSize, tc.wantSize)
		}
	}
}

func TestAzureKeyToFinding(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/keys/signing-key"
	kty := armkeyvault.JSONWebKeyTypeECHSM
	curve := armkeyvault.JSONWebKeyCurveNameP384
	enabled := false
	created := int64(1_700_000_000)
	key := &armkeyvault.Key{
		ID: &id,
		Properties: &armkeyvault.KeyProperties{
			Kty:            &kty,
			CurveName:      &curve,
			Attributes:     &armkeyvault.KeyAttributes{Enabled: &enabled, Created: &created},
			RotationPolicy: &armkeyvault.RotationPolicy{},
		},
	}

	f := azureKeyToFinding(key, "eastus", "sub-123")

	if f.KeyID != id || f.KeyARN != id {
		t.Errorf("KeyID/ARN = %q/%q, want %q", f.KeyID, f.KeyARN, id)
	}
	if f.KeySpec != "ECC_NIST_P384" {
		t.Errorf("KeySpec = %q, want ECC_NIST_P384", f.KeySpec)
	}
	if f.Origin != "HSM" {
		t.Errorf("Origin = %q, want HSM (EC-HSM key)", f.Origin)
	}
	if f.KeyState != "DISABLED" || f.Enabled {
		t.Errorf("state = %q enabled=%v, want DISABLED/false", f.KeyState, f.Enabled)
	}
	if f.KeyManager != "CUSTOMER" || f.Region != "eastus" || f.AccountID != "sub-123" {
		t.Errorf("manager/region/account = %q/%q/%q", f.KeyManager, f.Region, f.AccountID)
	}
	if !f.RotationEnabled {
		t.Error("RotationEnabled should be true when a rotation policy is present")
	}
	if f.CreationDate.IsZero() {
		t.Error("CreationDate should be derived from the unix Created attribute")
	}
}
