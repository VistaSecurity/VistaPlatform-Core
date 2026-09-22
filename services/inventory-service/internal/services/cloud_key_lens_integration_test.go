package services

// REACHABILITY proof for cloud KMS keys: a key discovered through a cloud
// integration must be visible at Inventory → Keys, not just stored somewhere.
//
// The bug this closes: discovery wrote to `kms_keys`, a second key inventory
// parallel to the first-class `keys` table the Keys lens reads, with nothing
// joining them and one reader — an /experimental/kms-keys endpoint that no
// frontend calls. A discovered key was therefore invisible.
//
// These tests drive the REAL read path (ListKeys / GetKeyByID — the queries
// behind GET /keys, which is what the lens calls) over rows the REAL producer
// wrote. Delete the UpsertCloudKeys call and they fail; make ListKeys filter
// these rows out and they fail.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newCloudKeySvc(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return &AssetService{db: db}, db, testdb.NewTenant(t, raw)
}

func awsManagedS3Key() CloudKeyRecord {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	return CloudKeyRecord{
		Provider:        "aws",
		KeyID:           "11111111-2222-3333-4444-555555555555",
		KeyARN:          "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555",
		KeyName:         "alias/aws/s3",
		KeySpec:         "SYMMETRIC_DEFAULT",
		KeyUsage:        "ENCRYPT_DECRYPT",
		KeyState:        "Enabled",
		KeyManager:      "AWS", // the key that used to be DISCARDED
		Origin:          "AWS_KMS",
		Region:          "us-east-1",
		AccountID:       "111122223333",
		CreationDate:    &created,
		RotationEnabled: true,
		Aliases:         []string{"alias/aws/s3"},
	}
}

// The headline: an AWS-MANAGED key reaches the lens, carrying its custody.
func TestIntegration_CloudKeys_AWSManagedKeyReachesKeysLens(t *testing.T) {
	svc, _, tenant := newCloudKeySvc(t)

	written, err := svc.UpsertCloudKeys(tenant, []CloudKeyRecord{awsManagedS3Key()})
	if err != nil {
		t.Fatalf("UpsertCloudKeys: %v", err)
	}
	if written != 1 {
		t.Fatalf("wrote %d keys, want 1", written)
	}

	// ListKeys is what GET /keys serves and what the Keys lens renders.
	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("the Keys lens shows %d keys, want 1 — a discovered key must be VISIBLE", len(keys))
	}
	k := keys[0]

	if k.KeyCustody == nil || *k.KeyCustody != "provider" {
		t.Errorf("key_custody = %v, want \"provider\" — an AWS-managed key is provider-managed, not custody-unknown", k.KeyCustody)
	}
	if k.ExternalRef == nil || *k.ExternalRef != awsManagedS3Key().KeyARN {
		t.Errorf("external_ref = %v, want the key ARN", k.ExternalRef)
	}
	if k.KeyType != "AES" {
		t.Errorf("key_type = %q, want AES", k.KeyType)
	}
	if k.SizeBits == nil || *k.SizeBits != 256 {
		t.Errorf("size_bits = %v, want 256", k.SizeBits)
	}
	if k.MaterialType != "secret-key" {
		t.Errorf("material_type = %q, want secret-key", k.MaterialType)
	}
	if k.State != "active" {
		t.Errorf("state = %q, want active (KMS Enabled)", k.State)
	}
	// algorithm_id must resolve against the CATALOGUE — the single source of
	// crypto assessment — so the lens's Algorithm column is a citation, not a
	// hardcoded string. algorithm_ref is the joined algorithms.name.
	if k.AlgorithmRef == nil || *k.AlgorithmRef != "AES-256" {
		t.Errorf("algorithm_ref = %v, want the catalogue's AES-256 row", k.AlgorithmRef)
	}
	if k.SecuredBy == nil || *k.SecuredBy != "AWS KMS" {
		t.Errorf("secured_by = %v, want \"AWS KMS\"", k.SecuredBy)
	}
	if k.Provenance == nil || *k.Provenance != "cloud-kms:aws" {
		t.Errorf("provenance = %v, want cloud-kms:aws", k.Provenance)
	}
	if k.Metadata["region"] != "us-east-1" || k.Metadata["account_id"] != "111122223333" {
		t.Errorf("metadata lost the cloud coordinates: %v", k.Metadata)
	}
	if k.Metadata["rotation_enabled"] != true {
		t.Errorf("metadata rotation_enabled = %v, want true", k.Metadata["rotation_enabled"])
	}

	// NEVER fabricated: a symmetric CMK exports no public material, so there is
	// nothing to fingerprint. Storing a stand-in would be a claim about key
	// bytes we have never seen.
	if k.PublicFingerprint != nil {
		t.Errorf("public_fingerprint = %v, want nil — a KMS key has no exportable public material", k.PublicFingerprint)
	}
	if k.JWKThumbprint != nil {
		t.Errorf("jwk_thumbprint = %v, want nil", k.JWKThumbprint)
	}
	// Rotation posture is known; the rotation DATE is not.
	if k.RotatedAt != nil {
		t.Errorf("rotated_at = %v, want nil — rotation_enabled does not say WHEN", k.RotatedAt)
	}

	// The single-key read the drawer uses must agree.
	one, err := svc.GetKeyByID(tenant, k.ID)
	if err != nil {
		t.Fatalf("GetKeyByID: %v", err)
	}
	if one.KeyCustody == nil || *one.KeyCustody != "provider" {
		t.Errorf("drawer read lost custody: %v", one.KeyCustody)
	}
}

// Re-discovery converges on one row rather than accumulating duplicates, and a
// changed state is picked up.
func TestIntegration_CloudKeys_RediscoveryIsIdempotent(t *testing.T) {
	svc, _, tenant := newCloudKeySvc(t)

	rec := awsManagedS3Key()
	if _, err := svc.UpsertCloudKeys(tenant, []CloudKeyRecord{rec}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	rec.KeyState = "PendingDeletion"
	if _, err := svc.UpsertCloudKeys(tenant, []CloudKeyRecord{rec}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("re-discovery produced %d rows, want 1 — (tenant, external_ref) is the dedup identity", len(keys))
	}
	if keys[0].State != "deactivated" {
		t.Errorf("state = %q, want deactivated (KMS PendingDeletion)", keys[0].State)
	}
	if keys[0].StateReason == nil || *keys[0].StateReason != "AWS KMS key state: PendingDeletion" {
		t.Errorf("state_reason = %v, want the provider's own wording", keys[0].StateReason)
	}
}

// A customer-managed asymmetric key: the other custody, and the mapping that
// has to reach the catalogue by size.
func TestIntegration_CloudKeys_CustomerManagedAsymmetricKey(t *testing.T) {
	svc, _, tenant := newCloudKeySvc(t)

	_, err := svc.UpsertCloudKeys(tenant, []CloudKeyRecord{{
		Provider:   "aws",
		KeyID:      "cmk-1",
		KeyARN:     "arn:aws:kms:eu-west-1:111122223333:key/cmk-1",
		KeySpec:    "RSA_4096",
		KeyUsage:   "SIGN_VERIFY",
		KeyState:   "Enabled",
		KeyManager: "CUSTOMER",
		Origin:     "AWS_CLOUDHSM",
	}})
	if err != nil {
		t.Fatalf("UpsertCloudKeys: %v", err)
	}

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.KeyCustody == nil || *k.KeyCustody != "customer" {
		t.Errorf("key_custody = %v, want customer", k.KeyCustody)
	}
	if k.KeyType != "RSA" || k.SizeBits == nil || *k.SizeBits != 4096 {
		t.Errorf("key_type/size = %q/%v, want RSA/4096", k.KeyType, k.SizeBits)
	}
	if k.MaterialType != "private-key" {
		t.Errorf("material_type = %q, want private-key", k.MaterialType)
	}
	if k.AlgorithmRef == nil || *k.AlgorithmRef != "RSA 4096-bit" {
		t.Errorf("algorithm_ref = %v, want the catalogue's RSA-4096 row", k.AlgorithmRef)
	}
	if len(k.KeyUsage) != 2 || k.KeyUsage[0] != "sign" || k.KeyUsage[1] != "verify" {
		t.Errorf("key_usage = %v, want [sign verify]", k.KeyUsage)
	}
	if k.SecuredBy == nil || *k.SecuredBy != "AWS CloudHSM key store" {
		t.Errorf("secured_by = %v, want the CloudHSM wording", k.SecuredBy)
	}
}

// An unrecognised provider state must land as NULL rather than 'active', and a
// spec the catalogue has no row for must leave algorithm_id unresolved rather
// than borrow one.
func TestIntegration_CloudKeys_UnknownsStayUnknown(t *testing.T) {
	svc, _, tenant := newCloudKeySvc(t)

	_, err := svc.UpsertCloudKeys(tenant, []CloudKeyRecord{{
		Provider:   "aws",
		KeyID:      "hmac-1",
		KeyARN:     "arn:aws:kms:us-east-1:111122223333:key/hmac-1",
		KeySpec:    "HMAC_256",
		KeyUsage:   "GENERATE_VERIFY_MAC",
		KeyState:   "SomeFutureState",
		KeyManager: "WhoKnows",
	}})
	if err != nil {
		t.Fatalf("UpsertCloudKeys: %v", err)
	}

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.State != "" {
		t.Errorf("state = %q, want empty (NULL) — an unrecognised provider state is not 'active'", k.State)
	}
	if k.StateReason == nil || *k.StateReason != "AWS KMS key state: SomeFutureState" {
		t.Errorf("state_reason = %v, want the raw provider state recorded", k.StateReason)
	}
	if k.KeyCustody != nil {
		t.Errorf("key_custody = %v, want nil — an unrecognised manager is not a custody answer", k.KeyCustody)
	}
	if k.AlgorithmRef != nil {
		t.Errorf("algorithm_ref = %v, want nil — the catalogue has no row that assesses a standalone HMAC key", k.AlgorithmRef)
	}
	if k.SizeBits == nil || *k.SizeBits != 256 {
		t.Errorf("size_bits = %v, want 256 — the spec DOES carry a size", k.SizeBits)
	}
}

// Cloud keys and certificate-derived keys share the table without colliding:
// the cloud dedup index is partial on external_ref, so many certificate keys
// (external_ref NULL) coexist with it.
func TestIntegration_CloudKeys_CoexistWithCertificateKeys(t *testing.T) {
	svc, db, tenant := newCloudKeySvc(t)

	for _, fp := range []string{"aa11", "bb22"} {
		if _, err := db.Exec(`
			INSERT INTO keys (tenant_id, key_type, public_fingerprint, material_type, state, provenance)
			VALUES ($1, 'RSA', $2, 'public-key', 'active', 'certificate')`, tenant, fp); err != nil {
			t.Fatalf("insert certificate key: %v", err)
		}
	}
	if _, err := svc.UpsertCloudKeys(tenant, []CloudKeyRecord{awsManagedS3Key()}); err != nil {
		t.Fatalf("UpsertCloudKeys: %v", err)
	}

	keys, err := svc.ListKeys(tenant)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("the Keys lens shows %d keys, want 3 (2 certificate + 1 cloud)", len(keys))
	}
	cloud := 0
	for _, k := range keys {
		if k.ExternalRef != nil {
			cloud++
			if k.KeyCustody == nil {
				t.Error("a cloud key reached the lens without custody")
			}
		} else if k.KeyCustody != nil {
			t.Errorf("a certificate-derived key carries custody %v — custody is a cloud attribute, not a default", k.KeyCustody)
		}
	}
	if cloud != 1 {
		t.Errorf("found %d cloud keys, want 1", cloud)
	}
}
