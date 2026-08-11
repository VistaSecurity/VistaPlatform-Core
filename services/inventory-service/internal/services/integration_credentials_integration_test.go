package services

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// public.integrations.auth_config is gap 6, and the sharpest one: TWO
// services in different modules write this column. Before this change
// inventory-service stored plaintext while admin-service's MSP writer stored
// (untagged) ciphertext, so a tenant's credentials were protected or not
// depending purely on which endpoint they hit — and neither service could read
// the other's rows.
//
// So these tests cover three provenances in one column:
//
//	1. legacy PLAINTEXT   — written by old inventory-service
//	2. legacy BARE ciphertext (no enc:v1: tag) — written by old admin-service
//	3. current TAGGED ciphertext — written by either service now
//
// All three must read correctly, and 1 and 2 must converge on 3 as rows are
// re-saved.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

const integrationITMasterKey = "integration-test-master-key-32byt"

func itAssetService(t *testing.T, db *sql.DB, masterKey string) *AssetService {
	t.Helper()
	t.Setenv("ENCRYPTION_MASTER_KEY", masterKey)
	return &AssetService{
		db:                &database.DB{DB: sqlx.NewDb(db, "postgres")},
		integrationCipher: newIntegrationCipher(),
	}
}

func rawAuthConfig(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT auth_config::text FROM integrations WHERE id = $1`, id).Scan(&raw); err != nil {
		t.Fatalf("read raw auth_config: %v", err)
	}
	return raw
}

// TestIntegration_IntegrationAuthConfig_CiphertextIsAtRest is the base claim
// for the writer that used to store plaintext.
func TestIntegration_IntegrationAuthConfig_CiphertextIsAtRest(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAssetService(t, db, integrationITMasterKey)

	const token = "jira-api-token-SUPERSECRET-42"
	created, err := svc.CreateIntegration(tenant, Integration{
		Name: "jira", Type: "jira", BaseURL: "https://jira.example.com", AuthType: "api_token",
		AuthConfig: map[string]interface{}{
			"api_token": token,
			"username":  "svc-account",
		},
		IsEnabled: true,
	})
	if err != nil {
		t.Fatalf("CreateIntegration: %v", err)
	}

	raw := rawAuthConfig(t, db, created.ID)
	if strings.Contains(raw, token) || strings.Contains(raw, "SUPERSECRET") {
		t.Fatalf("api_token stored in the clear: %s", raw)
	}
	if !strings.Contains(raw, credentials.Prefix) {
		t.Fatalf("stored auth_config carries no %q tag: %s", credentials.Prefix, raw)
	}
	// username is deliberately NOT a credential (see the policy's comment) —
	// it is displayed in listings and encrypting it would be a UX regression
	// with no security gain, since its password is encrypted.
	if !strings.Contains(raw, "svc-account") {
		t.Fatalf("username should stay readable: %s", raw)
	}

	list, err := svc.ListIntegrations(tenant)
	if err != nil {
		t.Fatalf("ListIntegrations: %v", err)
	}
	if got := findIntegration(t, list, created.ID).AuthConfig["api_token"]; got != token {
		t.Fatalf("round trip lost api_token: %v", got)
	}
}

// TestIntegration_IntegrationAuthConfig_ThreeProvenancesAllRead is the
// cross-writer proof. It seeds one row of each provenance and asserts a single
// ListIntegrations call decodes all three.
func TestIntegration_IntegrationAuthConfig_ThreeProvenancesAllRead(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAssetService(t, db, integrationITMasterKey)

	const plainToken = "legacy-plaintext-token"
	const bareToken = "legacy-bare-ciphertext-token"
	const taggedToken = "current-tagged-token"

	// (1) legacy plaintext, as old inventory-service wrote it
	plainID := seedIntegration(t, db, tenant, `{"api_token":"`+plainToken+`","username":"u1"}`)

	// (2) legacy BARE ciphertext, exactly as old admin-service wrote it:
	//     encryption.Service.Encrypt with no enc:v1: tag.
	enc, err := encryption.NewService(integrationITMasterKey)
	if err != nil {
		t.Fatalf("encryption.NewService: %v", err)
	}
	bareCT, err := enc.Encrypt(bareToken)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	bareBlob, _ := json.Marshal(map[string]string{"api_token": bareCT, "username": "u2"})
	bareID := seedIntegration(t, db, tenant, string(bareBlob))

	// (3) current tagged ciphertext, written through the service
	tagged, err := svc.CreateIntegration(tenant, Integration{
		Name: "tagged", Type: "servicenow", BaseURL: "https://sn.example.com", AuthType: "api_token",
		AuthConfig: map[string]interface{}{"api_token": taggedToken, "username": "u3"},
		IsEnabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateIntegration: %v", err)
	}

	list, err := svc.ListIntegrations(tenant)
	if err != nil {
		t.Fatalf("ListIntegrations: %v", err)
	}
	for _, tc := range []struct {
		id   uuid.UUID
		want string
		what string
	}{
		{plainID, plainToken, "legacy plaintext"},
		{bareID, bareToken, "legacy bare ciphertext (old admin-service writer)"},
		{tagged.ID, taggedToken, "current tagged ciphertext"},
	} {
		if got := findIntegration(t, list, tc.id).AuthConfig["api_token"]; got != tc.want {
			t.Errorf("%s row read back as %v, want %q", tc.what, got, tc.want)
		}
	}
}

// TestIntegration_IntegrationAuthConfig_LegacyRowsMigrateOnSave: both legacy
// provenances converge on tagged ciphertext once the row is saved again.
func TestIntegration_IntegrationAuthConfig_LegacyRowsMigrateOnSave(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAssetService(t, db, integrationITMasterKey)

	const plainToken = "migrate-me-plaintext"
	plainID := seedIntegration(t, db, tenant, `{"api_token":"`+plainToken+`","username":"u1"}`)

	list, err := svc.ListIntegrations(tenant)
	if err != nil {
		t.Fatalf("ListIntegrations: %v", err)
	}
	row := findIntegration(t, list, plainID)

	// A save that changes only the display name still migrates the credential.
	row.Name = "renamed"
	if _, err := svc.UpdateIntegration(tenant, plainID, row); err != nil {
		t.Fatalf("UpdateIntegration: %v", err)
	}

	raw := rawAuthConfig(t, db, plainID)
	if strings.Contains(raw, plainToken) {
		t.Fatalf("legacy plaintext survived the save: %s", raw)
	}
	if !strings.Contains(raw, credentials.Prefix) {
		t.Fatalf("migrated row carries no %q tag: %s", credentials.Prefix, raw)
	}

	list, err = svc.ListIntegrations(tenant)
	if err != nil {
		t.Fatalf("ListIntegrations: %v", err)
	}
	if got := findIntegration(t, list, plainID).AuthConfig["api_token"]; got != plainToken {
		t.Fatalf("migration corrupted the credential: %v", got)
	}
}

// TestIntegration_IntegrationAuthConfig_ReadableByTheOtherWriter closes
// requirement (d) in the direction the modules allow. inventory-service cannot
// import admin-service's msp package, so this constructs the cipher exactly as
// NewTenantIntegrationService does — same exported policy, same option — and
// asserts it decodes a row this service wrote. If the two ever diverge, they
// diverge by editing credentials.IntegrationAuthConfigPolicy, which the shared
// unit tests pin.
func TestIntegration_IntegrationAuthConfig_ReadableByTheOtherWriter(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAssetService(t, db, integrationITMasterKey)

	const secret = "cross-writer-client-secret"
	created, err := svc.CreateIntegration(tenant, Integration{
		Name: "cross", Type: "oauth", BaseURL: "https://x.example.com", AuthType: "oauth2",
		AuthConfig: map[string]interface{}{"client_secret": secret, "access_token": "at-123"},
		IsEnabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateIntegration: %v", err)
	}

	peer, err := credentials.NewCipher(
		"integrations.auth_config",
		integrationITMasterKey,
		credentials.IntegrationAuthConfigPolicy,
		credentials.WithLegacyUnprefixedCiphertext(),
	)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	var raw []byte
	if err := db.QueryRow(`SELECT auth_config FROM integrations WHERE id = $1`, created.ID).Scan(&raw); err != nil {
		t.Fatalf("read raw auth_config: %v", err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	decoded, err := peer.DecryptMap(stored)
	if err != nil {
		t.Fatalf("the other writer of this column could not decrypt our row: %v", err)
	}
	if decoded["client_secret"] != secret {
		t.Fatalf("cross-writer decode mismatch on client_secret: %v", decoded["client_secret"])
	}
	if decoded["access_token"] != "at-123" {
		t.Fatalf("cross-writer decode mismatch on access_token: %v", decoded["access_token"])
	}
}

func seedIntegration(t *testing.T, db *sql.DB, tenant uuid.UUID, authConfig string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO integrations (id, tenant_id, name, type, base_url, auth_type, auth_config, mapping_config, is_enabled)
		VALUES ($1, $2, $3, 'jira', 'https://legacy.example.com', 'api_token', $4::jsonb, '{}'::jsonb, true)`,
		id, tenant, "seeded-"+id.String()[:8], authConfig); err != nil {
		t.Fatalf("seed integration row: %v", err)
	}
	return id
}

func findIntegration(t *testing.T, list []Integration, id uuid.UUID) Integration {
	t.Helper()
	for _, in := range list {
		if in.ID == id {
			return in
		}
	}
	t.Fatalf("integration %s not found among %d rows", id, len(list))
	return Integration{}
}
