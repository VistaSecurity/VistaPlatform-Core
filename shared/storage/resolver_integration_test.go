package storage_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	"github.com/vistasecurity/vistaplatform/shared/storage"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The master key only has to be a valid input to encryption.NewService; the row
// is written and read back inside this test.
const testMasterKey = "integration-test-master-key-0123456789"

// TestIntegration_GetAWSCredentials_ReadsConfigColumn proves the S3 credential
// lookup runs against a column platform_integrations actually has.
//
// GetAWSCredentials used to select `encrypted_config`, a column that appears
// nowhere in the DDL and nowhere in the writer — admin-service stores the
// per-field-encrypted map in `config` jsonb. Every call therefore failed with
// `column "encrypted_config" does not exist`, which is why S3 artifact storage
// could never activate on any install however it was configured. A pure unit
// test cannot catch this: only a real Postgres knows which columns exist.
//
// Mutation check: rename the column back to `encrypted_config` in
// resolver.go and this test fails on the query.
func TestIntegration_GetAWSCredentials_ReadsConfigColumn(t *testing.T) {
	db := testdb.Connect(t)
	ctx := context.Background()

	encSvc, err := encryption.NewService(testMasterKey)
	if err != nil {
		t.Fatalf("encryption.NewService: %v", err)
	}

	// Write the row exactly as admin-service's IntegrationService does:
	// sensitive fields encrypted individually, the whole map into `config`.
	encAccessKey, err := encSvc.Encrypt("AKIAINTEGRATIONTEST")
	if err != nil {
		t.Fatalf("encrypt access key: %v", err)
	}
	encSecret, err := encSvc.Encrypt("integration-test-secret-access-key")
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	configJSON, err := json.Marshal(map[string]string{
		"access_key_id":     encAccessKey,
		"secret_access_key": encSecret,
		"region":            "us-east-1",
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	integrationID := uuid.New()
	_, err = db.ExecContext(ctx, `
		INSERT INTO platform_integrations
			(id, integration_type, integration_name, provider, config, is_active)
		VALUES ($1, 'aws', $2, 'cloud', $3, true)`,
		integrationID, "storage-resolver-test-"+integrationID.String()[:8], configJSON)
	if err != nil {
		t.Fatalf("insert platform_integrations: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM platform_integrations WHERE id = $1`, integrationID)
	})

	provider := storage.NewDatabaseIntegrationProvider(db, encSvc)

	creds, err := provider.GetAWSCredentials(ctx, integrationID)
	if err != nil {
		t.Fatalf("GetAWSCredentials: %v", err)
	}
	if creds.AccessKeyID != "AKIAINTEGRATIONTEST" {
		t.Errorf("AccessKeyID = %q, want the decrypted key", creds.AccessKeyID)
	}
	if creds.SecretAccessKey != "integration-test-secret-access-key" {
		t.Errorf("SecretAccessKey = %q, want the decrypted secret", creds.SecretAccessKey)
	}
	if creds.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", creds.Region)
	}

	// A soft-deleted integration must stop handing out live credentials.
	if _, err := db.ExecContext(ctx,
		`UPDATE platform_integrations SET deleted_at = now() WHERE id = $1`, integrationID); err != nil {
		t.Fatalf("soft-delete integration: %v", err)
	}
	if _, err := provider.GetAWSCredentials(ctx, integrationID); err == nil {
		t.Error("GetAWSCredentials returned credentials for a soft-deleted integration")
	} else if !strings.Contains(err.Error(), "integration not found") {
		t.Errorf("error = %v, want 'integration not found'", err)
	}
}
