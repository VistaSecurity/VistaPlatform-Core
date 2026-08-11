package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// gap 5: security_incident_webhooks.secret is the HMAC-SHA256 key used to
// sign outbound incident webhooks. It is RECOVERABLE — the receiver needs the
// same bytes to verify — so it must be encrypted at rest, not hashed.
//
// The table has no writer in the codebase (rows are inserted out of band), so
// what these tests prove is the read contract: a plaintext row keeps working,
// an encrypted row decrypts, and a tagged row that will not decrypt is dropped
// rather than delivered with a signature made from ciphertext.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

const webhookITMasterKey = "integration-test-master-key-32byt"

func seedIncidentWebhook(t *testing.T, db *sql.DB, name, secret string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO security_incident_webhooks (id, name, url, secret, events, enabled)
		VALUES ($1, $2, 'https://receiver.example.com/hook', $3, '["incident.created"]'::jsonb, true)`,
		id, name, secret); err != nil {
		t.Fatalf("seed incident webhook: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM security_incident_webhooks WHERE id = $1`, id) })
	return id
}

func TestIntegration_IncidentWebhook_ReadsBothProvenances(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	svc, err := NewIncidentWebhookService(db, webhookITMasterKey)
	if err != nil {
		t.Fatalf("NewIncidentWebhookService: %v", err)
	}
	cipher, err := credentials.NewCipher("test", webhookITMasterKey, credentials.Policy{})
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	const plainSecret = "legacy-plaintext-signing-secret"
	const encSecret = "encrypted-signing-secret"
	encStored, err := cipher.EncryptValue(encSecret)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}

	plainName := "plain-" + uuid.NewString()[:8]
	encName := "enc-" + uuid.NewString()[:8]
	seedIncidentWebhook(t, db, plainName, plainSecret)
	seedIncidentWebhook(t, db, encName, encStored)

	got, err := svc.getWebhookConfigs(context.Background(), "incident.created")
	if err != nil {
		t.Fatalf("getWebhookConfigs: %v", err)
	}
	bySecretName := map[string]string{}
	for _, w := range got {
		bySecretName[w.Name] = w.Secret
	}
	if bySecretName[plainName] != plainSecret {
		t.Errorf("legacy plaintext secret: got %q, want %q", bySecretName[plainName], plainSecret)
	}
	if bySecretName[encName] != encSecret {
		t.Errorf("encrypted secret: got %q, want %q", bySecretName[encName], encSecret)
	}
	// The stored bytes for the encrypted row must not be the secret.
	var raw string
	if err := db.QueryRow(`SELECT secret FROM security_incident_webhooks WHERE name = $1`, encName).Scan(&raw); err != nil {
		t.Fatalf("read raw secret: %v", err)
	}
	if raw == encSecret {
		t.Fatalf("secret is at rest in the clear: %q", raw)
	}
}

// TestIntegration_IncidentWebhook_UndecryptableIsSkipped: signing with
// ciphertext would produce a signature the receiver rejects, which reads as a
// receiver bug. Dropping the webhook and logging is the honest failure.
func TestIntegration_IncidentWebhook_UndecryptableIsSkipped(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	writer, err := credentials.NewCipher("test", webhookITMasterKey, credentials.Policy{})
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	stored, err := writer.EncryptValue("secret-under-the-other-key")
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	name := "wrongkey-" + uuid.NewString()[:8]
	seedIncidentWebhook(t, db, name, stored)

	reader, err := NewIncidentWebhookService(db, "a-totally-different-master-key!!")
	if err != nil {
		t.Fatalf("NewIncidentWebhookService: %v", err)
	}
	got, err := reader.getWebhookConfigs(context.Background(), "incident.created")
	if err != nil {
		t.Fatalf("getWebhookConfigs: %v", err)
	}
	for _, w := range got {
		if w.Name == name {
			t.Fatalf("an undecryptable webhook was returned for delivery with secret %q", w.Secret)
		}
	}
}
