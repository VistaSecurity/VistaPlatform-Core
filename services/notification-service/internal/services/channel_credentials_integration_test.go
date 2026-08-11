package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// These tests exist because the interesting risk in was never the
// encryption — it was the MIGRATION. Six live stores already held plaintext
// rows, and a fix that encrypts new writes while breaking reads of old rows
// would be worse than the bug.
//
// So each test asserts on the RAW COLUMN BYTES as well as the round trip. An
// "encryption" that quietly returns its input passes a round-trip test
// perfectly; only reading the database catches it. See CLAUDE.md, "checks that
// report success while doing nothing".
//
// They skip unless TEST_DATABASE_URL is set — run `make test-integration-db`.

const itMasterKey = "integration-test-master-key-32byt"

func itChannelManager(t *testing.T, db *sql.DB) *ChannelManager {
	t.Helper()
	return NewChannelManager(sqlx.NewDb(db, "postgres"), &config.Config{EncryptionMasterKey: itMasterKey}, nil)
}

// rawChannelConfig reads the config column exactly as Postgres holds it,
// bypassing every layer of the service under test.
func rawChannelConfig(t *testing.T, db *sql.DB, channelID uuid.UUID) string {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT config::text FROM tenant_notification_channels WHERE id = $1`, channelID).Scan(&raw); err != nil {
		t.Fatalf("read raw config: %v", err)
	}
	return raw
}

// TestIntegration_NotificationChannel_CiphertextIsAtRest is the core claim:
// after a create through the service, the tenant's Slack webhook is NOT in the
// database in readable form, and comes back intact on read.
func TestIntegration_NotificationChannel_CiphertextIsAtRest(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	cm := itChannelManager(t, db)
	ctx := context.Background()

	const webhook = "https://hooks.slack.com/services/T000/B000/zzTOPSECRETzz"
	const bearer = "Bearer super-secret-token"

	created, err := cm.CreateTenantChannel(ctx, tenant, &models.CreateChannelRequest{
		ChannelName: "slack-prod",
		ChannelType: "slack",
		Enabled:     true,
		Config: map[string]interface{}{
			"webhook_url": webhook,
			"channel":     "#alerts",
			"headers":     map[string]interface{}{"Authorization": bearer},
		},
	}, nil)
	if err != nil {
		t.Fatalf("CreateTenantChannel: %v", err)
	}

	raw := rawChannelConfig(t, db, created.ID)
	if strings.Contains(raw, webhook) || strings.Contains(raw, "TOPSECRET") {
		t.Fatalf("webhook_url stored in the clear: %s", raw)
	}
	if strings.Contains(raw, bearer) || strings.Contains(raw, "super-secret-token") {
		t.Fatalf("header credential stored in the clear: %s", raw)
	}
	if !strings.Contains(raw, credentials.Prefix) {
		t.Fatalf("stored config carries no %q tag, so nothing was encrypted: %s", credentials.Prefix, raw)
	}
	// Non-credential fields must stay queryable.
	if !strings.Contains(raw, "#alerts") {
		t.Fatalf("non-credential field was encrypted too: %s", raw)
	}

	got, err := cm.GetTenantChannelByID(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("GetTenantChannelByID: %v", err)
	}
	if got.Config["webhook_url"] != webhook {
		t.Fatalf("round trip lost webhook_url: %v", got.Config["webhook_url"])
	}
	if got.Config["headers"].(map[string]interface{})["Authorization"] != bearer {
		t.Fatalf("round trip lost header: %v", got.Config["headers"])
	}
}

// TestIntegration_NotificationChannel_LegacyPlaintextRowMigrates is the
// migration proof: a row written before this change (plaintext) still reads
// correctly, and is encrypted the next time it is saved.
func TestIntegration_NotificationChannel_LegacyPlaintextRowMigrates(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	cm := itChannelManager(t, db)
	ctx := context.Background()

	const legacyWebhook = "https://hooks.slack.com/services/T111/B111/LEGACYPLAIN"
	legacyID := uuid.New()
	legacyConfig := `{"webhook_url":"` + legacyWebhook + `","channel":"#legacy"}`
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, 'legacy-slack', 'slack', $3::jsonb, true)`,
		legacyID, tenant, legacyConfig); err != nil {
		t.Fatalf("seed legacy plaintext row: %v", err)
	}

	// (a) the plaintext row still reads correctly
	got, err := cm.GetTenantChannelByID(ctx, tenant, legacyID)
	if err != nil {
		t.Fatalf("read legacy row: %v", err)
	}
	if got.Config["webhook_url"] != legacyWebhook {
		t.Fatalf("legacy plaintext row did not read back: %v", got.Config["webhook_url"])
	}

	// (b) it is encrypted on next save — here an update that does not even
	// touch the credential, which is the realistic case (a user renames the
	// channel and the row silently migrates).
	newName := "legacy-slack-renamed"
	if _, err := cm.UpdateTenantChannel(ctx, tenant, legacyID, &models.UpdateChannelRequest{ChannelName: &newName}, nil); err != nil {
		t.Fatalf("UpdateTenantChannel: %v", err)
	}

	raw := rawChannelConfig(t, db, legacyID)
	if strings.Contains(raw, legacyWebhook) || strings.Contains(raw, "LEGACYPLAIN") {
		t.Fatalf("legacy row was not encrypted on save: %s", raw)
	}
	if !strings.Contains(raw, credentials.Prefix) {
		t.Fatalf("migrated row carries no %q tag: %s", credentials.Prefix, raw)
	}

	// (c) and it still reads correctly afterwards
	got, err = cm.GetTenantChannelByID(ctx, tenant, legacyID)
	if err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if got.Config["webhook_url"] != legacyWebhook {
		t.Fatalf("migration corrupted the credential: %v", got.Config["webhook_url"])
	}
}

// TestIntegration_NotificationChannel_ReadModifyWriteDoesNotDoubleEncrypt
// guards the cycle that breaks naive prefix-less schemes: load, change
// something unrelated, save. The credential must survive N saves.
func TestIntegration_NotificationChannel_ReadModifyWriteDoesNotDoubleEncrypt(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	cm := itChannelManager(t, db)
	ctx := context.Background()

	const key = "pd-integration-key-abc123"
	created, err := cm.CreateTenantChannel(ctx, tenant, &models.CreateChannelRequest{
		ChannelName: "pd", ChannelType: "pagerduty", Enabled: true,
		Config: map[string]interface{}{"integration_key": key},
	}, nil)
	if err != nil {
		t.Fatalf("CreateTenantChannel: %v", err)
	}

	for i := 0; i < 3; i++ {
		enabled := i%2 == 0
		if _, err := cm.UpdateTenantChannel(ctx, tenant, created.ID, &models.UpdateChannelRequest{Enabled: &enabled}, nil); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}

	got, err := cm.GetTenantChannelByID(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("GetTenantChannelByID: %v", err)
	}
	if got.Config["integration_key"] != key {
		t.Fatalf("credential corrupted after repeated saves: %v", got.Config["integration_key"])
	}
	raw := rawChannelConfig(t, db, created.ID)
	if strings.Contains(raw, key) {
		t.Fatalf("credential ended up plaintext after repeated saves: %s", raw)
	}
	// Exactly one tag — a doubly-encrypted value would carry two.
	if n := strings.Count(raw, credentials.Prefix); n != 1 {
		t.Fatalf("expected exactly 1 %q tag, got %d: %s", credentials.Prefix, n, raw)
	}
}

// TestIntegration_PlatformNotificationChannel_CiphertextIsAtRest covers the
// second of the two notification stores. Separate SQL, separate methods, same
// cipher — and it has been the one that gets forgotten.
func TestIntegration_PlatformNotificationChannel_CiphertextIsAtRest(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	cm := itChannelManager(t, db)

	const webhook = "https://hooks.slack.com/services/PLAT/FORM/plat0rmsecret"
	created, err := cm.CreatePlatformChannel(&models.CreateChannelRequest{
		ChannelName: "platform-slack-" + uuid.NewString()[:8],
		ChannelType: "slack",
		Enabled:     true,
		Config:      map[string]interface{}{"webhook_url": webhook},
	}, nil)
	if err != nil {
		t.Fatalf("CreatePlatformChannel: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_notification_channels WHERE id = $1`, created.ID)
	})

	var raw string
	if err := db.QueryRow(`SELECT config::text FROM platform_notification_channels WHERE id = $1`, created.ID).Scan(&raw); err != nil {
		t.Fatalf("read raw config: %v", err)
	}
	if strings.Contains(raw, webhook) || strings.Contains(raw, "plat0rmsecret") {
		t.Fatalf("platform webhook_url stored in the clear: %s", raw)
	}

	got, err := cm.GetPlatformChannelByID(created.ID)
	if err != nil {
		t.Fatalf("GetPlatformChannelByID: %v", err)
	}
	if got.Config["webhook_url"] != webhook {
		t.Fatalf("round trip lost webhook_url: %v", got.Config["webhook_url"])
	}
}

// TestIntegration_NotificationChannel_WrongKeyFailsLoudly pins the reason the
// enc:v1: tag exists. Without it, a wrong-key read would hand ciphertext to
// the Slack sender as if it were a webhook URL; with it, the read reports an
// empty config and logs, rather than delivering to a garbage endpoint.
func TestIntegration_NotificationChannel_WrongKeyFailsLoudly(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	const webhook = "https://hooks.slack.com/services/W/K/wrongkeyprobe"
	created, err := itChannelManager(t, db).CreateTenantChannel(ctx, tenant, &models.CreateChannelRequest{
		ChannelName: "wrong-key", ChannelType: "slack", Enabled: true,
		Config: map[string]interface{}{"webhook_url": webhook},
	}, nil)
	if err != nil {
		t.Fatalf("CreateTenantChannel: %v", err)
	}

	other := NewChannelManager(sqlx.NewDb(db, "postgres"),
		&config.Config{EncryptionMasterKey: "a-totally-different-master-key!!"}, nil)
	got, err := other.GetTenantChannelByID(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("GetTenantChannelByID: %v", err)
	}
	if v, ok := got.Config["webhook_url"]; ok {
		t.Fatalf("a wrong-key read returned a webhook_url (%v) instead of refusing", v)
	}

	// Sanity: the row itself is fine under the right key.
	back, err := itChannelManager(t, db).GetTenantChannelByID(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("re-read under correct key: %v", err)
	}
	if back.Config["webhook_url"] != webhook {
		t.Fatalf("correct key failed to read the row: %v", back.Config["webhook_url"])
	}
}

// TestIntegration_NotificationChannel_MonitoringServiceSharesTheDecode proves
// requirement (d) for the notification family: monitoring-service reads a
// sibling table with the SAME config shape, and must decode a row that
// notification-service wrote. It cannot import monitoring-service (different
// module), so it asserts the guarantee at the point where it actually lives —
// both build their cipher from credentials.NotificationChannelPolicy.
func TestIntegration_NotificationChannel_MonitoringServiceSharesTheDecode(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	const webhook = "https://hooks.slack.com/services/CROSS/SVC/crossreadprobe"
	created, err := itChannelManager(t, db).CreateTenantChannel(ctx, tenant, &models.CreateChannelRequest{
		ChannelName: "cross", ChannelType: "slack", Enabled: true,
		Config: map[string]interface{}{"webhook_url": webhook},
	}, nil)
	if err != nil {
		t.Fatalf("CreateTenantChannel: %v", err)
	}

	// Exactly how monitoring-service builds its cipher.
	peer, err := credentials.NewCipher("monitoring notification channel", itMasterKey, credentials.NotificationChannelPolicy)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	var raw []byte
	if err := db.QueryRow(`SELECT config FROM tenant_notification_channels WHERE id = $1`, created.ID).Scan(&raw); err != nil {
		t.Fatalf("read raw config: %v", err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	decoded, err := peer.DecryptMap(stored)
	if err != nil {
		t.Fatalf("peer service could not decrypt a row this service wrote: %v", err)
	}
	if decoded["webhook_url"] != webhook {
		t.Fatalf("peer decode mismatch: %v", decoded["webhook_url"])
	}
}
