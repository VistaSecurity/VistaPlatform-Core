package services

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// discovery_alert_configs.slack_webhook_url is gap 4: a Slack incoming
// webhook URL — a full posting credential — in a plaintext text column. Unlike
// the notification stores this one is a scalar, not a JSON blob, so it
// exercises the EncryptValue/DecryptValue half of the shared helper.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

const alertITMasterKey = "integration-test-master-key-32byt"

func itAlertService(t *testing.T, db *sql.DB, masterKey string) *AlertService {
	t.Helper()
	t.Setenv("ENCRYPTION_MASTER_KEY", masterKey)
	svc, err := NewAlertService(sqlx.NewDb(db, "postgres"), &config.Config{})
	if err != nil {
		t.Fatalf("NewAlertService: %v", err)
	}
	return svc
}

func rawSlackWebhook(t *testing.T, db *sql.DB, tenant uuid.UUID, alertType string) string {
	t.Helper()
	var raw sql.NullString
	err := db.QueryRow(
		`SELECT slack_webhook_url FROM discovery_alert_configs WHERE tenant_id = $1 AND alert_type = $2`,
		tenant, alertType).Scan(&raw)
	if err != nil {
		t.Fatalf("read raw slack_webhook_url: %v", err)
	}
	return raw.String
}

// TestIntegration_DiscoveryAlertConfig_CiphertextIsAtRest proves the webhook
// leaves the service encrypted and comes back intact.
func TestIntegration_DiscoveryAlertConfig_CiphertextIsAtRest(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAlertService(t, db, alertITMasterKey)

	const webhook = "https://hooks.slack.com/services/D1/S1/discoverysecret"
	if err := svc.UpdateAlertConfig(tenant.String(), models.AlertConfigRequest{
		TenantID: tenant.String(), AlertType: "job_completed", Enabled: true,
		SlackEnabled: true, SlackWebhookURL: webhook, SlackChannel: "#discovery",
	}); err != nil {
		t.Fatalf("UpdateAlertConfig: %v", err)
	}

	raw := rawSlackWebhook(t, db, tenant, "job_completed")
	if strings.Contains(raw, "hooks.slack.com") || strings.Contains(raw, "discoverysecret") {
		t.Fatalf("slack webhook stored in the clear: %q", raw)
	}
	if !strings.HasPrefix(raw, credentials.Prefix) {
		t.Fatalf("stored value carries no %q tag, so nothing was encrypted: %q", credentials.Prefix, raw)
	}

	configs, err := svc.GetAlertConfigs(tenant.String())
	if err != nil {
		t.Fatalf("GetAlertConfigs: %v", err)
	}
	if got := findAlertConfig(t, configs, "job_completed").SlackWebhookURL; got != webhook {
		t.Fatalf("round trip lost the webhook: %q", got)
	}
	// The non-credential sibling column must be untouched.
	if got := findAlertConfig(t, configs, "job_completed").SlackChannel; got != "#discovery" {
		t.Fatalf("slack_channel was altered: %q", got)
	}
}

// TestIntegration_DiscoveryAlertConfig_LegacyPlaintextRowMigrates is the
// migration proof for the scalar path.
func TestIntegration_DiscoveryAlertConfig_LegacyPlaintextRowMigrates(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAlertService(t, db, alertITMasterKey)

	const legacy = "https://hooks.slack.com/services/L1/L1/LEGACYSCALAR"
	if _, err := db.Exec(`
		INSERT INTO discovery_alert_configs (tenant_id, alert_type, enabled, slack_enabled, slack_webhook_url)
		VALUES ($1, 'job_failed', true, true, $2)`, tenant, legacy); err != nil {
		t.Fatalf("seed legacy plaintext row: %v", err)
	}

	// (a) reads correctly while still plaintext
	configs, err := svc.GetAlertConfigs(tenant.String())
	if err != nil {
		t.Fatalf("GetAlertConfigs: %v", err)
	}
	if got := findAlertConfig(t, configs, "job_failed").SlackWebhookURL; got != legacy {
		t.Fatalf("legacy plaintext row did not read back: %q", got)
	}

	// (b) encrypted on next save
	if err := svc.UpdateAlertConfig(tenant.String(), models.AlertConfigRequest{
		TenantID: tenant.String(), AlertType: "job_failed", Enabled: true,
		SlackEnabled: true, SlackWebhookURL: legacy,
	}); err != nil {
		t.Fatalf("UpdateAlertConfig: %v", err)
	}
	raw := rawSlackWebhook(t, db, tenant, "job_failed")
	if strings.Contains(raw, "LEGACYSCALAR") {
		t.Fatalf("legacy row was not encrypted on save: %q", raw)
	}

	// (c) and still reads correctly
	configs, err = svc.GetAlertConfigs(tenant.String())
	if err != nil {
		t.Fatalf("GetAlertConfigs: %v", err)
	}
	if got := findAlertConfig(t, configs, "job_failed").SlackWebhookURL; got != legacy {
		t.Fatalf("migration corrupted the credential: %q", got)
	}
}

// TestIntegration_DiscoveryAlertConfig_ResaveDoesNotDoubleEncrypt: the upsert
// takes whatever GetAlertConfigs returned, so a save-after-read must not stack
// a second layer of ciphertext.
func TestIntegration_DiscoveryAlertConfig_ResaveDoesNotDoubleEncrypt(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	svc := itAlertService(t, db, alertITMasterKey)

	const webhook = "https://hooks.slack.com/services/R1/R1/resaveprobe"
	for i := 0; i < 3; i++ {
		configs, err := svc.GetAlertConfigs(tenant.String())
		if err != nil {
			t.Fatalf("GetAlertConfigs: %v", err)
		}
		url := webhook
		if len(configs) > 0 {
			url = configs[0].SlackWebhookURL
		}
		if err := svc.UpdateAlertConfig(tenant.String(), models.AlertConfigRequest{
			TenantID: tenant.String(), AlertType: "new_findings", Enabled: true,
			SlackEnabled: true, SlackWebhookURL: url,
		}); err != nil {
			t.Fatalf("UpdateAlertConfig %d: %v", i, err)
		}
	}

	configs, err := svc.GetAlertConfigs(tenant.String())
	if err != nil {
		t.Fatalf("GetAlertConfigs: %v", err)
	}
	if got := findAlertConfig(t, configs, "new_findings").SlackWebhookURL; got != webhook {
		t.Fatalf("credential corrupted after repeated read-then-save: %q", got)
	}
	if raw := rawSlackWebhook(t, db, tenant, "new_findings"); strings.Count(raw, credentials.Prefix) != 1 {
		t.Fatalf("expected exactly one %q tag, got %q", credentials.Prefix, raw)
	}
}

// TestIntegration_DiscoveryAlertConfig_WrongKeyErrors: a tagged value that
// will not decrypt must surface as an error, not as a webhook URL made of
// ciphertext that the Slack sender would POST to.
func TestIntegration_DiscoveryAlertConfig_WrongKeyErrors(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)

	if err := itAlertService(t, db, alertITMasterKey).UpdateAlertConfig(tenant.String(), models.AlertConfigRequest{
		TenantID: tenant.String(), AlertType: "job_completed", Enabled: true,
		SlackEnabled: true, SlackWebhookURL: "https://hooks.slack.com/services/W/W/wrongkey",
	}); err != nil {
		t.Fatalf("UpdateAlertConfig: %v", err)
	}

	if _, err := itAlertService(t, db, "a-totally-different-master-key!!").GetAlertConfigs(tenant.String()); err == nil {
		t.Fatal("reading a tagged ciphertext under the wrong key must error")
	}
}

func findAlertConfig(t *testing.T, configs []models.DiscoveryAlertConfig, alertType string) models.DiscoveryAlertConfig {
	t.Helper()
	for _, c := range configs {
		if c.AlertType == alertType {
			return c
		}
	}
	t.Fatalf("no alert config of type %q in %d rows", alertType, len(configs))
	return models.DiscoveryAlertConfig{}
}
