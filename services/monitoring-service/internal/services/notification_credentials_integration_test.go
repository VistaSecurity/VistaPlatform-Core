package services

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// gap 3: monitoring_notification_channels.config holds Slack webhook URLs
// and PagerDuty integration keys. This service is a read-only consumer of that
// legacy table, so the guarantee to prove is the read one — every senders'
// input must be plaintext regardless of how the row was stored.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

const monitoringITMasterKey = "integration-test-master-key-32byt"

func seedMonitoringChannel(t *testing.T, db *sql.DB, name, chType, config string) {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO monitoring_notification_channels (id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, $3, $4::jsonb, true)`, id, name, chType, config); err != nil {
		t.Fatalf("seed monitoring channel: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM monitoring_notification_channels WHERE id = $1`, id) })
}

// TestIntegration_MonitoringChannel_ReadsBothProvenances: a plaintext row
// (every row today) and an encrypted row (what the unified-notifications
// pipeline will produce) must both reach the sender as plaintext.
func TestIntegration_MonitoringChannel_ReadsBothProvenances(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	t.Setenv("ENCRYPTION_MASTER_KEY", monitoringITMasterKey)

	const plainWebhook = "https://hooks.slack.com/services/M1/M1/monitorplain"
	const encWebhook = "https://hooks.slack.com/services/M2/M2/monitorenc"

	plainName := "mon-plain-" + uuid.NewString()[:8]
	seedMonitoringChannel(t, db, plainName, "slack", `{"webhook_url":"`+plainWebhook+`"}`)

	cipher, err := credentials.NewCipher("test", monitoringITMasterKey, credentials.NotificationChannelPolicy)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	encrypted, err := cipher.EncryptMap(map[string]interface{}{"webhook_url": encWebhook})
	if err != nil {
		t.Fatalf("EncryptMap: %v", err)
	}
	encJSON, _ := json.Marshal(encrypted)
	encName := "mon-enc-" + uuid.NewString()[:8]
	seedMonitoringChannel(t, db, encName, "slack", string(encJSON))

	svc := NewNotificationService(db)
	channels, err := svc.GetNotificationChannels()
	if err != nil {
		t.Fatalf("GetNotificationChannels: %v", err)
	}

	byName := map[string]NotificationChannel{}
	for _, c := range channels {
		byName[c.ChannelName] = c
	}
	if got := byName[plainName].Config["webhook_url"]; got != plainWebhook {
		t.Errorf("legacy plaintext row: got %v, want %q", got, plainWebhook)
	}
	if got := byName[encName].Config["webhook_url"]; got != encWebhook {
		t.Errorf("encrypted row: got %v, want %q", got, encWebhook)
	}
}
