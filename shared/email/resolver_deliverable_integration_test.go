package email

// ResolveDeliverableConfig tells "email is not configured" apart from "email is
// configured but unreachable".
//
// The older resolvers never could: with no platform_settings.email_config they
// returned localhost:587, so an unconfigured deployment looked like a
// configured one whose SMTP server was down — and notification-service retried
// every alert email five times against a port nothing listens on.
//
// Runs against a real Postgres (skips without TEST_DATABASE_URL). platform_settings
// is a global table other suites may touch, so every write happens inside one
// manual transaction on a single pinned connection that is rolled back — nothing
// is ever committed and nothing is visible to a parallel package.

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// isolatedDB returns a connection pinned to one session, inside a transaction
// that is rolled back at test end, with email_config removed for the duration.
func isolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`BEGIN`); err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`ROLLBACK`) })
	if _, err := db.Exec(`DELETE FROM platform_settings WHERE setting_key = 'email_config'`); err != nil {
		t.Fatalf("clear email_config: %v", err)
	}
	return db
}

func setPlatformEmailConfig(t *testing.T, db *sql.DB, doc string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO platform_settings (setting_key, setting_value) VALUES ('email_config', $1::jsonb)`, doc); err != nil {
		t.Fatalf("insert email_config: %v", err)
	}
}

func TestIntegration_DeliverableConfig_NothingConfiguredIsErrNotConfigured(t *testing.T) {
	db := isolatedDB(t)
	t.Setenv("SMTP_HOST", "")
	r := NewEmailConfigResolver(db, "")

	if _, err := r.ResolveDeliverableConfig(nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("platform: err = %v, want ErrNotConfigured", err)
	}
	tenant := uuid.New()
	if _, err := r.ResolveDeliverableConfig(&tenant); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("tenant with no override: err = %v, want ErrNotConfigured", err)
	}

	// The legacy resolver is deliberately unchanged: it still answers
	// localhost, which is exactly the behaviour this method exists to avoid.
	legacy, err := r.GetPlatformEmailConfig()
	if err != nil || legacy.SMTPHost != "localhost" {
		t.Fatalf("legacy GetPlatformEmailConfig = %+v, %v; expected the unchanged localhost fallback", legacy, err)
	}
}

func TestIntegration_DeliverableConfig_BlankHostIsNotConfigured(t *testing.T) {
	db := isolatedDB(t)
	t.Setenv("SMTP_HOST", "")
	setPlatformEmailConfig(t, db, `{"smtp_host":"   ","smtp_port":"587","from_email":"noreply@example.test"}`)
	r := NewEmailConfigResolver(db, "")
	if _, err := r.ResolveDeliverableConfig(nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured for a blank smtp_host", err)
	}
}

func TestIntegration_DeliverableConfig_PlatformSettingsWin(t *testing.T) {
	db := isolatedDB(t)
	t.Setenv("SMTP_HOST", "env-smtp.example.test")
	setPlatformEmailConfig(t, db, `{"smtp_host":"smtp.example.test","smtp_port":"2525","from_email":"alerts@example.test","from_name":"Ops"}`)
	r := NewEmailConfigResolver(db, "")

	cfg, err := r.ResolveDeliverableConfig(nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cfg.SMTPHost != "smtp.example.test" || cfg.SMTPPort != "2525" || cfg.FromEmail != "alerts@example.test" {
		t.Errorf("config = %+v, want the platform_settings values", cfg)
	}
}

// The dev/compose path: no platform settings, but SMTP_HOST is set explicitly
// (a mail catcher, say). That must keep working.
func TestIntegration_DeliverableConfig_ExplicitEnvHostStillWorks(t *testing.T) {
	db := isolatedDB(t)
	t.Setenv("SMTP_HOST", "mailcatcher.example.test")
	t.Setenv("SMTP_PORT", "1025")
	r := NewEmailConfigResolver(db, "")

	cfg, err := r.ResolveDeliverableConfig(nil)
	if err != nil {
		t.Fatalf("err = %v, want the env config", err)
	}
	if cfg.SMTPHost != "mailcatcher.example.test" || cfg.SMTPPort != "1025" {
		t.Errorf("config = %+v, want the SMTP_HOST/SMTP_PORT values", cfg)
	}
}

func TestIntegration_DeliverableConfig_TenantOverrideAloneIsEnough(t *testing.T) {
	db := isolatedDB(t)
	t.Setenv("SMTP_HOST", "")
	tenant := uuid.New()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'IT email', $2)`, tenant, "it-"+tenant.String()[:8]); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings (tenant_id, config) VALUES ($1, $2::jsonb)`, tenant,
		`{"email_config":{"use_platform_default":false,"smtp_host":"tenant-smtp.example.test","smtp_port":"465"}}`); err != nil {
		t.Fatalf("insert tenant_admin_settings: %v", err)
	}
	r := NewEmailConfigResolver(db, "")

	cfg, err := r.ResolveDeliverableConfig(&tenant)
	if err != nil {
		t.Fatalf("err = %v: a tenant with its own SMTP host can send even when the platform cannot", err)
	}
	if cfg.SMTPHost != "tenant-smtp.example.test" || cfg.SMTPPort != "465" {
		t.Errorf("config = %+v, want the tenant's own SMTP settings", cfg)
	}
	// ...and the platform, with no config of its own, still cannot.
	if _, err := r.ResolveDeliverableConfig(nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("platform err = %v, want ErrNotConfigured", err)
	}
}
