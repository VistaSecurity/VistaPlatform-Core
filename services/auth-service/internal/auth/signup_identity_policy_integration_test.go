package auth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SignupEnablesIdentityPolicy(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	app := testdb.ConnectAsAppRole(t, db)
	testdb.WithSchemaShareLock(t, db, func() {
		// An existing customer's explicit policy must survive new signups.
		existing := testdb.NewTenant(t, db)
		if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"paused"},"identity_enrichment":{"enabled":false},"discovery_auto_scan":{"enabled":false}}')`, existing); err != nil {
			t.Fatal(err)
		}
		var before string
		if err := db.QueryRow(`SELECT config::text FROM tenant_admin_settings WHERE tenant_id=$1`, existing).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, social := range []bool{false, true} {
			auth := makeAuthForTest(app)
			var id string
			if social {
				tenant, err := auth.CreateTenantPublic("Identity social signup")
				if err != nil {
					t.Fatal(err)
				}
				id = tenant.ID.String()
			} else {
				id = newSignupTenant(t, app).String()
			}
			var raw []byte
			var version, audits int
			if err := db.QueryRow(`SELECT config,version FROM tenant_admin_settings WHERE tenant_id=$1`, id).Scan(&raw, &version); err != nil {
				t.Fatal(err)
			}
			var policy struct {
				Admission struct {
					Mode        string     `json:"mode"`
					ActivatedAt *time.Time `json:"activated_at"`
				} `json:"identity_admission"`
				Enrichment struct {
					Enabled   bool     `json:"enabled"`
					Excluded  []string `json:"excluded_cidrs"`
					Sensitive []string `json:"sensitive_asset_ids"`
				} `json:"identity_enrichment"`
			}
			if err := json.Unmarshal(raw, &policy); err != nil {
				t.Fatal(err)
			}
			if policy.Admission.Mode != "enforce" || policy.Admission.ActivatedAt == nil || !policy.Enrichment.Enabled || policy.Enrichment.Excluded == nil || policy.Enrichment.Sensitive == nil || version != 1 {
				t.Fatalf("signup policy = %s, version %d", raw, version)
			}
			if err := db.QueryRow(`SELECT count(*) FROM tenant_admin_settings_audit a JOIN tenant_admin_settings s USING(tenant_id) WHERE a.tenant_id=$1 AND a.config_after=s.config AND a.changed_by IS NULL AND a.version_before=0 AND a.version_after=1`, id).Scan(&audits); err != nil || audits != 1 {
				t.Fatalf("initial audit count=%d err=%v", audits, err)
			}
		}
		var after string
		if err := db.QueryRow(`SELECT config::text FROM tenant_admin_settings WHERE tenant_id=$1`, existing).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if before != after {
			t.Fatal("signup changed an existing tenant's policy")
		}
	})
}
