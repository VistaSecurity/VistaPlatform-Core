package services

// external_connections.dest_hostname is the field the Inventory → 3rd Party
// lens shows in place of a bare IP:port. Two properties matter for it, both
// instances of the "empty never wins" rule (see CLAUDE.md): a later
// observation that DOES carry a hostname (e.g. the sensor's captured TLS SNI)
// must fill a previously-empty column, and a later observation that does NOT
// carry one (e.g. a TLS enrichment probe, which measures certificates and
// cipher but not the client's original SNI) must never blank a hostname a
// prior observation already wrote.
//
// Asserted against a real Postgres because the claim is about what the
// COALESCE in the upsert's ON CONFLICT clause actually does to a stored row,
// not what the Go call site intended. Skips without TEST_DATABASE_URL
// (`make test-integration-db`).

import (
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ExternalConnectionUpsert_DestHostnameFillsButNeverBlanks(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	readHostname := func(destPort int) *string {
		var hostname sql.NullString
		if err := raw.QueryRow(
			`SELECT dest_hostname FROM external_connections WHERE tenant_id = $1 AND dest_port = $2`,
			tenant, destPort).Scan(&hostname); err != nil {
			t.Fatalf("read back dest_hostname for port %d: %v", destPort, err)
		}
		if !hostname.Valid {
			return nil
		}
		v := hostname.String
		return &v
	}

	// strptr is defined in bulk_import_test.go (package services).

	// --- Case 1: a hostname-less observation followed by one that captured
	// the SNI must FILL the column. This is the reported defect: the sensor's
	// first-seen TLS-over-TCP row (no SNI parsed yet, or an enrichment probe
	// landing first) leaves dest_hostname NULL, and a later observation of
	// the same endpoint that carried the SNI must not be discarded by the
	// upsert.
	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.10",
		DestIP:   "203.0.113.40",
		DestPort: 443,
		Protocol: "TLS",
	}); err != nil {
		t.Fatalf("first upsert (no hostname): %v", err)
	}
	if got := readHostname(443); got != nil {
		t.Fatalf("dest_hostname after first observation = %v, want nil", *got)
	}

	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:     "192.0.2.10",
		DestIP:       "203.0.113.40",
		DestPort:     443,
		Protocol:     "TLS",
		DestHostname: strptr("settings-win.data.microsoft.com"),
	}); err != nil {
		t.Fatalf("second upsert (with hostname): %v", err)
	}
	got := readHostname(443)
	if got == nil || *got != "settings-win.data.microsoft.com" {
		t.Errorf("dest_hostname after second observation = %v, want %q", got, "settings-win.data.microsoft.com")
	}

	// --- Case 2: a populated hostname followed by a hostname-less observation
	// (e.g. the TLS enricher's active-probe re-observation, which reports
	// certificates but not the original SNI) must NOT blank it.
	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:     "192.0.2.10",
		DestIP:       "203.0.113.41",
		DestPort:     8443,
		Protocol:     "TLS",
		DestHostname: strptr("api.example.com"),
	}); err != nil {
		t.Fatalf("first upsert (with hostname): %v", err)
	}
	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.10",
		DestIP:   "203.0.113.41",
		DestPort: 8443,
		Protocol: "TLS",
		// DestHostname deliberately nil — this observation measured nothing
		// about the hostname.
		CipherSuite: strptr("TLS_AES_128_GCM_SHA256"),
	}); err != nil {
		t.Fatalf("second upsert (no hostname, cert-only re-observation): %v", err)
	}
	got = readHostname(8443)
	if got == nil || *got != "api.example.com" {
		t.Errorf("dest_hostname after hostname-less re-observation = %v, want %q (must not be blanked)", got, "api.example.com")
	}
}
