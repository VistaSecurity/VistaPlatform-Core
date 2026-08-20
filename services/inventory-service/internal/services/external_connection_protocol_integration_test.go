package services

// external_connections.protocol is the third free-text protocol column, and the
// only one where the spelling is part of the row's UNIQUE key
// (tenant, source_ip, dest_ip, dest_port, protocol). Two spellings of the same
// protocol therefore did not just look inconsistent — they split one endpoint
// into two rows, each accumulating its own observation_count and history.
//
// Asserted against a real Postgres because the claim is about what the column
// holds and how many rows exist, neither of which a unit test can see.
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ExternalConnectionUpsert_StoresCanonicalProtocol(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.50",
		DestIP:   "198.51.100.60",
		DestPort: 44818,
		Protocol: "EtherNet/IP",
	}); err != nil {
		t.Fatalf("Upsert with the vendor spelling: %v", err)
	}

	var stored string
	if err := raw.QueryRow(
		`SELECT protocol FROM external_connections WHERE tenant_id = $1 AND dest_port = 44818`,
		tenant).Scan(&stored); err != nil {
		t.Fatalf("read back connection: %v", err)
	}
	if stored != "EtherNet_IP" {
		t.Errorf("external_connections.protocol holds %q, want %q", stored, "EtherNet_IP")
	}

	// The same endpoint observed again with the canonical spelling must land on
	// the SAME row. Before normalization the unique key differed and this
	// produced a second row.
	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.50",
		DestIP:   "198.51.100.60",
		DestPort: 44818,
		Protocol: "EtherNet_IP",
	}); err != nil {
		t.Fatalf("Upsert with the canonical spelling: %v", err)
	}

	var rows, observations int
	if err := raw.QueryRow(
		`SELECT count(*), coalesce(max(observation_count), 0) FROM external_connections
		 WHERE tenant_id = $1 AND dest_port = 44818`, tenant).Scan(&rows, &observations); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if rows != 1 {
		t.Errorf("two spellings of EtherNet/IP produced %d external_connections rows, want 1", rows)
	}
	if observations != 2 {
		t.Errorf("observation_count = %d, want 2 — the second observation started a new row "+
			"instead of incrementing the existing one", observations)
	}

	// A protocol the enum does not model must still be storable, un-rewritten.
	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.50",
		DestIP:   "198.51.100.60",
		DestPort: 443,
		Protocol: "QUIC",
	}); err != nil {
		t.Fatalf("Upsert with an unmodelled protocol: %v", err)
	}
	if err := raw.QueryRow(
		`SELECT protocol FROM external_connections WHERE tenant_id = $1 AND dest_port = 443`,
		tenant).Scan(&stored); err != nil {
		t.Fatalf("read back QUIC connection: %v", err)
	}
	if stored != "QUIC" {
		t.Errorf("external_connections.protocol holds %q for an unmodelled protocol, want %q "+
			"— an unrecognised protocol must pass through, not be coerced", stored, "QUIC")
	}
}
