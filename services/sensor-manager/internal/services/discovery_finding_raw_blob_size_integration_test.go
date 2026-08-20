package services

// discovery_findings.raw_blob_size is `integer DEFAULT 0 NOT NULL`, but
// models.DiscoveryFinding.RawBlobSize is a *int that ReceiveDiscoveryResults
// bound straight into an INSERT naming the column explicitly. An explicitly
// bound NULL does not fall back to the column default, so any finding that
// omitted the field — every producer that stores no raw blob — violated the
// NOT NULL constraint. And because the whole submission shares one transaction,
// that discarded EVERY finding in the batch, not just the offending one: a
// sensor's entire scan result lost to a field nothing reads.
//
// Asserted against a real Postgres because the claim is about a column
// constraint. A unit test of the struct would have been green throughout.
//
// Skips unless TEST_DATABASE_URL is set (`make test-integration-db`).

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ReceiveDiscoveryResults_FindingWithoutRawBlobSize(t *testing.T) {
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)

	jobID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status)
		VALUES ($1, $2, 'sensor', 'queued')`, jobID, tenantID); err != nil {
		t.Fatalf("insert discovery job: %v", err)
	}
	targetID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports)
		VALUES ($1, $2, $3, '198.51.100.40', ARRAY['TLS'], ARRAY[443])`,
		targetID, jobID, tenantID); err != nil {
		t.Fatalf("insert discovery target: %v", err)
	}

	svc := &DiscoveryJobService{db: db}

	// A batch where one finding carries a raw blob and two do not. Before the
	// fix the two nil ones failed the NOT NULL constraint and took the first
	// down with them.
	blobSize := 4096
	res := &models.DiscoveryJobResult{Findings: []models.DiscoveryFinding{
		{TargetID: targetID, ExecutedVia: "sensor", Protocol: "TLS", Port: 443, RawBlobSize: &blobSize},
		{TargetID: targetID, ExecutedVia: "sensor", Protocol: "SSH", Port: 22},
		{TargetID: targetID, ExecutedVia: "sensor", Protocol: "TLS", Port: 8443},
	}}

	if err := svc.ReceiveDiscoveryResults(tenantID, jobID, res); err != nil {
		t.Fatalf("ReceiveDiscoveryResults rejected a batch containing a finding with no "+
			"raw_blob_size: %v — the column defaults to 0 and the field is optional", err)
	}

	var stored int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`, jobID).Scan(&stored); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if stored != len(res.Findings) {
		t.Fatalf("stored %d of %d findings — one finding without raw_blob_size aborted the batch",
			stored, len(res.Findings))
	}

	// The omitted field must land on the column's own default, not on some other
	// number: raw_blob_size is "how many bytes of raw blob we kept", and the
	// honest answer for a finding with no blob is zero.
	var sizes []int
	rows, err := db.Query(`SELECT raw_blob_size FROM discovery_findings WHERE job_id = $1 ORDER BY port`, jobID)
	if err != nil {
		t.Fatalf("read raw_blob_size: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan raw_blob_size: %v", err)
		}
		sizes = append(sizes, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate raw_blob_size: %v", err)
	}
	// Ordered by port: 22 (omitted → 0), 443 (4096), 8443 (omitted → 0).
	want := []int{0, blobSize, 0}
	if len(sizes) != len(want) {
		t.Fatalf("got %d raw_blob_size values, want %d", len(sizes), len(want))
	}
	for i, w := range want {
		if sizes[i] != w {
			t.Errorf("raw_blob_size[%d] = %d, want %d — a supplied size must survive and an "+
				"omitted one must become the column default", i, sizes[i], w)
		}
	}
}
