package services

// The point of normalizing at ingest is what ends up in the COLUMN, so this is
// asserted against a real Postgres rather than against the normalizer.
// A unit test of cryptoparse.NormalizeProtocol would have passed before this
// change too — StoreDiscoveries wrote discovery.Protocol straight through, and
// nothing anywhere logged the fact that "EtherNet/IP" upper-cases to a string no
// service_identification_rules row can match.
//
// Skips unless TEST_DATABASE_URL is set (`make test-integration-db`).

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func insertProtoTestSensor(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile)
		VALUES ($1, $2, 'protocol-normalization', 'linux', '0.0.0-test', 'datacenter_host')`,
		id, tenantID)
	if err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	return id
}

func TestIntegration_StoreDiscoveries_StoresCanonicalProtocol(t *testing.T) {
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)
	sensorID := insertProtoTestSensor(t, db, tenantID)

	svc := &SensorService{db: db, bypassDB: db}

	// Left column: spellings producers in this tree actually emit. Right column:
	// what has to be in the row afterwards. The last two are the ones that must
	// NOT be rewritten — an unmodelled protocol is still an observation, and the
	// string is the only record of it.
	cases := []struct {
		in   string
		want string
	}{
		{"EtherNet/IP", "EtherNet_IP"},
		{"OPC UA", "OPC_UA"},
		{"ModbusTCP", "Modbus"},
		{"BACnet.SC", "BACnet_SC"},
		{"tls", "TLS"},
		{"QUIC", "QUIC"},
		{"AT-REST", "AT-REST"},
	}

	batchID := uuid.New()
	batch := &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   batchID,
		Timestamp: time.Now(),
	}
	for i, c := range cases {
		batch.Discoveries = append(batch.Discoveries, models.SensorDiscoveryInput{
			Protocol:   c.in,
			SourceIP:   "192.0.2.10",
			DestIP:     "198.51.100.20",
			Port:       4840 + i, // distinct per row so each is identifiable
			Confidence: 0.9,
		})
	}

	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}

	for i, c := range cases {
		var got string
		err := db.QueryRow(
			`SELECT protocol FROM sensor_discoveries WHERE batch_id = $1 AND port = $2`,
			batchID, 4840+i).Scan(&got)
		if err != nil {
			t.Fatalf("read back discovery for %q: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("sensor sent protocol %q, sensor_discoveries.protocol holds %q, want %q",
				c.in, got, c.want)
		}
	}
}

// discovery_findings.protocol is the second of the three free-text protocol
// columns; it is written by a different service on a different path, which is
// exactly why the normalization has to sit on every writer rather than on the
// one reader that noticed the problem.
func TestIntegration_ReceiveDiscoveryResults_StoresCanonicalProtocol(t *testing.T) {
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
		VALUES ($1, $2, $3, '198.51.100.30', ARRAY['EtherNet/IP'], ARRAY[44818])`,
		targetID, jobID, tenantID); err != nil {
		t.Fatalf("insert discovery target: %v", err)
	}

	svc := &DiscoveryJobService{db: db}

	cases := []struct {
		in   string
		want string
		port int
	}{
		{"EtherNet/IP", "EtherNet_IP", 44818},
		{"OPC-UA", "OPC_UA", 4840},
		{"tcp", "tcp", 502}, // nmap's answer for an OT probe that did not reply — preserved
	}

	// raw_blob_size used to need a value here: the column is NOT NULL, the model
	// carries it as *int, and the INSERT bound the pointer straight through, so
	// a finding that omitted it aborted the whole batch. It is left unset now —
	// TestIntegration_ReceiveDiscoveryResults_FindingWithoutRawBlobSize pins
	// that directly.

	res := &models.DiscoveryJobResult{}
	for _, c := range cases {
		res.Findings = append(res.Findings, models.DiscoveryFinding{
			TargetID:    targetID,
			ExecutedVia: "sensor",
			Protocol:    c.in,
			Port:        c.port,
		})
	}

	if err := svc.ReceiveDiscoveryResults(tenantID, jobID, res); err != nil {
		t.Fatalf("ReceiveDiscoveryResults: %v", err)
	}

	for _, c := range cases {
		var got string
		if err := db.QueryRow(
			`SELECT protocol FROM discovery_findings WHERE job_id = $1 AND port = $2`,
			jobID, c.port).Scan(&got); err != nil {
			t.Fatalf("read back finding for %q: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("finding reported protocol %q, discovery_findings.protocol holds %q, want %q",
				c.in, got, c.want)
		}
	}
}
