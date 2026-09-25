package services

// W2.1, W2.2 and W2.7 against a real Postgres: what the two executors
// write into sensor_discoveries for a finding that names no address, and what
// an agent run with no crypto assets records about the device.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/forwardmeta"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type sensorDiscoveryRow struct {
	DestIP   string
	Port     int
	Protocol string
	Hostname *string
	Metadata map[string]interface{}
}

// panosAddressLessAssets are two findings a PAN-OS collector emits that name no
// address:
//
//   - a decrypting security rule whose name is DNS-valid. It is called
//     `localhost` here because that name resolves on EVERY machine this test
//     runs on — the old writer passed it to net.LookupIP and wrote 127.0.0.1;
//     in a cluster the same code turned a rule called `postgres` into the
//     platform's database.
//   - a decryption profile whose name is not DNS-valid, so it has no hostname
//     either. The agent path used to skip it outright while the in-cluster
//     executor wrote it, so whether it existed depended on which runtime
//     claimed the job.
func panosAddressLessAssets() []*di.CryptoAsset {
	return []*di.CryptoAsset{
		{
			Hostname: "localhost", Protocol: "TLS", Port: 443, AssetType: "firewall",
			Metadata: map[string]interface{}{"rule_name": "localhost", "ssl_decrypt": "yes",
				// What a hostile agent or collector could put in metadata: its own
				// choice of owner and job. Neither may reach the row.
				"source_asset_id":  "00000000-0000-4000-8000-000000000001",
				"device_job_id":    "00000000-0000-4000-8000-000000000002",
				"discovery_method": "host_inventory"},
		},
		{
			Protocol: "TLS", Port: 443, AssetType: "firewall",
			Metadata: map[string]interface{}{"profile_name": "Decrypt Profile 1", "profile_type": "ssl-decrypt", "certificate_ca": "Forward-Trust"},
		},
	}
}

func TestIntegration_AddressLessFindings_BothExecutorsWriteTheSameOwnedRow(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	device := subjectAsset(t, owner, tenant, "pa-edge-"+uuid.NewString()[:8])

	read := func(t *testing.T, where string, args ...any) map[string]sensorDiscoveryRow {
		t.Helper()
		rows, err := owner.QueryContext(ctx, `
			SELECT host(dest_ip), port, protocol::text, hostname, metadata
			  FROM sensor_discoveries WHERE tenant_id = $1 AND `+where, append([]any{tenant}, args...)...)
		if err != nil {
			t.Fatalf("read sensor_discoveries: %v", err)
		}
		defer func() { _ = rows.Close() }()
		out := map[string]sensorDiscoveryRow{}
		for rows.Next() {
			var r sensorDiscoveryRow
			var raw []byte
			if err := rows.Scan(&r.DestIP, &r.Port, &r.Protocol, &r.Hostname, &raw); err != nil {
				t.Fatalf("scan: %v", err)
			}
			if err := json.Unmarshal(raw, &r.Metadata); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}
			label, _ := r.Metadata[forwardmeta.KeyConfigName].(string)
			if label == "" {
				label, _ = r.Metadata[forwardmeta.KeyProfileName].(string)
			}
			out[label] = r
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// In-cluster executor.
	svc := NewDeviceInterrogationService(app, owner, "")
	sensor, err := svc.resultProcessor.lookupSystemSensor(ctx, tenant)
	if err != nil {
		t.Fatalf("lookupSystemSensor: %v", err)
	}
	jobID, targetID := seedInterrogationJob(t, owner, tenant)
	inClusterJob := uuid.New() // the device job the platform worker would be executing
	for _, a := range panosAddressLessAssets() {
		if !svc.materializeInterrogatedAsset(ctx, tenant, device, inClusterJob, jobID, targetID, sensor, jobID.String(), a, &di.InterrogateResult{}) {
			t.Fatalf("in-cluster: %v did not reach sensor_discoveries", a.Metadata)
		}
	}
	inCluster := read(t, "batch_id = $2", jobID.String())

	// Agent executor: the same collector output, posted as JSON and processed.
	agent := insertDeviceAgent(t, owner, tenant)
	agentJob := uuid.New()
	if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, agentJob, tenant, agent, device); err != nil {
		t.Fatalf("seed agent job: %v", err)
	}
	var posted []models.DiscoveredAsset
	for _, a := range panosAddressLessAssets() {
		posted = append(posted, toDiscoveredAsset(a, nil))
	}
	blob, _ := json.Marshal(&models.JobResult{JobID: agentJob, Success: true, Assets: posted, CompletedAt: time.Now().UTC()})
	var result models.JobResult
	if err := json.Unmarshal(blob, &result); err != nil {
		t.Fatal(err)
	}
	if err := NewResultProcessor(app, owner).ProcessJobResults(ctx, agentJob, &result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}
	agentRows := read(t, "batch_id <> $2 AND metadata->>'source_asset_id' = $3", jobID.String(), device.String())

	for _, label := range []string{"localhost", "Decrypt Profile 1"} {
		ic, ok := inCluster[label]
		if !ok {
			t.Fatalf("in-cluster wrote no row for %q (rows: %v)", label, inCluster)
		}
		ag, ok := agentRows[label]
		if !ok {
			t.Fatalf("agent path wrote no row for %q — the two runtimes disagree about whether it exists (rows: %v)", label, agentRows)
		}
		// No DNS: `localhost` would have become 127.0.0.1.
		if ic.DestIP != unspecifiedDestIP {
			t.Errorf("%q: dest_ip = %s, want the unspecified placeholder — a collector label was resolved", label, ic.DestIP)
		}
		// Owned by the interrogated device.
		if ic.Metadata["source_asset_id"] != device.String() {
			t.Errorf("%q: source_asset_id = %v, want the interrogated device %s", label, ic.Metadata["source_asset_id"], device)
		}
		if ic.Metadata["discovery_method"] != "device_interrogation" || ag.Metadata["discovery_method"] != "device_interrogation" {
			t.Errorf("%q: discovery_method overridden by collector metadata: %v / %v", label, ic.Metadata["discovery_method"], ag.Metadata["discovery_method"])
		}
		// Each row is bound to the device job that produced it, from the
		// server's own record — the only field the two runtimes may differ in.
		if ic.Metadata["device_job_id"] != inClusterJob.String() || ag.Metadata["device_job_id"] != agentJob.String() {
			t.Errorf("%q: device_job_id in-cluster=%v agent=%v, want %s / %s", label,
				ic.Metadata["device_job_id"], ag.Metadata["device_job_id"], inClusterJob, agentJob)
		}
		delete(ic.Metadata, "device_job_id")
		delete(ag.Metadata, "device_job_id")
		if !reflect.DeepEqual(ic, ag) {
			t.Errorf("%q: the executors wrote different rows\n in-cluster: %+v\n      agent: %+v", label, ic, ag)
		}
	}
}

// A PAN-OS firewall with no decryption profiles: the agent's run finds no
// crypto assets. Its identity must still be recorded against the device.
func TestIntegration_ZeroAssetAgentRun_KeepsDeviceIdentity(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	device := subjectAsset(t, owner, tenant, "pa-edge-"+uuid.NewString()[:8])
	agent := insertDeviceAgent(t, owner, tenant)
	jobID := uuid.New()
	if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, jobID, tenant, agent, device); err != nil {
		t.Fatalf("seed device_job: %v", err)
	}

	// As a current agent posts it: identity beside the (empty) asset list.
	blob := []byte(`{"job_id":"` + jobID.String() + `","success":true,"completed_at":"2026-09-24T10:00:00Z",
		"device_identity":{"vendor":"Palo Alto Networks","model":"PA-3220","serial_number":"013201001234","firmware_version":"11.1.4-h7"}}`)
	var result models.JobResult
	if err := json.Unmarshal(blob, &result); err != nil {
		t.Fatal(err)
	}
	if err := NewResultProcessor(app, owner).ProcessJobResults(ctx, jobID, &result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	for key, want := range map[string]string{facts.KeyHWVendor: "Palo Alto Networks", facts.KeyHWModel: "PA-3220"} {
		var got string
		if err := owner.QueryRowContext(ctx, `SELECT value #>> '{}' FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key=$3`,
			tenant, device, key).Scan(&got); err != nil {
			t.Errorf("fact %s was not recorded for a zero-asset run: %v", key, err)
			continue
		}
		if got != want {
			t.Errorf("fact %s = %q, want %q", key, got, want)
		}
	}
	var serials int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='serial_number' AND value='013201001234'`,
		tenant, device).Scan(&serials); err != nil {
		t.Fatal(err)
	}
	if serials != 1 {
		t.Errorf("serial identifier rows = %d, want 1 — the device's serial was lost with its assets", serials)
	}
}

// With no interrogated device on the job there is nothing to own an
// address-less finding. It is not written — and the job's processing block
// says so, rather than the row being written and then dropped downstream
// without a word.
func TestIntegration_AddressLessFindingWithNoDevice_IsReportedNotSilentlyDropped(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	agent := insertDeviceAgent(t, owner, tenant)
	jobID := uuid.New()
	if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, 'in_progress')`, jobID, tenant, agent); err != nil {
		t.Fatalf("seed device_job: %v", err)
	}
	result := &models.JobResult{JobID: jobID, Success: true, CompletedAt: time.Now().UTC(), Assets: []models.DiscoveredAsset{
		{Hostname: "decrypt-rule.example.test", Protocol: "TLS", Port: 443, AssetType: "firewall",
			Metadata: map[string]interface{}{"rule_name": "decrypt-rule.example.test"}},
	}}
	if err := NewResultProcessor(app, owner).ProcessJobResults(ctx, jobID, result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	var written int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM sensor_discoveries WHERE tenant_id=$1 AND metadata->>'config_name'='decrypt-rule.example.test'`,
		tenant).Scan(&written); err != nil {
		t.Fatal(err)
	}
	if written != 0 {
		t.Errorf("an ownerless address-less finding was written (%d rows) — it can only be dropped downstream", written)
	}
	var skipped int
	if err := owner.QueryRowContext(ctx, `SELECT (results->'processing'->>'discoveries_skipped')::int FROM device_jobs WHERE id=$1`, jobID).Scan(&skipped); err != nil {
		t.Fatalf("read processing block: %v", err)
	}
	if skipped != 1 {
		t.Errorf("discoveries_skipped = %d, want 1 — the drop must be visible on the job", skipped)
	}
}
