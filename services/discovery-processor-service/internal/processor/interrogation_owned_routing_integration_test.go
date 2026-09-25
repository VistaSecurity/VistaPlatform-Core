package processor

// Interrogation findings with a public address or no address reach inventory
// on the managed path, carrying the interrogated device's asset id ( W2.2,
// finding P-11). They used to classify third_party, have no source IP, and be
// dropped by the external-connections branch with a stdout warning while the
// interrogation job reported success.
//
// Drives the REAL batch processor over real sensor_discoveries rows; the
// inventory HTTP boundary is recorded, so the test asserts which door each row
// used and what crossed it.
//
// Skips without TEST_DATABASE_URL.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type ownedRoutingRecorder struct {
	mu       sync.Mutex
	device   uuid.UUID
	external []client.ExternalConnectionUpsert
	imported []converter.IngestFinding
	srv      *httptest.Server
}

func newOwnedRoutingRecorder(t *testing.T, device uuid.UUID) *ownedRoutingRecorder {
	t.Helper()
	r := &ownedRoutingRecorder{device: device}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/api/v2/inventory-service/network-segments/classify-asset":
			// What inventory-service answers: neither 0.0.0.0 nor a
			// documentation-range public address is in any segment.
			_ = json.NewEncoder(w).Encode(map[string]any{"ownership": "third_party", "network_type": "public"})
		case "/api/v2/inventory-service/external-connections":
			var body client.ExternalConnectionUpsert
			_ = json.NewDecoder(req.Body).Decode(&body)
			r.mu.Lock()
			r.external = append(r.external, body)
			r.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"id": uuid.New().String()})
		default:
			var body struct {
				Findings []converter.IngestFinding `json:"findings"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.mu.Lock()
			r.imported = append(r.imported, body.Findings...)
			r.mu.Unlock()
			// What inventory-service answers for an owned finding: it landed
			// on the device, which is monitoring.
			statuses := make([]string, len(body.Findings))
			results := make([]map[string]string, len(body.Findings))
			for i := range body.Findings {
				statuses[i] = "monitoring"
				results[i] = map[string]string{"outcome": "matched", "asset_id": r.device.String()}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(body.Findings), "asset_statuses": statuses, "results": results})
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func TestIntegration_InterrogationFindings_PublicAndAddressLessReachInventoryOwned(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	device := uuid.New()

	recorder := newOwnedRoutingRecorder(t, device)
	inventory, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: recorder.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordingSink{}
	processor := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), approval.NewService(raw), inventory, audit)

	batchID, sensorID := uuid.New().String(), uuid.New()
	insert := func(destIP string, port int, hostname string, metadata map[string]any) uuid.UUID {
		t.Helper()
		id := uuid.New()
		blob, _ := json.Marshal(metadata)
		var host any
		if hostname != "" {
			host = hostname
		}
		if _, err := raw.Exec(`INSERT INTO sensor_discoveries
			(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,hostname,timestamp,created_at)
			VALUES($1,$2,$3,$4,'TLS',$5::inet,$6,0.95,$7::jsonb,$8,now(),now())`,
			id, sensorID, tenant, batchID, destIP, port, blob, host); err != nil {
			t.Fatal(err)
		}
		return id
	}
	owned := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"discovery_method": "device_interrogation", "version": "TLS 1.2",
			"device_id": device.String(), "source_device_id": device.String(),
			"source_asset_id": device.String(),
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// A PAN-OS decrypting rule: a label, no address. An invalid MAC rides
	// along to prove the forwarded subset is re-checked on receipt.
	ruleRow := insert("0.0.0.0", 443, "postgres", owned(map[string]any{
		"config_name": "postgres", "mac_address": "ff:ff:ff:ff:ff:ff",
	}))
	// An F5 virtual server on a public (documentation-range) address.
	vipRow := insert("203.0.113.30", 443, "", owned(map[string]any{
		"config_name": "/Common/shop_vs", "profile_name": "/Common/clientssl",
	}))
	// Control: a sensor's public third-party row with no source IP is still
	// not something this service can record — the change is scoped to rows
	// that name an interrogated device.
	sensorRow := insert("203.0.113.99", 443, "", map[string]any{"discovery_method": "passive"})

	// No reverse DNS for an interrogation row: the public VIP's name is the
	// collector's label, not whatever somebody's PTR record says. The sensor
	// control row is still looked up, which is what proves the resolver is
	// wired at all — a recorder that nothing calls would pass either way.
	var ptrAsked []string
	previousPTR := lookupPTR
	lookupPTR = func(ip string) string {
		ptrAsked = append(ptrAsked, ip)
		if ip == "203.0.113.30" {
			t.Errorf("reverse-resolved the interrogated VIP %s", ip)
		}
		return ""
	}
	t.Cleanup(func() { lookupPTR = previousPTR })

	if err := processor.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(ptrAsked) != 1 || ptrAsked[0] != "203.0.113.99" {
		t.Errorf("PTR lookups = %v, want exactly the sensor control row's 203.0.113.99", ptrAsked)
	}

	recorder.mu.Lock()
	imported := append([]converter.IngestFinding(nil), recorder.imported...)
	external := append([]client.ExternalConnectionUpsert(nil), recorder.external...)
	recorder.mu.Unlock()

	if len(external) != 0 {
		t.Errorf("routed to external_connections: %+v — an interrogated device's own configuration is not a connection", external)
	}
	byLabel := map[string]converter.IngestFinding{}
	for _, f := range imported {
		label, _ := f.RawData["config_name"].(string)
		byLabel[label] = f
	}
	for _, label := range []string{"postgres", "/Common/shop_vs"} {
		f, ok := byLabel[label]
		if !ok {
			t.Fatalf("%q was not imported — an interrogation finding was dropped (imported: %d rows)", label, len(imported))
		}
		if f.RawData["source_asset_id"] != device.String() {
			t.Errorf("%q: source_asset_id = %v, want the interrogated device", label, f.RawData["source_asset_id"])
		}
	}
	if h := byLabel["/Common/shop_vs"].Hostname; h != nil {
		t.Errorf("the interrogated VIP was given hostname %q; it has none of its own", *h)
	}
	if _, ok := byLabel["postgres"].RawData["mac_address"]; ok {
		t.Error("an invalid forwarded mac_address survived receipt sanitisation")
	}
	for _, f := range imported {
		if f.IPAddress != nil && *f.IPAddress == "203.0.113.99" {
			t.Error("the unclaimed sensor row was imported as if an interrogated device owned it")
		}
	}

	// The owned rows are settled onto the device.
	for _, id := range []uuid.UUID{ruleRow, vipRow} {
		var status string
		var asset *uuid.UUID
		if err := raw.QueryRow(`SELECT approval_status, asset_id FROM sensor_discoveries WHERE tenant_id=$1 AND id=$2 AND processed_at IS NOT NULL`,
			tenant, id).Scan(&status, &asset); err != nil {
			t.Fatalf("owned row %s was not processed: %v", id, err)
		}
		if asset == nil || *asset != device {
			t.Errorf("row %s asset_id = %v, want the device %s", id, asset, device)
		}
		if status != "auto_approved" {
			t.Errorf("row %s approval_status = %q, want auto_approved (it landed on a monitoring device)", id, status)
		}
	}
	// The unclaimed row still takes the old branch: never imported, never an
	// asset, left for the batch audit's third_party_dropped_no_source_ip count.
	// …and the drop is counted on the batch's audit record, not only printed.
	events := audit.all()
	if len(events) != 1 || events[0].Counts["third_party_dropped_no_source_ip"] != 1 {
		t.Errorf("audit events = %+v, want one batch record counting 1 dropped third-party row", events)
	}
	var sensorAsset *uuid.UUID
	if err := raw.QueryRow(`SELECT asset_id FROM sensor_discoveries WHERE tenant_id=$1 AND id=$2`, tenant, sensorRow).Scan(&sensorAsset); err != nil {
		t.Fatal(err)
	}
	if sensorAsset != nil {
		t.Errorf("the unclaimed sensor row was attached to asset %s", *sensorAsset)
	}
}
