package processor

// This drives host-inventory connection rows through the real batch processor
// and a real approval-rule table. The inventory HTTP boundary is recorded so
// the test can assert which door each ownership class used and which source
// asset crossed that wire.

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

type hostConnectionInventoryRecorder struct {
	mu       sync.Mutex
	segment  uuid.UUID
	external []client.ExternalConnectionUpsert
	imports  map[string][]converter.IngestFinding
	srv      *httptest.Server
}

func newHostConnectionInventoryRecorder(t *testing.T, segment uuid.UUID) *hostConnectionInventoryRecorder {
	t.Helper()
	r := &hostConnectionInventoryRecorder{segment: segment, imports: make(map[string][]converter.IngestFinding)}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/api/v2/inventory-service/network-segments/classify-asset":
			var body struct {
				IP string `json:"ip_address"`
			}
			_ = json.NewDecoder(req.Body).Decode(&body)
			switch body.IP {
			case "8.8.8.8":
				_ = json.NewEncoder(w).Encode(map[string]any{"ownership": "third_party", "network_type": "public"})
			case "10.40.0.15":
				_ = json.NewEncoder(w).Encode(map[string]any{"ownership": "internal", "network_type": "private", "segment_id": r.segment.String()})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"ownership": "unknown", "network_type": "private"})
			}
		case "/api/v2/inventory-service/external-connections":
			var body client.ExternalConnectionUpsert
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.mu.Lock()
			r.external = append(r.external, body)
			r.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"id": uuid.New().String()})
		default:
			var body struct {
				Findings    []converter.IngestFinding `json:"findings"`
				AssetStatus *string                   `json:"asset_status"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			status := ""
			if body.AssetStatus != nil {
				status = *body.AssetStatus
			}
			r.mu.Lock()
			r.imports[status] = append(r.imports[status], body.Findings...)
			r.mu.Unlock()
			statuses := make([]string, len(body.Findings))
			for i := range statuses {
				statuses[i] = status
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(body.Findings), "asset_statuses": statuses})
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func TestIntegration_HostConnectionsUseOwnershipApprovalAndSourceAssetRouting(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	segmentID, ruleID, sourceAssetID := uuid.New(), uuid.New(), uuid.New()
	if _, err := raw.Exec(`INSERT INTO discovery_auto_approval_rules(id,tenant_id,name,query,is_active)
		VALUES($1,$2,'approve measured segment',$3,true)`, ruleID, tenant, "network.segment_id="+segmentID.String()); err != nil {
		t.Fatal(err)
	}

	recorder := newHostConnectionInventoryRecorder(t, segmentID)
	inventory, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: recorder.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	processor := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), approval.NewService(raw), inventory, nil)

	batchID, sensorID := uuid.New().String(), uuid.New()
	for _, peer := range []struct {
		ip   string
		port int
	}{{"8.8.8.8", 443}, {"10.40.0.15", 8443}, {"10.50.0.15", 9443}} {
		metadata, _ := json.Marshal(map[string]any{
			"discovery_method": "host_inventory", "discovery_type": "host_connection",
			"source_asset_id": sourceAssetID.String(), "source_agent_id": uuid.New().String(),
		})
		if _, err := raw.Exec(`INSERT INTO sensor_discoveries
			(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,source_ip,timestamp,created_at)
			VALUES($1,$2,$3,$4,'tcp',$5::inet,$6,1,$7::jsonb,'10.1.2.3'::inet,now(),now())`,
			uuid.New(), sensorID, tenant, batchID, peer.ip, peer.port, metadata); err != nil {
			t.Fatal(err)
		}
	}

	if err := processor.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	recorder.mu.Lock()
	external := append([]client.ExternalConnectionUpsert(nil), recorder.external...)
	monitoring := append([]converter.IngestFinding(nil), recorder.imports["monitoring"]...)
	pending := append([]converter.IngestFinding(nil), recorder.imports["pending_approval"]...)
	recorder.mu.Unlock()
	if len(external) != 1 || external[0].DestIP != "8.8.8.8" || external[0].SourceAssetID == nil || *external[0].SourceAssetID != sourceAssetID {
		t.Fatalf("public route = %#v, want one external upsert attributed to host %s", external, sourceAssetID)
	}
	if len(monitoring) != 1 || monitoring[0].IPAddress == nil || *monitoring[0].IPAddress != "10.40.0.15" {
		t.Fatalf("registered private route = %#v, want monitoring import", monitoring)
	}
	if len(pending) != 1 || pending[0].IPAddress == nil || *pending[0].IPAddress != "10.50.0.15" {
		t.Fatalf("unregistered private route = %#v, want pending import", pending)
	}
	for _, finding := range append(monitoring, pending...) {
		if finding.RawData["source_asset_id"] != sourceAssetID.String() {
			t.Errorf("managed fallback dropped source_asset_id: %#v", finding.RawData)
		}
	}

	rows, err := raw.Query(`SELECT host(dest_ip),approval_status,auto_approval_rule_id FROM sensor_discoveries
		WHERE tenant_id=$1 AND batch_id=$2 ORDER BY host(dest_ip)`, tenant, batchID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	want := map[string]struct {
		status string
		rule   *uuid.UUID
	}{
		"8.8.8.8":    {"auto_approved", nil},
		"10.40.0.15": {"auto_approved", &ruleID},
		"10.50.0.15": {"pending", nil},
	}
	for rows.Next() {
		var ip, status string
		var gotRule *uuid.UUID
		if err := rows.Scan(&ip, &status, &gotRule); err != nil {
			t.Fatal(err)
		}
		expect := want[ip]
		if status != expect.status || (expect.rule != nil && (gotRule == nil || *gotRule != *expect.rule)) || (expect.rule == nil && gotRule != nil) {
			t.Errorf("%s status/rule = %s/%v, want %s/%v", ip, status, gotRule, expect.status, expect.rule)
		}
		delete(want, ip)
	}
	if len(want) != 0 {
		t.Fatalf("missing processed discoveries: %#v", want)
	}
}
