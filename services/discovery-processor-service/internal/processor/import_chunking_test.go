package processor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// The import must go over in pieces small enough to answer inside
// client.ImportTimeout.
//
// It used to go in ONE call per batch, and inventory-service's side of it is
// O(n): per finding it resolves identity, scores catalogue risk and publishes
// an event. Seeding a 4-site tenant on a dev cluster produced batches of 338, 208 and
// 156 findings; all three blew the 30s deadline on every attempt, exhausted
// the retry ladder, and had their rows marked `approval_status=rejected` —
// while inventory-service, which never learned the client had gone, completed
// each import anyway, three times over. Success and failure disagreed,
// and the operator was shown the failure.
//
// This test pins the shape — every call small enough, nothing dropped. The
// arithmetic that makes that size the RIGHT size is pinned separately, below.
func TestImportIsChunkedToFitTheClientTimeout(t *testing.T) {
	const findings = 200

	var mu sync.Mutex
	var callSizes []int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		callSizes = append(callSizes, len(body.Findings))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"imported": len(body.Findings)})
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	p := &BatchProcessor{inventoryClient: c}

	batch := make([]converter.IngestFinding, findings)
	for i := range batch {
		h := fmt.Sprintf("host-%03d.example.test", i)
		batch[i] = converter.IngestFinding{Kind: "crypto", Hostname: &h}
	}

	rows := make([]*models.SensorDiscovery, findings)
	for i := range rows {
		rows[i] = &models.SensorDiscovery{ID: uuid.New(), ApprovalStatus: "pending"}
	}

	imported, err := p.importInChunks(uuid.New(), uuid.New(), batch, rows, "monitoring")
	if err != nil {
		t.Fatalf("importInChunks: %v", err)
	}
	if imported != findings {
		t.Fatalf("imported %d findings, sent %d", imported, findings)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(callSizes) < 2 {
		t.Fatalf("%d findings went to inventory-service in %d call(s) — the import is not chunked", findings, len(callSizes))
	}
	total := 0
	for i, n := range callSizes {
		if n > importChunkSize {
			t.Errorf("call %d carried %d findings, over the %d chunk size", i, n, importChunkSize)
		}
		total += n
	}
	if total != findings {
		t.Errorf("inventory-service received %d findings, batch held %d", total, findings)
	}
}

// The chunk size is only correct relative to the timeout it has to fit inside.
// This is the arithmetic the fix rests on; it fails if either side moves
// without the other.
func TestImportChunkFitsInsideTheTimeout(t *testing.T) {
	// The slowest per-finding cost observed on a dev cluster while diagnosing
	// the original timeout.
	const slowestObserved = 280 * time.Millisecond

	worstChunk := time.Duration(importChunkSize) * slowestObserved
	if worstChunk >= client.ImportTimeout {
		t.Fatalf("a chunk of %d findings needs %v at the slowest observed rate, but the client gives up at %v — every batch would fail the way #1782 did",
			importChunkSize, worstChunk, client.ImportTimeout)
	}
	// Leave real headroom for a far side slower than anything measured, rather
	// than passing on a margin of milliseconds.
	if worstChunk > client.ImportTimeout/2 {
		t.Errorf("a chunk needs %v of the %v budget — too little headroom for a slower far side", worstChunk, client.ImportTimeout)
	}
}

// A finding that lands on an asset the tenant is ALREADY monitoring must not
// leave its discovery row `pending`.
//
// The row's status comes from the auto-approval rules, which are evaluated over
// the row — so the same access point seen on an address in no registered
// segment matches no rule and arrives `pending_approval`. inventory-service
// materializes it anyway, because the asset it matched is monitoring, and the
// row is then pending with nothing that will ever clear it: Discovery →
// Approvals lists pending ASSETS, and this asset is not one. Eleven access
// points and eighty host observations sat like that on a dev cluster.
//
// This drives the real import path — the HTTP call, the chunking, and the
// stamping — against a fake inventory-service. The mutation that proves it:
// delete the adoptEffectiveStatus call from importInChunks and the first
// subtest goes red.
func TestImportAdoptsTheStatusTheAssetActuallyHas(t *testing.T) {
	// Two chunks' worth, so the alignment is exercised across the chunk
	// boundary rather than only within the first call.
	const findings = importChunkSize + 7
	// Every third finding matched an asset that is already monitoring.
	monitoring := func(i int) bool { return i%3 == 0 }

	var mu sync.Mutex
	seen := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		offset := seen
		seen += len(body.Findings)
		mu.Unlock()

		statuses := make([]string, len(body.Findings))
		for i := range statuses {
			statuses[i] = "pending_approval"
			if monitoring(offset + i) {
				statuses[i] = "monitoring"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"imported":       len(body.Findings),
			"asset_statuses": statuses,
		})
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	p := &BatchProcessor{inventoryClient: c}

	batch := make([]converter.IngestFinding, findings)
	rows := make([]*models.SensorDiscovery, findings)
	for i := range batch {
		h := fmt.Sprintf("ap-%03d.example.test", i)
		batch[i] = converter.IngestFinding{Kind: "crypto", Hostname: &h}
		rows[i] = &models.SensorDiscovery{ID: uuid.New(), ApprovalStatus: "pending"}
	}

	if _, err := p.importInChunks(uuid.New(), uuid.New(), batch, rows, "pending_approval"); err != nil {
		t.Fatalf("importInChunks: %v", err)
	}

	t.Run("rows whose asset is monitoring are no longer pending", func(t *testing.T) {
		for i, row := range rows {
			want := "pending"
			if monitoring(i) {
				want = "auto_approved"
			}
			if row.ApprovalStatus != want {
				t.Fatalf("row %d: approval_status = %q, want %q — the discovery's data was materialized "+
					"but the row says it is still waiting for an approval nothing will ever give it",
					i, row.ApprovalStatus, want)
			}
		}
	})

	t.Run("no rule is claimed", func(t *testing.T) {
		// No auto-approval rule fired; the asset simply already existed. A rule
		// id here would credit a rule that did not match.
		for i, row := range rows {
			if row.AutoApprovalRuleID != nil {
				t.Fatalf("row %d carries auto_approval_rule_id %s, but no rule matched it", i, row.AutoApprovalRuleID)
			}
		}
	})
}

// An inventory-service that does not send the statuses — one older than the
// field — must leave every row exactly as it was. The cross-service change has
// to be deployable in either order.
func TestImportLeavesRowsAloneWhenInventoryIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"imported": len(body.Findings)})
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	p := &BatchProcessor{inventoryClient: c}

	h := "silent.example.test"
	batch := []converter.IngestFinding{{Kind: "crypto", Hostname: &h}}
	rows := []*models.SensorDiscovery{{ID: uuid.New(), ApprovalStatus: "pending"}}

	if _, err := p.importInChunks(uuid.New(), uuid.New(), batch, rows, "pending_approval"); err != nil {
		t.Fatalf("importInChunks: %v", err)
	}
	if rows[0].ApprovalStatus != "pending" {
		t.Fatalf("approval_status = %q, want it untouched at %q", rows[0].ApprovalStatus, "pending")
	}
}

// A finding that matched an asset the tenant took off the table — archived or
// denied — must land `suppressed`, not `pending` forever. asset_service.go
// IngestFindings materializes nothing for either status, and no approval
// decision will ever be made about the row: it is not in Discovery →
// Approvals (there is no pending asset) and it is not auto-approved (nothing
// was approved).
//
// Mutation that proves it: delete the `case "archived", "denied":` arm from
// adoptEffectiveStatus — this test goes red while
// TestImportAdoptsTheStatusTheAssetActuallyHas stays green, so the two must be
// pinned separately.
func TestImportSuppressesRowsOnArchivedOrDeniedAssets(t *testing.T) {
	statuses := []string{"archived", "denied", "monitoring", "pending_approval"}

	var mu sync.Mutex
	seen := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		offset := seen
		seen += len(body.Findings)
		mu.Unlock()

		out := make([]string, len(body.Findings))
		for i := range out {
			out[i] = statuses[(offset+i)%len(statuses)]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"imported":       len(body.Findings),
			"asset_statuses": out,
		})
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	p := &BatchProcessor{inventoryClient: c}

	const findings = 8
	batch := make([]converter.IngestFinding, findings)
	rows := make([]*models.SensorDiscovery, findings)
	for i := range batch {
		h := fmt.Sprintf("taken-off-table-%03d.example.test", i)
		batch[i] = converter.IngestFinding{Kind: "crypto", Hostname: &h}
		rows[i] = &models.SensorDiscovery{ID: uuid.New(), ApprovalStatus: "pending"}
	}

	if _, err := p.importInChunks(uuid.New(), uuid.New(), batch, rows, "pending_approval"); err != nil {
		t.Fatalf("importInChunks: %v", err)
	}

	want := map[string]string{
		"archived":         "suppressed",
		"denied":           "suppressed",
		"monitoring":       "auto_approved",
		"pending_approval": "pending",
	}
	for i, row := range rows {
		expected := want[statuses[i%len(statuses)]]
		if row.ApprovalStatus != expected {
			t.Errorf("row %d (asset status %q): approval_status = %q, want %q",
				i, statuses[i%len(statuses)], row.ApprovalStatus, expected)
		}
	}
}

// A host observation's discovery row is identity evidence, never a finding
// awaiting approval — so it must land `observed`, whatever status the asset it
// matched (or created) ends up with. Unlike a crypto finding, `observed` is
// decided BEFORE inventory-service is even called (there is no crypto to
// materialize either way), and adoptEffectiveStatus must not correct it back
// to `auto_approved`/`suppressed`/anything else afterward.
//
// Mutation that proves it: delete the `if hostObservation` arm that sets
// `observed`, or delete the `isHostObservationDiscovery` guard inside
// adoptEffectiveStatus — either one turns this row `auto_approved`.
func TestHostObservationRowsAreObservedNotPendingOrApproved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// The asset this host observation matched is already monitoring — the
		// exact case adoptEffectiveStatus exists to correct for a CRYPTO
		// finding, and the one this test proves must NOT apply here.
		statuses := make([]string, len(body.Findings))
		for i := range statuses {
			statuses[i] = "monitoring"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"imported":       len(body.Findings),
			"asset_statuses": statuses,
		})
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatalf("NewInventoryClient: %v", err)
	}
	p := &BatchProcessor{inventoryClient: c}

	h := "presence-only.example.test"
	batch := []converter.IngestFinding{{Kind: converter.KindHostObservation, Hostname: &h}}
	metadata, _ := json.Marshal(map[string]interface{}{"discovery_type": "host_observation"})
	rows := []*models.SensorDiscovery{{ID: uuid.New(), ApprovalStatus: "observed", Metadata: metadata}}

	if _, err := p.importInChunks(uuid.New(), uuid.New(), batch, rows, "monitoring"); err != nil {
		t.Fatalf("importInChunks: %v", err)
	}
	if rows[0].ApprovalStatus != "observed" {
		t.Fatalf("approval_status = %q, want %q — a host observation must never be corrected to a crypto-finding "+
			"disposition, even when it matched a monitoring asset", rows[0].ApprovalStatus, "observed")
	}
}

// A length the response and the request disagree on describes no row at its
// index, so nothing may be stamped from it.
func TestAdoptEffectiveStatusRefusesAMisalignedAnswer(t *testing.T) {
	rows := []*models.SensorDiscovery{
		{ID: uuid.New(), ApprovalStatus: "pending"},
		{ID: uuid.New(), ApprovalStatus: "pending"},
	}
	adoptEffectiveStatus(rows, []string{"monitoring"})
	for i, row := range rows {
		if row.ApprovalStatus != "pending" {
			t.Fatalf("row %d was stamped %q from a response of the wrong length", i, row.ApprovalStatus)
		}
	}
}
