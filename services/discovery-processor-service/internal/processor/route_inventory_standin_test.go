package processor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/network/addrscope"
)

// routeInventoryStandIn is inventory-service's discovery import as
// discovery-processor sees it after WP3: ONE route,
// POST /api/v1/inventory-service/discovery/jobs/:id/import, which classifies
// every finding, evaluates the tenant's rules and either resolves the finding
// to an asset or writes it to external_connections.
//
// The response is the real handler's shape (IngestPipelineFindings: imported,
// asset_statuses and results, index-aligned with the request), with the
// decisions inventory makes:
//
//   - a third-party finding (by the ownership table, else by address class) is
//     `routed` — or, with no source_ip in its raw_data, `dropped` with reason
//     third_party_no_source_ip (D2) — and lands on no asset;
//   - an interrogation finding naming a known device lands on it, `matched`;
//   - a host observation is never third party;
//   - anything else creates an asset: `monitoring` and the rule's id when the
//     rules table names one for its address, `pending_approval` otherwise.
//
// Every other path is recorded and answered 404, so a test can assert the
// processor called nothing else — classify-asset and external-connections
// least of all.
type routeInventoryStandIn struct {
	mu  sync.Mutex
	srv *httptest.Server
	// ownership overrides the address-class answer for a destination.
	ownership map[string]string
	// rules names the auto-approval rule that matches a destination.
	rules map[string]uuid.UUID
	// devices are interrogated devices (asset id → status) whose claim
	// verifies: an interrogation finding naming one lands on it, `matched`,
	// before any routing — inventory's interrogation-owned ingest.
	devices map[string]string
	// imports is every import request's findings, in call order.
	imports [][]converter.IngestFinding
	// routed is every finding the stand-in wrote to "external_connections".
	routed []converter.IngestFinding
	// otherPaths is every request to any other path.
	otherPaths []string
}

const routeImportSuffix = "/import"

func newRouteInventoryStandIn(t *testing.T) *routeInventoryStandIn {
	t.Helper()
	s := &routeInventoryStandIn{ownership: map[string]string{}, rules: map[string]uuid.UUID{}, devices: map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// client is an InventoryClient pointed at the stand-in.
func (s *routeInventoryStandIn) client(t *testing.T) *client.InventoryClient {
	t.Helper()
	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: s.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (s *routeInventoryStandIn) serve(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, "/api/v1/inventory-service/discovery/jobs/") ||
		!strings.HasSuffix(req.URL.Path, routeImportSuffix) {
		s.mu.Lock()
		s.otherPaths = append(s.otherPaths, req.Method+" "+req.URL.Path)
		s.mu.Unlock()
		http.NotFound(w, req)
		return
	}
	var body struct {
		Findings []converter.IngestFinding `json:"findings"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imports = append(s.imports, body.Findings)
	statuses := make([]string, len(body.Findings))
	results := make([]identity.IngestResult, len(body.Findings))
	imported := 0
	for i, f := range body.Findings {
		ip := ""
		if f.IPAddress != nil {
			ip = *f.IPAddress
		}
		if f.RawData["discovery_method"] == "device_interrogation" {
			if owner, _ := f.RawData["source_asset_id"].(string); owner != "" {
				if status, ok := s.devices[owner]; ok {
					results[i] = identity.IngestResult{Outcome: string(identity.OutcomeMatched), AssetID: owner}
					statuses[i] = status
					imported++
					continue
				}
			}
		}
		if f.Kind != converter.KindHostObservation && s.ownershipOf(ip) == "third_party" {
			if src, _ := f.RawData["source_ip"].(string); strings.TrimSpace(src) == "" {
				results[i] = identity.IngestResult{Outcome: outcomeDropped, Reason: dropReasonThirdPartyNoSourceIP}
				continue
			}
			s.routed = append(s.routed, f)
			results[i] = identity.IngestResult{Outcome: outcomeRouted}
			imported++
			continue
		}
		results[i] = identity.IngestResult{Outcome: string(identity.OutcomeCreated), AssetID: uuid.NewString()}
		statuses[i] = "pending_approval"
		if rule, ok := s.rules[ip]; ok {
			statuses[i] = "monitoring"
			results[i].AutoApprovalRuleID = rule.String()
		}
		imported++
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"imported":       imported,
		"asset_statuses": statuses,
		"results":        results,
	})
}

// ownershipOf is the table's answer, else inventory's address-class rule:
// an internal candidate (private or CGNAT) is unknown, anything else
// third_party.
func (s *routeInventoryStandIn) ownershipOf(ip string) string {
	if o, ok := s.ownership[ip]; ok {
		return o
	}
	if sc := addrscope.ClassifyString(ip); sc == addrscope.Private || sc == addrscope.CGNAT {
		return "unknown"
	}
	return "third_party"
}

// allImported is every finding the processor imported, in order.
func (s *routeInventoryStandIn) allImported() []converter.IngestFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []converter.IngestFinding
	for _, batch := range s.imports {
		out = append(out, batch...)
	}
	return out
}

// routedFindings is every finding written to external_connections.
func (s *routeInventoryStandIn) routedFindings() []converter.IngestFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]converter.IngestFinding(nil), s.routed...)
}

// assertOnlyImports fails when the processor called anything but the import.
func (s *routeInventoryStandIn) assertOnlyImports(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.otherPaths) != 0 {
		t.Fatalf("the processor called %v; since #2374 WP3 it calls only the import (no classify-asset, no external-connections)", s.otherPaths)
	}
}
