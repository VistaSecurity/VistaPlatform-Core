package processor

// The drift guard.
//
// `identity.OutcomeSupporting` was added to shared/identity by and
// shipped in core-v1.0.0. applyIngestOutcome's switch never learned it, so
// every batch carrying one supporting finding errored, was retried three times
// as a transient failure, and then had ALL of its rows marked
// `approval_status = 'rejected'` with `processed_at` set — 5,006 rows on the
// dev cluster, ~500/hour, invisible because a rejected row reads as a decision
// rather than as evidence discarded.
//
// The fix for that one outcome is a switch arm. The fix for the CLASS of bug is
// this file: shared/identity's Outcome set and this service's switch could
// drift apart with nothing noticing, and this test is the something that
// notices. It reads the constants out of shared/identity's SOURCE — not a
// hand-maintained list in this package, which would be the same drift one level
// removed — and drives the real switch with each one.
//
// Mutation-proven: adding a seventh `Outcome` constant to shared/identity turns
// TestEveryIdentityOutcomeIsHandled red; removing it turns it green again.

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// identityPackageDir is shared/identity relative to this package's directory,
// which is where `go test` runs.
const identityPackageDir = "../../../../shared/identity"

func TestEveryIdentityOutcomeIsHandled(t *testing.T) {
	outcomes := declaredIdentityOutcomes(t)

	for _, outcome := range outcomes {
		t.Run(outcome, func(t *testing.T) {
			row := &models.SensorDiscovery{ID: uuid.New(), ApprovalStatus: "pending"}
			// ObservationID and AssetID are populated so the only thing that
			// can fail is the switch itself: an `unresolved` with neither trips
			// the durable-receipt contract check, which is a different error
			// and a different rule.
			err := applyIngestOutcome(row, identity.IngestResult{
				Outcome:       outcome,
				AssetID:       uuid.NewString(),
				ObservationID: uuid.NewString(),
			})
			if errors.Is(err, errUnknownIngestOutcome) {
				t.Fatalf("shared/identity declares Outcome %q and applyIngestOutcome has no arm for it.\n"+
					"Left alone, every batch containing one of these rows loses ALL of its rows to "+
					"markBatchAsFailed — that is exactly how 5,006 rows were rejected on the dev cluster. "+
					"Add the arm, and say what the discovery row's honest terminal state is.", outcome)
			}
			if err != nil {
				t.Fatalf("applyIngestOutcome(%q): %v", outcome, err)
			}
		})
	}
}

// declaredIdentityOutcomes reads every `Outcome` constant out of
// shared/identity's source.
//
// Parsing the source rather than asking the package for a list is deliberate: a
// `var AllOutcomes = []Outcome{...}` in shared/identity would be a second
// registry that the next new constant could be forgotten from just as easily as
// it was forgotten from the switch, and the guard would then pass while the
// drift it exists to catch was happening.
func declaredIdentityOutcomes(t *testing.T) []string {
	t.Helper()

	if _, err := os.Stat(identityPackageDir); err != nil {
		t.Fatalf("cannot reach shared/identity at %s: %v — this guard cannot run, and a guard that cannot run is worse than none",
			identityPackageDir, err)
	}

	entries, err := os.ReadDir(identityPackageDir)
	if err != nil {
		t.Fatalf("reading %s: %v", identityPackageDir, err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		// Test files may declare fixtures of the same type; those are not part
		// of the contract this service has to honour.
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(identityPackageDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		if file.Name.Name != "identity" {
			continue
		}
		files = append(files, file)
		names = append(names, name)
	}
	if len(files) == 0 {
		t.Fatalf("no `identity` source files found in %s", identityPackageDir)
	}

	var outcomes []string
	seen := map[string]bool{}
	for i, file := range files {
		name := names[i]
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			// Within one const block a spec that omits BOTH type and value
			// repeats the previous spec's (the iota form), so carry the type
			// forward for those and recompute it for every other spec — a
			// `B = "b"` following `A Outcome = "a"` is an untyped string, not
			// an Outcome.
			carried := ""
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				typeName := ""
				switch {
				case vs.Type == nil && len(vs.Values) == 0:
					typeName = carried
				default:
					if id, ok := vs.Type.(*ast.Ident); ok {
						typeName = id.Name
					}
					carried = typeName
				}
				if typeName != "Outcome" {
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: an Outcome constant is not a plain string literal; this guard can no longer read the set", name)
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s: unquoting %s: %v", name, lit.Value, err)
					}
					if !seen[value] {
						seen[value] = true
						outcomes = append(outcomes, value)
					}
				}
			}
		}
	}

	// A parser that silently found nothing would pass this test for every
	// outcome there is. Pin the floor and two known members — one from the
	// original set, one from the set that drifted.
	if len(outcomes) < 6 {
		t.Fatalf("found only %d Outcome constant(s) in %s (%v) — the parse is wrong, not shared/identity",
			len(outcomes), identityPackageDir, outcomes)
	}
	for _, want := range []string{string(identity.OutcomeMatched), string(identity.OutcomeSupporting)} {
		if !seen[want] {
			t.Fatalf("Outcome %q is declared in shared/identity but this parse did not find it: %v", want, outcomes)
		}
	}
	return outcomes
}

// The other half of the same defect: the batch must survive a row whose outcome
// this build genuinely cannot interpret.
//
// Before the fix this returned an error, which the poller classified as
// transient, retried three times and then resolved with markBatchAsFailed —
// stamping `processed_at` and `approval_status = 'rejected'` on every row in
// the batch, including the ones that imported perfectly.
func TestAnUnknownOutcomeDoesNotCostTheRow(t *testing.T) {
	rule := uuid.New()
	row := &models.SensorDiscovery{ID: uuid.New(), ApprovalStatus: "pending", AutoApprovalRuleID: &rule}

	err := applyIngestOutcome(row, identity.IngestResult{Outcome: "a-future-outcome", AssetID: uuid.NewString()})
	if !errors.Is(err, errUnknownIngestOutcome) {
		t.Fatalf("applyIngestOutcome reported %v for an outcome it cannot know; the caller needs errUnknownIngestOutcome to tell it apart from a real failure", err)
	}
	if row.ApprovalStatus != "pending" || row.AutoApprovalRuleID == nil {
		t.Fatalf("an uninterpretable outcome rewrote the row's state: %+v — it must keep what the rules gave it", row)
	}
}

// The wiring, not just the helper.
//
// The defect lived in importInChunks' loop, and the loss happened in the
// poller: one unhandled outcome made importInChunks return an error, which
// ProcessBatch wrapped, which the poller retried three times and then resolved
// with markBatchAsFailed — rejecting EVERY row in the batch, including the ones
// inventory-service had already materialized.
//
// So drive the real import: the HTTP call, the chunking, the stamping.
//
// It asserts on the WARNING as well as on the rows, and that is deliberate.
// With the unknown-outcome half of this fix in place, a missing arm no longer
// fails the import — so "the batch survived" alone would pass with
// `supporting` unhandled, and the test would be measuring nothing. The
// mutation that proves it: delete `string(identity.OutcomeSupporting)` from
// applyIngestOutcome's switch and this test goes red.
func TestASupportingRowDoesNotCostTheBatch(t *testing.T) {
	assets := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"imported": 3,
			"results": []identity.IngestResult{
				{Outcome: string(identity.OutcomeMatched), AssetID: assets[0]},
				{Outcome: string(identity.OutcomeSupporting), AssetID: assets[1]},
				{Outcome: string(identity.OutcomeCreated), AssetID: assets[2]},
			},
			// The supporting row's asset is one the tenant approved long ago;
			// the created one is still awaiting a decision.
			"asset_statuses": []string{"monitoring", "monitoring", "pending_approval"},
		})
	}))
	t.Cleanup(srv.Close)

	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p := &BatchProcessor{inventoryClient: c}

	rows := make([]*models.SensorDiscovery, 3)
	findings := make([]converter.IngestFinding, 3)
	for i := range rows {
		host := "host-" + strconv.Itoa(i) + ".example.com"
		rows[i] = &models.SensorDiscovery{ID: uuid.New(), ApprovalStatus: "pending"}
		findings[i] = converter.IngestFinding{Kind: "crypto", Hostname: &host}
	}

	var imported int
	logged := captureStdout(t, func() {
		imported, err = p.importInChunks(uuid.New(), uuid.New(), findings, rows, "pending_approval")
	})
	if err != nil {
		t.Fatalf("one supporting finding failed the whole import: %v — the poller retries that three times and then rejects every row in the batch", err)
	}
	if imported != 3 {
		t.Fatalf("imported %d of 3 findings", imported)
	}
	if strings.Contains(logged, "no arm for") {
		t.Fatalf("`supporting` reached the unknown-outcome path: %s", strings.TrimSpace(logged))
	}

	// The supporting row settles exactly like the matched one beside it: its
	// asset is monitoring, so adoptEffectiveStatus stamps `auto_approved`, and
	// adoptAssetID links it to the asset it corroborated.
	//
	// The `created` row stays `pending` on purpose: its asset is in Discovery →
	// Approvals, and inventory-service's settleDiscoveryQueueRows closes the
	// row out (by asset_id) when a human decides. `observed` there would deny a
	// decision that is still coming.
	for i, want := range []string{"auto_approved", "auto_approved", "pending"} {
		if rows[i].ApprovalStatus != want {
			t.Errorf("row %d settled as %q, want %q", i, rows[i].ApprovalStatus, want)
		}
		if rows[i].AssetID == nil || rows[i].AssetID.String() != assets[i] {
			t.Errorf("row %d was not linked to asset %s: %v", i, assets[i], rows[i].AssetID)
		}
	}
}

// captureStdout collects what fn prints. This package reports with fmt.Printf,
// so the unknown-outcome warning is only observable this way.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("closing the capture pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading the capture pipe: %v", err)
	}
	return string(out)
}
