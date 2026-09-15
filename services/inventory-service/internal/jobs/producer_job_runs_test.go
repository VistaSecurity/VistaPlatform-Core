package jobs

// Every producer the job holds is actually RUN, and the rollup runs after them.
//
// `runTenant` is the only thing that executes a producer in production, and
// nothing else in the repository observes it. Each producer's own tests call
// `Run` directly; the wiring test beside this one proves the ingest hooks are
// installed; `make audit` knows nothing about this file. So deleting one of the
// four blocks in `runTenant` leaves `go test ./...` entirely green while that
// producer silently stops writing findings — the shape CLAUDE.md names in "a
// fix can compile, pass its tests, and still do nothing in production", and the
// one shipped for seven services.
//
// A source scan rather than a driven pass: `runTenant` needs a real database,
// four populated catalogues and a tenant to say anything, and a test that
// heavy would be skipped in exactly the runs that matter. It fails closed — an
// unreadable or renamed file is a failure, not a pass.

import (
	"os"
	"strings"
	"testing"
)

// The producers the job owns, and the call that has to appear in runTenant for
// each. Adding a producer to the struct without adding it here is caught by the
// second test below, which reads the struct and demands a row for every field.
var producerCalls = map[string]string{
	"eol":     "j.eol.Run(ctx, tenantID)",
	"vuln":    "j.vuln.Run(ctx, tenantID)",
	"crypto":  "j.crypto.Run(ctx, tenantID)",
	"config":  "j.config.Run(ctx, tenantID)",
	"hygiene": "j.hygiene.Run(ctx, tenantID)",
	"drift":   "j.drift.Run(ctx, tenantID)",
}

func producerJobSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("producer_job.go")
	if err != nil {
		t.Fatalf("reading producer_job.go: %v", err)
	}
	return string(src)
}

func TestRunTenantRunsEveryProducer(t *testing.T) {
	src := producerJobSource(t)
	for name, call := range producerCalls {
		if !strings.Contains(src, call) {
			t.Errorf("runTenant never calls the %s producer (%s) — it is constructed, held on the struct, "+
				"and never executed, so it writes nothing and nothing says so", name, call)
		}
	}
	// The rollup is what turns those findings into `assets.risk_score` and
	// `risk_assessed_by` (ADR-0005 D4). Without it every producer's work stays
	// in the findings table and the inventory keeps yesterday's numbers.
	if !strings.Contains(src, "j.recomputeRisk(ctx, tenantID)") {
		t.Error("runTenant never recomputes risk — the findings land and the asset rollup never moves")
	}
}

// The other direction: a producer added to the struct and not to the table
// above would make the first test vacuously true for it.
func TestEveryProducerFieldIsCovered(t *testing.T) {
	src := producerJobSource(t)
	start := strings.Index(src, "type FindingProducerJob struct {")
	if start < 0 {
		t.Fatal("FindingProducerJob struct not found; the scan is broken, not the job")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of the FindingProducerJob struct")
	}

	found := 0
	for _, line := range strings.Split(src[start:start+end], "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "*producers.") {
			continue
		}
		name := strings.Fields(line)[0]
		found++
		if _, ok := producerCalls[name]; !ok {
			t.Errorf("FindingProducerJob holds a %q producer that producerCalls does not list, so nothing "+
				"checks that runTenant executes it", name)
		}
	}
	if found != len(producerCalls) {
		t.Errorf("found %d producer fields on the struct but producerCalls lists %d", found, len(producerCalls))
	}
}
