package processor

// The hop-2 claims, per vendor: what discovery-processor must hand inventory
// for every row an interrogation wrote. Want is the correct behaviour; a claim
// with KnownGap pins today's behaviour until the named slice fixes it (see
// pipelinetest.Expectation).

import (
	"fmt"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
)

// hop2Findings is every imported finding, in import order, beside the hop-1
// row it came from.
func hop2Findings(t *testing.T, hop1 pipelinetest.Hop1Handoff, h pipelinetest.Hop2Handoff) (findings []map[string]any, rows []pipelinetest.SensorDiscoveryRow) {
	t.Helper()
	byID := map[string]int{}
	for _, r := range h.Rows {
		byID[discoveryPlaceholder(r.Row)] = r.Row
	}
	for _, req := range h.Imports {
		for _, f := range req.Findings {
			raw, _ := f["raw_data"].(map[string]any)
			id, _ := raw["discovery_id"].(string)
			i, ok := byID[id]
			if !ok {
				t.Fatalf("imported finding names no hop-1 row: %v", id)
			}
			findings = append(findings, f)
			rows = append(rows, hop1.SensorDiscoveries[i])
		}
	}
	return findings, rows
}

func discoveryPlaceholder(i int) string {
	return fmt.Sprintf(pipelinetest.PlaceholderDiscoveryIDFormat, i)
}

// notForwarded lists the hop-1 rows that reached neither inventory's import
// nor external_connections, and the rows left unprocessed.
func notForwarded(h pipelinetest.Hop2Handoff) (dropped, unprocessed []int) {
	dropped, unprocessed = []int{}, []int{}
	for _, r := range h.Rows {
		if r.Forwarded == "" {
			dropped = append(dropped, r.Row)
		}
		if !r.Processed {
			unprocessed = append(unprocessed, r.Row)
		}
	}
	return dropped, unprocessed
}

// vendorPipelineHop2Claims is the table.
func vendorPipelineHop2Claims(t *testing.T, vendor string, hop1 pipelinetest.Hop1Handoff, h pipelinetest.Hop2Handoff, _ error) []pipelinetest.Expectation {
	t.Helper()
	findings, rows := hop2Findings(t, hop1, h)
	dropped, unprocessed := notForwarded(h)

	// P-12: the converter hard-codes asset_type "server"; the collector said
	// what the thing is.
	var gotTypes, wantTypes []any
	// P-01,: an interrogation row's stated key exchange is the
	// finding's key exchange, and nothing else is.
	var gotKex, wantKex []any
	for i, f := range findings {
		gotTypes = append(gotTypes, f["asset_type"])
		wantTypes = append(wantTypes, rows[i].Metadata["asset_type"])
		gotKex = append(gotKex, f["key_exchange_algorithm"])
		wantKex = append(wantKex, rows[i].Metadata["key_exchange_algorithm"])
	}
	allServer := make([]any, len(findings))
	for i := range allServer {
		allServer[i] = "server"
	}

	claims := []pipelinetest.Expectation{
		{What: vendor + ": a finding's key exchange is the one its row stated", Got: gotKex, Want: wantKex},
	}
	if len(findings) > 0 {
		claims = append(claims, pipelinetest.Expectation{
			What: vendor + ": each finding keeps the asset type its collector reported",
			Got:  gotTypes, Want: wantTypes,
			KnownGap: "P-12 / W2.3", Current: allServer,
		})
	}

	// P-11,: an interrogated asset with a public address or no
	// address used to classify third party, have no source IP, and be skipped —
	// left unprocessed for the poller to find again forever — while the job
	// reported success (the Cisco ISAKMP SA and crypto map on their peer's
	// address, the FortiGate tunnel on its remote-gw and the SSL-VPN on
	// 0.0.0.0, the PAN-OS profile and rule with no address at all). Every such
	// row now names its interrogated device and goes to inventory, which lands
	// it there. Nothing is dropped for any vendor.
	switch vendor {
	case "unifi", "f5", "snmp", "cisco", "fortinet", "paloalto":
		claims = append(claims,
			pipelinetest.Expectation{What: vendor + ": rows that reached nowhere", Got: dropped, Want: []int{}},
			pipelinetest.Expectation{What: vendor + ": rows left unprocessed", Got: unprocessed, Want: []int{}},
			pipelinetest.Expectation{What: vendor + ": batch outcome", Got: h.ProcessError, Want: ""},
		)
	default:
		t.Fatalf("no hop-2 claims for %s", vendor)
	}
	return claims
}
