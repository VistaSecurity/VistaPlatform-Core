package services

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

// Every asset a scan request leaves alone is named in the server log with its
// reason; a request that dispatched everything writes nothing.
func TestLogActiveScanLeftAlone_NamesEachAssetAndReason(t *testing.T) {
	tenant := uuid.New()
	scanned, skipped, unconfirmed, addressless := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	requested := []uuid.UUID{scanned, skipped, unconfirmed, addressless}
	resolved := []activeScanAsset{{id: scanned, host: "10.0.0.1"}, {id: skipped, host: "10.0.0.2"}, {id: unconfirmed, host: "203.0.113.9"}}

	out := captureLog(t, func() {
		logActiveScanLeftAlone(tenant, requested, resolved, ActiveScanResult{
			Scanned:           1,
			Skipped:           []ActiveScanSkip{{AssetID: skipped, Reason: "observing sensor s1 is offline; 10.0.0.2 was not scanned this pass"}},
			NeedsConfirmation: []ActiveScanExternalTarget{{AssetID: unconfirmed, Target: "203.0.113.9"}},
		})
	})
	for _, want := range []string{
		"requested: 4, dispatched: 1, skipped: 1, awaiting confirmation: 1, no address or name: 1",
		skipped.String(), "observing sensor s1 is offline",
		unconfirmed.String(), "203.0.113.9",
		addressless.String(), "no address or name to scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, scanned.String()) {
		t.Errorf("the dispatched asset was logged as left alone:\n%s", out)
	}

	quiet := captureLog(t, func() {
		logActiveScanLeftAlone(tenant, []uuid.UUID{scanned}, resolved[:1], ActiveScanResult{Scanned: 1})
	})
	if quiet != "" {
		t.Errorf("a fully dispatched scan logged %q, want nothing", quiet)
	}
}

func TestLogActiveScanLeftAlone_BoundsPerAssetLines(t *testing.T) {
	var result ActiveScanResult
	var requested []uuid.UUID
	var resolved []activeScanAsset
	for i := 0; i < maxActiveScanSkipLogLines+7; i++ {
		id := uuid.New()
		requested = append(requested, id)
		resolved = append(resolved, activeScanAsset{id: id, host: "10.0.0.1"})
		result.Skipped = append(result.Skipped, ActiveScanSkip{AssetID: id, Reason: "r"})
	}
	out := captureLog(t, func() { logActiveScanLeftAlone(uuid.New(), requested, resolved, result) })
	if got := strings.Count(out, "Active scan skipped asset"); got != maxActiveScanSkipLogLines {
		t.Errorf("%d per-asset lines, want the cap of %d", got, maxActiveScanSkipLogLines)
	}
	if !strings.Contains(out, "7 more asset(s) left alone") {
		t.Errorf("the overflow was not reported:\n%s", out)
	}
}
