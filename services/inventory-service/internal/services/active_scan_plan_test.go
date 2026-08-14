package services

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test addresses are RFC 5737 documentation ranges.

func hasProtocol(protocols []string, want string) bool {
	for _, p := range protocols {
		if p == want {
			return true
		}
	}
	return false
}

func hasPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

// TestPlanActiveScanBatches_NeverEmitsHostPortTargets pins the contract that
// made Active Scan a silent no-op: a "host:port" target is rejected by
// cluster-sensor's validateNmapTarget and fails DNS resolution in the
// standalone sensor, while the asset has already been stamped as scanned.
func TestPlanActiveScanBatches_NeverEmitsHostPortTargets(t *testing.T) {
	assets := []activeScanAsset{
		{id: uuid.New(), host: "192.0.2.10", port: 22},
		{id: uuid.New(), host: "192.0.2.11", port: 8443},
		{id: uuid.New(), host: "host.example.com", port: 9443},
		{id: uuid.New(), host: "192.0.2.12"}, // no port
	}

	batches := planActiveScanBatches(assets)
	if len(batches) == 0 {
		t.Fatal("expected batches, got none")
	}

	for _, b := range batches {
		for _, target := range b.targets {
			if strings.Contains(target, ":") {
				t.Errorf("target %q contains ':' — downstream validateNmapTarget rejects it and the scan silently does nothing", target)
			}
		}
	}
}

// TestPlanActiveScanBatches_AssetPortReachesJobPorts pins the other half of the
// same bug: the port must travel in the job's Ports field, not glued to the host.
func TestPlanActiveScanBatches_AssetPortReachesJobPorts(t *testing.T) {
	assets := []activeScanAsset{
		{id: uuid.New(), host: "192.0.2.10", port: 22},
		{id: uuid.New(), host: "192.0.2.11", port: 9443},
	}

	batches := planActiveScanBatches(assets)

	for _, want := range []struct {
		host string
		port int
	}{{"192.0.2.10", 22}, {"192.0.2.11", 9443}} {
		found := false
		for _, b := range batches {
			for _, target := range b.targets {
				if target == want.host && hasPort(b.ports, want.port) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("asset %s port %d never reached a job's Ports list", want.host, want.port)
		}
	}
}

// TestPlanActiveScanBatches_PortlessAssetKeepsTLSFallback guards against
// regressing the pre-fix behaviour for assets that record no port.
func TestPlanActiveScanBatches_PortlessAssetKeepsTLSFallback(t *testing.T) {
	batches := planActiveScanBatches([]activeScanAsset{{id: uuid.New(), host: "192.0.2.20"}})
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
	if !hasPort(batches[0].ports, 443) || !hasPort(batches[0].ports, 8443) {
		t.Errorf("portless asset lost the 443/8443 TLS fallback: %v", batches[0].ports)
	}
	if !hasProtocol(batches[0].protocols, "TLS") {
		t.Errorf("portless asset lost the TLS default: %v", batches[0].protocols)
	}
}

// TestPlanActiveScanBatches_SSHAssetGetsSSHProtocol pins bug B: an SSH asset
// must actually be probed for SSH. Both evidence paths are covered — the port
// (22) and a recorded SSH crypto configuration on a non-standard port.
func TestPlanActiveScanBatches_SSHAssetGetsSSHProtocol(t *testing.T) {
	cases := []struct {
		name  string
		asset activeScanAsset
	}{
		{"ssh by well-known port", activeScanAsset{id: uuid.New(), host: "192.0.2.30", port: 22}},
		{"ssh by crypto configuration", activeScanAsset{id: uuid.New(), host: "192.0.2.31", port: 2022, configProtocols: []string{"ssh"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batches := planActiveScanBatches([]activeScanAsset{tc.asset})
			if len(batches) != 1 {
				t.Fatalf("expected 1 batch, got %d", len(batches))
			}
			if !hasProtocol(batches[0].protocols, "SSH") {
				t.Errorf("SSH asset was not scheduled for an SSH probe: protocols=%v", batches[0].protocols)
			}
		})
	}
}

// TestDeriveActiveScanProtocols covers the protocol-derivation ladder.
func TestDeriveActiveScanProtocols(t *testing.T) {
	cases := []struct {
		name            string
		port            int
		configProtocols []string
		want            []string
	}{
		{"unknown port, no evidence falls back to TLS", 6443, nil, []string{"TLS"}},
		{"well-known TLS port", 443, nil, []string{"TLS"}},
		{"well-known SSH port", 22, nil, []string{"SSH"}},
		{"config says HTTPS on an odd port", 9999, []string{"HTTPS"}, []string{"TLS"}},
		{"config says SSH and TLS", 2222, []string{"ssh", "TLS"}, []string{"SSH", "TLS"}},
		{"unprobeable config values are ignored", 443, []string{"tcp", "udp"}, []string{"TLS"}},
		{"OT protocols are not smuggled into Protocols", 502, []string{"Modbus"}, []string{"TLS"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveActiveScanProtocols(tc.port, tc.configProtocols)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("deriveActiveScanProtocols(%d, %v) = %v, want %v", tc.port, tc.configProtocols, got, tc.want)
			}
		})
	}
}

// TestPlanActiveScanBatches_GroupsByScanShape checks the scan-volume property:
// each job carries only the port(s) its own assets listen on, so probe work
// stays proportional to the asset count instead of assets × ports × protocols.
func TestPlanActiveScanBatches_GroupsByScanShape(t *testing.T) {
	assets := []activeScanAsset{
		{id: uuid.New(), host: "192.0.2.40", port: 443},
		{id: uuid.New(), host: "192.0.2.41", port: 443},
		{id: uuid.New(), host: "192.0.2.42", port: 22},
	}

	batches := planActiveScanBatches(assets)
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches (one per scan shape), got %d", len(batches))
	}

	probes := 0
	for _, b := range batches {
		probes += len(b.targets) * len(b.ports) * len(b.protocols)
		if len(b.ports) != 1 {
			t.Errorf("batch carries %d ports; each asset would be probed on ports it does not listen on", len(b.ports))
		}
	}
	if probes != len(assets) {
		t.Errorf("scan volume is %d probes for %d assets; expected one probe per asset", probes, len(assets))
	}
}

// TestPlanActiveScanBatches_SkipsAddresslessAssets — an asset with no host is
// never batched, which is what lets the caller avoid stamping it as scanned.
func TestPlanActiveScanBatches_SkipsAddresslessAssets(t *testing.T) {
	addressless := uuid.New()
	batches := planActiveScanBatches([]activeScanAsset{
		{id: addressless, port: 443},
		{id: uuid.New(), host: "192.0.2.50", port: 443},
	})

	for _, b := range batches {
		for _, id := range b.assetIDs {
			if id == addressless {
				t.Fatal("asset with no addressable host was batched — it would be stamped as freshly scanned without ever being probed")
			}
		}
	}
}

// TestPlanActiveScanBatches_ChunksOversizedBatches — both CreateJob
// implementations reject more than 1000 targets.
func TestPlanActiveScanBatches_ChunksOversizedBatches(t *testing.T) {
	var assets []activeScanAsset
	for i := 0; i < maxActiveScanTargetsPerJob+5; i++ {
		assets = append(assets, activeScanAsset{id: uuid.New(), host: fmt.Sprintf("host-%d.example.com", i), port: 443})
	}

	batches := planActiveScanBatches(assets)
	if len(batches) != 2 {
		t.Fatalf("expected the oversized group to be chunked into 2 jobs, got %d", len(batches))
	}
	totalAssets := 0
	for _, b := range batches {
		if len(b.targets) > maxActiveScanTargetsPerJob {
			t.Errorf("batch has %d targets, over the %d cap CreateJob enforces", len(b.targets), maxActiveScanTargetsPerJob)
		}
		totalAssets += len(b.assetIDs)
	}
	// Every asset must be stamped exactly once, by the job that probes its host.
	if totalAssets != len(assets) {
		t.Errorf("chunking lost or duplicated assets: %d across batches, expected %d", totalAssets, len(assets))
	}
}

// TestPlanActiveScanBatches_DedupsSharedHost — several asset records can point
// at the same host and port. cluster-sensor writes one target row per input, so
// the host must be listed once, while every asset still rides along (each one
// gets a freshness stamp and must land in the job that probes it).
func TestPlanActiveScanBatches_DedupsSharedHost(t *testing.T) {
	a1, a2, a3 := uuid.New(), uuid.New(), uuid.New()
	batches := planActiveScanBatches([]activeScanAsset{
		{id: a1, host: "192.0.2.70", port: 443},
		{id: a2, host: "192.0.2.70", port: 443},
		{id: a3, host: "192.0.2.71", port: 443},
	})

	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
	if len(batches[0].targets) != 2 {
		t.Errorf("expected the shared host to be listed once (2 targets), got %d: %v", len(batches[0].targets), batches[0].targets)
	}
	if len(batches[0].assetIDs) != 3 {
		t.Errorf("dedup dropped an asset: %d assetIDs, expected 3 — every asset gets stamped", len(batches[0].assetIDs))
	}
}

// TestPlanActiveScanBatches_DoesNotAliasFallbackPorts — a returned batch must
// not share backing storage with the package-level fallback slice.
func TestPlanActiveScanBatches_DoesNotAliasFallbackPorts(t *testing.T) {
	batches := planActiveScanBatches([]activeScanAsset{{id: uuid.New(), host: "192.0.2.80"}})
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
	batches[0].ports[0] = 1
	if activeScanFallbackPorts[0] != 443 {
		t.Errorf("batch.ports aliases the package var activeScanFallbackPorts — mutating a batch corrupted it to %v", activeScanFallbackPorts)
	}
}

// TestPlanStampRestore pins BOTH directions of the freshness restore. Blanking
// last_scanned_at unconditionally would erase real scan history, because
// `last_scanned_at IS NULL` is the "never scanned" coverage cut.
func TestPlanStampRestore(t *testing.T) {
	neverScanned := uuid.New()
	scannedBefore := uuid.New()
	when := time.Date(2026, 8, 6, 14, 30, 45, 123456000, time.UTC)

	nullIDs, tsIDs, tsValues := planStampRestore([]scanStamp{
		{assetID: neverScanned, lastScannedAt: sql.NullTime{Valid: false}},
		{assetID: scannedBefore, lastScannedAt: sql.NullTime{Time: when, Valid: true}},
	})

	// Direction 1: previously NULL stays NULL — the asset really was never
	// scanned and belongs back on the Active Scan list.
	if len(nullIDs) != 1 || nullIDs[0] != neverScanned {
		t.Errorf("previously-unscanned asset not restored to NULL: %v", nullIDs)
	}

	// Direction 2: a previously-scanned asset is restored to that EXACT instant,
	// not blanked and not "now".
	if len(tsIDs) != 1 || tsIDs[0] != scannedBefore.String() {
		t.Fatalf("previously-scanned asset missing from the timestamp restore: %v", tsIDs)
	}
	if len(tsValues) != 1 {
		t.Fatalf("expected 1 restore value, got %d", len(tsValues))
	}
	got, err := time.Parse(time.RFC3339Nano, tsValues[0])
	if err != nil {
		t.Fatalf("restore value %q is not a valid timestamp: %v", tsValues[0], err)
	}
	if !got.Equal(when) {
		t.Errorf("restore value = %v, want the exact prior timestamp %v", got, when)
	}

	// And the previously-scanned asset must NOT also appear in the NULL group,
	// which would blank it anyway.
	for _, id := range nullIDs {
		if id == scannedBefore {
			t.Error("previously-scanned asset was ALSO queued for NULL — its scan history would be erased")
		}
	}
}
