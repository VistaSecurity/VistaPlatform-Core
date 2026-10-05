package services

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Test addresses are RFC 5737 documentation ranges.

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

// TestPlanActiveScanBatches_PortlessAssetKeepsFallbackPorts guards against
// regressing the pre-fix behaviour for assets that record no port.
func TestPlanActiveScanBatches_PortlessAssetKeepsFallbackPorts(t *testing.T) {
	batches := planActiveScanBatches([]activeScanAsset{{id: uuid.New(), host: "192.0.2.20"}})
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
	if !hasPort(batches[0].ports, 443) || !hasPort(batches[0].ports, 8443) {
		t.Errorf("portless asset lost the 443/8443 fallback: %v", batches[0].ports)
	}
}

// TestPlanActiveScanBatches_GroupsByPortsOnly: the engine identifies the
// service from what answers ( WP4), so two assets on the same port share
// a job whatever their recorded configurations speak — an SSH asset and a TLS
// asset both on 2222 are one job, not two.
func TestPlanActiveScanBatches_GroupsByPortsOnly(t *testing.T) {
	batches := planActiveScanBatches([]activeScanAsset{
		{id: uuid.New(), host: "192.0.2.90", port: 2222},
		{id: uuid.New(), host: "192.0.2.91", port: 2222},
		{id: uuid.New(), host: "192.0.2.92"},
		{id: uuid.New(), host: "192.0.2.93"},
	})
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches (one per port list), got %d: %+v", len(batches), batches)
	}
	if len(batches[0].targets) != 2 || len(batches[1].targets) != 2 {
		t.Fatalf("batches = %+v, want two hosts on 2222 and two on the fallback ports", batches)
	}
}

// TestPlanActiveScanBatches_GroupsByScanShape checks the scan-volume property:
// each job carries only the port(s) its own assets listen on, so probe work
// stays proportional to the asset count instead of assets × ports.
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
		probes += len(b.targets) * len(b.ports)
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
