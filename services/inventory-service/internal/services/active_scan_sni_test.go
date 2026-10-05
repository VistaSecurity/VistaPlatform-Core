package services

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// An Active Scan's job request carries each asset's names per ADDRESS target:
// merged across assets that share the address, bounded to three, never for a
// hostname target (it presents its own name), and kept when the batch is split
// across executors.
func TestPlanActiveScanBatches_CarriesSNINamesPerAddress(t *testing.T) {
	a1, a2, a3 := uuid.New(), uuid.New(), uuid.New()
	batches := planActiveScanBatches([]activeScanAsset{
		{id: a1, host: "198.51.100.10", port: 443, sni: []string{"a.example.test", "b.example.test"}},
		{id: a2, host: "198.51.100.10", port: 443, sni: []string{"c.example.test", "d.example.test"}},
		{id: a3, host: "named.example.test", port: 443, sni: []string{"x.example.test"}},
	})
	if len(batches) != 1 {
		t.Fatalf("%d batches, want 1", len(batches))
	}
	want := map[string][]string{"198.51.100.10": {"a.example.test", "b.example.test", "c.example.test"}}
	if got := batches[0].sniByHost; !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	// A split batch keeps the names of the hosts it still covers, and only those.
	sub := batches[0].subset([]string{"named.example.test"})
	if len(sub.sniByHost) != 0 {
		t.Errorf("a subset without the address carries names %v", sub.sniByHost)
	}
	sub = batches[0].subset([]string{"198.51.100.10"})
	if !reflect.DeepEqual(sub.sniByHost, want) {
		t.Errorf("a subset with the address lost its names: %v", sub.sniByHost)
	}
}
