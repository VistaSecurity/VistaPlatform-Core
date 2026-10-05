package jobs

// The automatic sweep offers the names an asset is known by, per address, to the
// job it dispatches (shared/discovery SNICandidates): a TLS port that refuses an
// address-only handshake is then tried with them. These drive the real sweep.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"

	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

func TestSweepTenant_JobCarriesTheAssetNamesPerAddress(t *testing.T) {
	targets := targetsAt("10.0.0.1", "10.0.0.2", "10.0.0.2")
	store := &fakeStore{
		policy:  sharedautoscan.DefaultPolicy(),
		targets: targets,
		sni: map[uuid.UUID][]string{
			targets[0].AssetID: {"a.example.test"},
			// Two assets share 10.0.0.2: their names are merged, in order, and
			// bounded to three whatever they bring.
			targets[1].AssetID: {"b1.example.test", "b2.example.test"},
			targets[2].AssetID: {"b3.example.test", "b4.example.test"},
		},
	}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)

	if len(d.jobs) != 1 {
		t.Fatalf("dispatched %d jobs, want 1", len(d.jobs))
	}
	want := map[string][]string{
		"10.0.0.1": {"a.example.test"},
		"10.0.0.2": {"b1.example.test", "b2.example.test", "b3.example.test"},
	}
	if got := d.jobs[0].SNICandidates; !reflect.DeepEqual(got, want) {
		t.Fatalf("job names = %v, want %v", got, want)
	}
}

func TestSweepTenant_NamesAreOptionalNeverBlockingTheScan(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1"), sniErr: errors.New("db down")}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)
	if len(d.jobs) != 1 {
		t.Fatalf("dispatched %d jobs, want 1: a failed name read must not stop the scan", len(d.jobs))
	}
	if len(d.jobs[0].SNICandidates) != 0 {
		t.Errorf("job carries names %v after a failed read", d.jobs[0].SNICandidates)
	}
}
