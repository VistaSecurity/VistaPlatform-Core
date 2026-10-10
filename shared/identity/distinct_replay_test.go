package identity_test

// Follow-up to distinct_device_test.go. The second plug is created without the
// shared name (the first plug holds it), so its next report resolves its MAC to
// itself and the name to the first plug. That must stay a match: a weak name
// does not vote against the device-binding identifier that decided.
//
// Mutation record (each made in turn, the named test failed, then restored):
//   - sharedNameDoesNotVote always false, or the `shares_name` marker not
//     written at creation: TestDistinctSecondDeviceReplayStaysMatched fails with
//     outcome `conflict` and a proposal (plain and admission).
//   - controllerChannel accepting any measured unrelayed report:
//     TestSensorProbeUnderASharedNameStillProposes fails with outcome `created`.
//   - the locally administered clause removed from classifyDrift:
//     TestLocallyAdministeredMACDoesNotCreateADistinctDevice fails.
//   - sharedNameDoesNotVote always true (no kind or history check): the replay
//     test still passes but the relayed-advert, provisional and sensor pins fail.
//   - TestSerialStillConflictsWithAMACElsewhere pins behaviour this change does
//     not touch (strong kinds still conflict); it is NOT mutation-sensitive to it.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

type replayStore interface {
	FindByIdentifier(context.Context, string, identity.Kind, string, string) ([]identity.AssetRef, error)
	Identifiers(identity.AssetRef) []identity.Identifier
	Proposals() []identity.MergeProposal
	AssetCount() int
}

func forBothEngines(t *testing.T, run func(t *testing.T, e *identity.Engine, repo replayStore)) {
	t.Helper()
	t.Run("plain", func(t *testing.T) {
		e, repo := newEngine(t, identity.Config{})
		run(t, e, repo)
	})
	t.Run("admission", func(t *testing.T) {
		repo := newAdmissionRepo()
		e, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		run(t, e, repo)
	})
}

func TestDistinctSecondDeviceReplayStaysMatched(t *testing.T) {
	forBothEngines(t, func(t *testing.T, e *identity.Engine, repo replayStore) {
		a := mustResolve(t, e, interrogationClient(plugAt, plugName, plugIPA, plugMACA))
		b := mustResolve(t, e, interrogationClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
		if a.Outcome != identity.OutcomeCreated || b.Outcome != identity.OutcomeCreated || a.Asset.ID == b.Asset.ID {
			t.Fatalf("setup: %s / %s", a.Outcome, b.Outcome)
		}
		for i := 2; i < 4; i++ {
			at := plugAt.Add(time.Duration(i) * time.Minute)
			rb := mustResolve(t, e, interrogationClient(at, plugName, plugIPB, plugMACB))
			if rb.Outcome != identity.OutcomeMatched || rb.Asset.ID != b.Asset.ID {
				t.Fatalf("replay of B (%d) = %s on %s, want matched on %s", i, rb.Outcome, rb.Asset.ID, b.Asset.ID)
			}
			ra := mustResolve(t, e, interrogationClient(at, plugName, plugIPA, plugMACA))
			if ra.Outcome != identity.OutcomeMatched || ra.Asset.ID != a.Asset.ID {
				t.Fatalf("replay of A (%d) = %s on %s, want matched on %s", i, ra.Outcome, ra.Asset.ID, a.Asset.ID)
			}
		}
		if n := len(repo.Proposals()); n != 0 {
			t.Fatalf("%d merge proposals, want none", n)
		}
		if repo.AssetCount() != 2 {
			t.Fatalf("%d assets, want 2", repo.AssetCount())
		}
		if got := ownerOfID(t, repo, plugName); len(got) != 1 || got[0].ID != a.Asset.ID {
			t.Fatalf("the shared name moved: %v", got)
		}
	})
}

// A sensor's own probe is not the controller channel: a new MAC and a new
// address under a shared name is still a question, however much it carries.
func TestSensorProbeUnderASharedNameStillProposes(t *testing.T) {
	for _, ref := range []string{"sensor:probe-1", "scan:job-7"} {
		t.Run(ref, func(t *testing.T) {
			forBothEngines(t, func(t *testing.T, e *identity.Engine, repo replayStore) {
				a := mustResolve(t, e, interrogationClient(plugAt, plugName, plugIPA, plugMACA))
				probe := interrogationClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB)
				probe.Source.Ref = ref
				got := mustResolve(t, e, probe)
				if got.Outcome == identity.OutcomeCreated {
					t.Fatalf("a %s probe created a second asset", ref)
				}
				if repo.AssetCount() != 1 {
					t.Fatalf("%d assets, want 1 (first %s)", repo.AssetCount(), a.Asset.ID)
				}
			})
		})
	}
	t.Run("admission proposes", func(t *testing.T) {
		repo := newAdmissionRepo()
		e, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		mustResolve(t, e, interrogationClient(plugAt, plugName, plugIPA, plugMACA))
		probe := interrogationClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB)
		probe.Source.Ref = "sensor:probe-1"
		got := mustResolve(t, e, probe)
		if got.Outcome != identity.OutcomeConflict || len(repo.Proposals()) != 1 {
			t.Fatalf("outcome = %s, proposals = %d, want conflict and 1", got.Outcome, len(repo.Proposals()))
		}
	})
}

// A randomised MAC is not hardware: neither side's may drive `distinct`.
func TestLocallyAdministeredMACDoesNotCreateADistinctDevice(t *testing.T) {
	laa := id(identity.KindMACAddress, "02:00:5e:00:53:c3")
	t.Run("observed", func(t *testing.T) {
		forBothEngines(t, func(t *testing.T, e *identity.Engine, repo replayStore) {
			mustResolve(t, e, interrogationClient(plugAt, plugName, plugIPA, plugMACA))
			got := mustResolve(t, e, interrogationClient(plugAt.Add(time.Minute), plugName, plugIPB, laa))
			if got.Outcome == identity.OutcomeCreated || repo.AssetCount() != 1 {
				t.Fatalf("outcome = %s, assets = %d: a randomised MAC created a device", got.Outcome, repo.AssetCount())
			}
		})
	})
	t.Run("held", func(t *testing.T) {
		forBothEngines(t, func(t *testing.T, e *identity.Engine, repo replayStore) {
			mustResolve(t, e, interrogationClient(plugAt, plugName, plugIPA, laa))
			got := mustResolve(t, e, interrogationClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
			if got.Outcome == identity.OutcomeCreated || repo.AssetCount() != 1 {
				t.Fatalf("outcome = %s, assets = %d: a randomised MAC created a device", got.Outcome, repo.AssetCount())
			}
		})
	})
}

// The singleton rule for strong kinds is untouched: a serial on one asset and a
// MAC on another are two answers about which device this is.
func TestSerialStillConflictsWithAMACElsewhere(t *testing.T) {
	serial := id(identity.KindSerialNumber, "SN-PLUG-0001")
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, interrogationClient(plugAt, serial, plugMACA))
	b := mustResolve(t, e, interrogationClient(plugAt.Add(time.Minute), plugMACB))
	if a.Asset.ID == b.Asset.ID {
		t.Fatalf("setup: one asset")
	}
	got := mustResolve(t, e, interrogationClient(plugAt.Add(2*time.Minute), serial, plugMACB))
	if got.Outcome != identity.OutcomeConflict || len(repo.Proposals()) != 1 {
		t.Fatalf("outcome = %s, proposals = %d, want conflict and 1", got.Outcome, len(repo.Proposals()))
	}
}
