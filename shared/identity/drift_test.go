package identity_test

// The drift verdicts through the engine (owner Decision 4 of): one test
// per row of the owner's table, driven through Resolve against the memory
// store, asserting what the asset holds afterwards and what its timeline says.

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const (
	driftSeg            = "segment-static"
	driftMAC, driftMAC2 = "00:00:5e:00:53:01", "00:00:5e:00:53:02"
	driftKey, driftKey2 = "SHA256:drift-key-one", "SHA256:drift-key-two"
	driftIP, driftIP2   = "192.0.2.10", "192.0.2.20"
)

// hostKey is an SSH host key identifier with its algorithm, as the probe
// reports it (the engine normalises "ssh-ed25519" to "ed25519").
func hostKey(fp, alg string) identity.Identifier {
	i := id(identity.KindSSHHostKeyFingerprint, fp)
	i.KeyAlgorithm = alg
	return i
}

func driftObs(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := obs(assetclass.KeyServer, ids...)
	o.ObservedAt = at
	return o
}

// establish creates the asset the drift cases change, and returns it.
func establish(t *testing.T, e *identity.Engine, o identity.Observation) identity.AssetRef {
	t.Helper()
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup: outcome = %s, want created", res.Outcome)
	}
	return res.Asset
}

func holds(repo *memory.Repository, ref identity.AssetRef, kind identity.Kind, value string) bool {
	for _, id := range repo.Identifiers(ref) {
		if id.Kind == kind && id.Value == value {
			return true
		}
	}
	return false
}

// driftEntry returns the asset's history entry with this action, failing when
// there is not exactly one.
func driftEntry(t *testing.T, repo *memory.Repository, ref identity.AssetRef, action identity.HistoryAction) identity.HistoryEntry {
	t.Helper()
	var found []identity.HistoryEntry
	var all []identity.HistoryAction
	for _, h := range repo.HistoryFor(ref) {
		all = append(all, h.Action)
		if h.Action == action {
			found = append(found, h)
		}
	}
	if len(found) != 1 {
		t.Fatalf("history = %v, want exactly one %s", all, action)
	}
	return found[0]
}

func noDriftEntries(t *testing.T, repo *memory.Repository, ref identity.AssetRef) {
	t.Helper()
	for _, h := range repo.HistoryFor(ref) {
		switch h.Action {
		case identity.ActionSSHHostKeyRotated, identity.ActionAddressMoved, identity.ActionIdentityMaterialRotated, identity.ActionIdentityDriftFlagged:
			t.Errorf("unexpected drift entry %s: %+v", h.Action, h.Changes)
		}
	}
}

func changeFor(t *testing.T, d *identity.Drift, kind identity.Kind) identity.MaterialChange {
	t.Helper()
	for _, c := range d.Changes {
		if c.Kind == string(kind) {
			return c
		}
	}
	t.Fatalf("drift %s carries no %s change: %+v", d.Verdict, kind, d.Changes)
	return identity.MaterialChange{}
}

func TestDrift_SameMACAndAddressNewHostKey_Rotated(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	asset := establish(t, e, driftObs(t0, id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey, "ssh-ed25519")))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey2, "ssh-ed25519")))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, asset.ID)
	}
	if res.Drift == nil || res.Drift.Verdict != matcher.DriftRotated {
		t.Fatalf("drift = %+v, want rotated", res.Drift)
	}
	if holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) || !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey2) {
		t.Errorf("identifiers = %+v, want the old key replaced by the new one", repo.Identifiers(asset))
	}
	c := changeFor(t, res.Drift, identity.KindSSHHostKeyFingerprint)
	if len(c.Previous) != 1 || c.Previous[0] != driftKey || len(c.Current) != 1 || c.Current[0] != driftKey2 || !c.Retired {
		t.Errorf("change = %+v, want %s → %s, retired", c, driftKey, driftKey2)
	}
	h := driftEntry(t, repo, asset, identity.ActionSSHHostKeyRotated)
	if h.Changes["verdict"] != "rotated" || h.Changes["rule"] != "mac_and_address_kept_key_changed" {
		t.Errorf("history changes = %+v", h.Changes)
	}
	if res.Drift.NeedsReview {
		t.Error("a corroborated rotation is not flagged for review")
	}
}

func TestDrift_SameKeysNewAddressOldOneSilent_Moved(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	first := []identity.Identifier{id(identity.KindMACAddress, driftMAC), hostKey(driftKey, "ssh-ed25519")}
	asset := establish(t, e, driftObs(t0, append(first, scoped(identity.KindIPAddress, driftIP, driftSeg))...))

	res := mustResolve(t, e, driftObs(t0.Add(identity.MovedSilence+time.Hour), append(first, scoped(identity.KindIPAddress, driftIP2, driftSeg))...))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, asset.ID)
	}
	if res.Drift == nil || res.Drift.Verdict != matcher.DriftMoved {
		t.Fatalf("drift = %+v, want moved", res.Drift)
	}
	if holds(repo, asset, identity.KindIPAddress, driftIP) || !holds(repo, asset, identity.KindIPAddress, driftIP2) {
		t.Errorf("identifiers = %+v, want the old address released and the new one attached", repo.Identifiers(asset))
	}
	if !res.Drift.Static {
		t.Error("a move off a static segment is reported as static")
	}
	driftEntry(t, repo, asset, identity.ActionAddressMoved)

	// The released address is free: a different device can now hold it.
	other := mustResolve(t, e, driftObs(t0.Add(identity.MovedSilence+2*time.Hour), id(identity.KindMACAddress, driftMAC2), scoped(identity.KindIPAddress, driftIP, driftSeg)))
	if other.Outcome != identity.OutcomeCreated {
		t.Errorf("a new device at the released address: outcome = %s, want created", other.Outcome)
	}
}

// A device met at a second address while its first is still live has two
// addresses, not a new one.
func TestDrift_NewAddressBesideALiveOne_IsNotAMove(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	first := []identity.Identifier{id(identity.KindMACAddress, driftMAC), hostKey(driftKey, "ssh-ed25519")}
	asset := establish(t, e, driftObs(t0, append(first, scoped(identity.KindIPAddress, driftIP, driftSeg))...))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), append(first, scoped(identity.KindIPAddress, driftIP2, driftSeg))...))

	if res.Outcome != identity.OutcomeMatched || res.Drift != nil {
		t.Fatalf("outcome = %s drift = %+v, want a plain match", res.Outcome, res.Drift)
	}
	if !holds(repo, asset, identity.KindIPAddress, driftIP) || !holds(repo, asset, identity.KindIPAddress, driftIP2) {
		t.Errorf("identifiers = %+v, want both addresses", repo.Identifiers(asset))
	}
	noDriftEntries(t, repo, asset)
}

func TestDrift_SameAddressNewMACAndHostKey_Replaced(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	asset := establish(t, e, driftObs(t0, id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey, "ssh-ed25519")))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), id(identity.KindMACAddress, driftMAC2), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey2, "ssh-ed25519")))

	if res.Outcome != identity.OutcomeConflict || res.Proposal.ID == "" {
		t.Fatalf("outcome = %s proposal = %+v, want a conflict with a proposal", res.Outcome, res.Proposal)
	}
	if holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey2) || holds(repo, asset, identity.KindMACAddress, driftMAC2) {
		t.Errorf("the replacing device's bindings landed on the established asset: %+v", repo.Identifiers(asset))
	}
	if got := repo.LastSeen(asset); !got.Equal(t0) {
		t.Errorf("the established asset's last-seen moved to %s on another device's sighting", got)
	}
	noDriftEntries(t, repo, asset)
}

func TestDrift_SameMACNewOSMaterial_Reimaged(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	asset := establish(t, e, driftObs(t0,
		id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg),
		hostKey(driftKey, "ssh-ed25519"), scoped(identity.KindHostname, "db-primary", driftSeg)))
	repo.SetTLSCertificates(asset, "aa11")

	o := driftObs(t0.Add(time.Hour),
		id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg),
		hostKey(driftKey2, "ssh-ed25519"), scoped(identity.KindHostname, "build-07", driftSeg))
	o.TLSCertFingerprints = []string{"bb22"}
	res := mustResolve(t, e, o)

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, asset.ID)
	}
	if res.Drift == nil || res.Drift.Verdict != matcher.DriftReimaged {
		t.Fatalf("drift = %+v, want reimaged", res.Drift)
	}
	if holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) {
		t.Error("the pre-reimage host key is still on the asset")
	}
	if c := changeFor(t, res.Drift, identity.KindHostname); len(c.Previous) != 1 || c.Previous[0] != "db-primary" {
		t.Errorf("hostname change = %+v", c)
	}
	driftEntry(t, repo, asset, identity.ActionIdentityMaterialRotated)
}

func TestDrift_AddressOnly_StableSignalsAgree_Rotated(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	asset := establish(t, e, driftObs(t0, scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey, "ssh-ed25519")))
	repo.SetTLSCertificates(asset, "aa11")

	o := driftObs(t0.Add(time.Hour), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey2, "ssh-ed25519"))
	o.TLSCertFingerprints = []string{"AA:11"}
	res := mustResolve(t, e, o)

	if res.Outcome != identity.OutcomeMatched || res.Drift == nil || res.Drift.Verdict != matcher.DriftRotated {
		t.Fatalf("outcome = %s drift = %+v, want matched + rotated", res.Outcome, res.Drift)
	}
	if res.Drift.Rule != "address_only_key_changed_rest_agrees" {
		t.Errorf("rule = %s", res.Drift.Rule)
	}
	driftEntry(t, repo, asset, identity.ActionSSHHostKeyRotated)
}

func TestDrift_AddressOnly_StableSignalsChanged_Replaced(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	asset := establish(t, e, driftObs(t0, scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey, "ssh-ed25519")))
	repo.SetTLSCertificates(asset, "aa11")

	o := driftObs(t0.Add(time.Hour), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey2, "ssh-ed25519"))
	o.TLSCertFingerprints = []string{"cc33"}
	res := mustResolve(t, e, o)

	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	if holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey2) {
		t.Error("the replacing device's host key landed on the established asset")
	}
	noDriftEntries(t, repo, asset)
}

// TestDrift_AddressOnly_NothingElseKnown_MatchedAndFlagged is also the WIRING
// test: before the classifier, this exact sighting matched silently (
// R5). Delete the classifyDrift call in Resolve and it goes red on the missing
// verdict, the missing flag and the missing timeline entry.
func TestDrift_AddressOnly_NothingElseKnown_MatchedAndFlagged(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	asset := establish(t, e, driftObs(t0, scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey, "ssh-ed25519")))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey2, "ssh-ed25519")))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, asset.ID)
	}
	if res.Drift == nil || res.Drift.Verdict != matcher.DriftUnverified || !res.Drift.NeedsReview {
		t.Fatalf("drift = %+v, want unverified and flagged for review", res.Drift)
	}
	// Nothing retired: both keys stay on record for the person who reviews it.
	if !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) || !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey2) {
		t.Errorf("identifiers = %+v, want both keys kept", repo.Identifiers(asset))
	}
	h := driftEntry(t, repo, asset, identity.ActionIdentityDriftFlagged)
	if h.Changes["needs_review"] != true {
		t.Errorf("history changes = %+v, want needs_review", h.Changes)
	}
}

// A re-sighting with nothing changed writes no drift entry and carries no
// verdict: the classifier is consulted on every decided match and must be
// silent when there is nothing to say.
func TestDrift_NothingChanged_NoVerdict(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	all := []identity.Identifier{id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg), hostKey(driftKey, "ssh-ed25519")}
	asset := establish(t, e, driftObs(observedAt, all...))
	res := mustResolve(t, e, driftObs(observedAt.Add(time.Hour), all...))
	if res.Outcome != identity.OutcomeMatched || res.Drift != nil {
		t.Fatalf("outcome = %s drift = %+v, want a plain match", res.Outcome, res.Drift)
	}
	noDriftEntries(t, repo, asset)
}

const driftKeyRSA = "SHA256:drift-key-rsa"

// A host offers an ed25519 and an RSA key; probes alternate between them as
// negotiation decides. Neither sighting is a change: the second key is
// attached, nothing is retired, no verdict and no timeline entry — however
// many times it alternates.
func TestDrift_TwoAlgorithmsAlternating_NoEvent(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	base := []identity.Identifier{id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg)}
	asset := establish(t, e, driftObs(t0, append(base, hostKey(driftKey, "ssh-ed25519"))...))

	for i, k := range []identity.Identifier{hostKey(driftKeyRSA, "rsa-sha2-512"), hostKey(driftKey, "ssh-ed25519"), hostKey(driftKeyRSA, "ssh-rsa")} {
		res := mustResolve(t, e, driftObs(t0.Add(time.Duration(i+1)*time.Hour), append(base, k)...))
		if res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset.ID || res.Drift != nil {
			t.Fatalf("sighting %d (%s): outcome=%s drift=%+v, want a plain match", i, k.Value, res.Outcome, res.Drift)
		}
	}
	if !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) || !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKeyRSA) {
		t.Errorf("identifiers = %+v, want both the ed25519 and the RSA key kept", repo.Identifiers(asset))
	}
	noDriftEntries(t, repo, asset)
}

// A key of an algorithm the asset has not shown is ADDED, also on an
// address-only sighting where a changed key would otherwise be flagged.
func TestDrift_NewAlgorithmAppears_Added(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	addr := scoped(identity.KindIPAddress, driftIP, driftSeg)
	asset := establish(t, e, driftObs(t0, addr, hostKey(driftKey, "ssh-ed25519")))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), addr, hostKey(driftKeyRSA, "rsa-sha2-256")))

	if res.Outcome != identity.OutcomeMatched || res.Drift != nil {
		t.Fatalf("outcome=%s drift=%+v, want a plain match", res.Outcome, res.Drift)
	}
	for _, k := range repo.Identifiers(asset) {
		if k.Value == driftKeyRSA && k.KeyAlgorithm != "rsa" {
			t.Errorf("the added key's algorithm = %q, want rsa", k.KeyAlgorithm)
		}
	}
	if !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) || !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKeyRSA) {
		t.Errorf("identifiers = %+v, want both keys", repo.Identifiers(asset))
	}
	noDriftEntries(t, repo, asset)
}

// The same algorithm with a new fingerprint is a rotation, and it replaces
// ONLY that algorithm's key: the host's RSA key stays.
func TestDrift_SameAlgorithmChanged_RotatesOnlyThatAlgorithm(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	base := []identity.Identifier{id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg)}
	asset := establish(t, e, driftObs(t0, append(base, hostKey(driftKey, "ssh-ed25519"), hostKey(driftKeyRSA, "ssh-rsa"))...))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), append(base, hostKey(driftKey2, "ssh-ed25519"))...))

	if res.Drift == nil || res.Drift.Verdict != matcher.DriftRotated {
		t.Fatalf("drift = %+v, want rotated", res.Drift)
	}
	if holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) {
		t.Error("the replaced ed25519 key is still on the asset")
	}
	if !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKeyRSA) {
		t.Error("the RSA key — a different algorithm, not rotated — was retired")
	}
	if c := changeFor(t, res.Drift, identity.KindSSHHostKeyFingerprint); len(c.Previous) != 1 || c.Previous[0] != driftKey {
		t.Errorf("change = %+v, want only the ed25519 key as previous", c)
	}
	driftEntry(t, repo, asset, identity.ActionSSHHostKeyRotated)
}

// A key stored before algorithms were recorded has no algorithm. A different
// fingerprint against it is never a rotation and never deletes it; on a
// MAC-known host it is simply attached.
func TestDrift_StoredAlgorithmUnknown_NoRotationNoDeletion(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	base := []identity.Identifier{id(identity.KindMACAddress, driftMAC), scoped(identity.KindIPAddress, driftIP, driftSeg)}
	asset := establish(t, e, driftObs(t0, append(base, id(identity.KindSSHHostKeyFingerprint, driftKey))...))

	res := mustResolve(t, e, driftObs(t0.Add(time.Hour), append(base, hostKey(driftKey2, "ssh-ed25519"))...))

	if res.Outcome != identity.OutcomeMatched || res.Drift != nil {
		t.Fatalf("outcome=%s drift=%+v, want a plain match", res.Outcome, res.Drift)
	}
	if !holds(repo, asset, identity.KindSSHHostKeyFingerprint, driftKey) {
		t.Error("a key of unknown algorithm was deleted")
	}
	noDriftEntries(t, repo, asset)

	// And a later sighting that names the stored key's algorithm fills it in.
	mustResolve(t, e, driftObs(t0.Add(2*time.Hour), append(base, hostKey(driftKey, "ssh-rsa"))...))
	for _, k := range repo.Identifiers(asset) {
		if k.Value == driftKey && k.KeyAlgorithm != "rsa" {
			t.Errorf("stored key's algorithm after a sighting that names it = %q, want rsa", k.KeyAlgorithm)
		}
	}
}

// A pinned address (decision 1) is never released by a move: the device has
// two addresses, not a new one.
func TestDrift_PinnedAddressIsNeverReleased(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	t0 := observedAt
	keys := []identity.Identifier{id(identity.KindMACAddress, driftMAC), hostKey(driftKey, "ssh-ed25519")}
	pinned := scoped(identity.KindIPAddress, driftIP, driftSeg)
	pinned.Assignment = identity.AssignmentStatic
	asset := establish(t, e, driftObs(t0, append(keys, pinned)...))

	res := mustResolve(t, e, driftObs(t0.Add(identity.MovedSilence+time.Hour), append(keys, scoped(identity.KindIPAddress, driftIP2, driftSeg))...))

	if res.Outcome != identity.OutcomeMatched || res.Drift != nil {
		t.Fatalf("outcome=%s drift=%+v, want a plain match", res.Outcome, res.Drift)
	}
	if !holds(repo, asset, identity.KindIPAddress, driftIP) {
		t.Error("the pinned address was released")
	}
	noDriftEntries(t, repo, asset)
}
