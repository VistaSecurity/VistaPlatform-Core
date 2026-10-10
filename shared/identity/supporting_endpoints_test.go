package identity_test

// WP7: endpoints are written only inside the engine.
//
//   - D4: a SUPPORTING outcome with exactly one owner attaches the
//     observation's endpoints to that owner when the measurement reached the
//     device (measured, direct, not relayed) and the owner is neither archived
//     nor denied. Everything else that is supporting holds them.
//   - F12: a MATCH carrying a complete endpoint set closes that source's
//     earlier endpoints the set no longer lists, in the engine's transaction;
//     supporting evidence never does.

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const (
	hostinvMAC      = "02:aa:bb:cc:dd:42"
	hostinvHostname = "build-01"
	hostinvAgentRef = "agent:7f1c"
)

// hostinvEstablished creates an established asset from a direct sighting
// carrying a MAC and a hostname, with the given endpoints.
func hostinvEstablished(t *testing.T, e *identity.Engine, eps ...identity.EndpointObservation) identity.Resolution {
	t.Helper()
	obs := direct(advertAt, segmentB,
		id(identity.KindMACAddress, hostinvMAC),
		scoped(identity.KindHostname, hostinvHostname, segmentB))
	obs.Endpoints = eps
	res := mustResolve(t, e, obs)
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup: outcome = %s, want created", res.Outcome)
	}
	return res
}

// hostinvNameOnly is a direct, measured sighting that names the asset by its
// hostname alone: not established (no device or address binding), so the
// name cannot decide, and its single owner makes it supporting evidence.
func hostinvNameOnly(at time.Time, eps ...identity.EndpointObservation) identity.Observation {
	obs := direct(at, segmentB, scoped(identity.KindHostname, hostinvHostname, segmentB))
	obs.Endpoints = eps
	return obs
}

func hostinvEndpoint(port int) identity.EndpointObservation {
	return identity.EndpointObservation{Address: "192.0.2.42", Port: port, Transport: "tcp"}
}

func hostinvEndpointKeys(eps []identity.EndpointObservation) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.Key())
	}
	slices.Sort(out)
	return out
}

func TestSupportingD4_DirectMeasurementAttachesEndpointsToTheSingleOwner(t *testing.T) {
	e, repo := newProvisionalEngine(t, false)
	created := hostinvEstablished(t, e)
	identifiersBefore := len(repo.Identifiers(created.Asset))

	later := advertAt.Add(time.Hour)
	res := mustResolve(t, e, hostinvNameOnly(later, hostinvEndpoint(8443)))

	if res.Outcome != identity.OutcomeSupporting || res.Asset.ID != created.Asset.ID {
		t.Fatalf("outcome = %s on %q, want supporting on %s", res.Outcome, res.Asset.ID, created.Asset.ID)
	}
	if res.EvidenceHeld || !res.SupportingEndpoints {
		t.Errorf("EvidenceHeld = %t, SupportingEndpoints = %t; a direct measurement's sockets belong to its single owner (D4)",
			res.EvidenceHeld, res.SupportingEndpoints)
	}
	if got := hostinvEndpointKeys(repo.Endpoints(created.Asset)); !slices.Equal(got, []string{hostinvEndpoint(8443).Key()}) {
		t.Errorf("endpoints = %v, want the supporting sighting's :8443", got)
	}
	if got := len(repo.Identifiers(created.Asset)); got != identifiersBefore {
		t.Errorf("identifiers %d -> %d: D4 attaches sockets, never the supporting evidence's identifiers", identifiersBefore, got)
	}
	var recorded bool
	for _, h := range repo.HistoryFor(created.Asset) {
		if h.Action == identity.ActionUpdated && h.Changes["supporting"] == true {
			if keys, ok := h.Changes["endpoints"].([]string); ok && len(keys) == 1 {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Errorf("no supporting history row names the attached endpoint: %+v", repo.HistoryFor(created.Asset))
	}
}

func TestSupportingD4_HoldsEndpointsUnlessTheMeasurementReachedALiveOwner(t *testing.T) {
	cases := map[string]func(*identity.Observation, *admissionRepo, identity.AssetRef){
		"relayed": func(o *identity.Observation, _ *admissionRepo, _ identity.AssetRef) {
			o.Admission = identity.AdmissionEvidence{Relayed: true}
		},
		"not direct": func(o *identity.Observation, _ *admissionRepo, _ identity.AssetRef) {
			o.Admission = identity.AdmissionEvidence{}
		},
		"not measured": func(o *identity.Observation, _ *admissionRepo, _ identity.AssetRef) {
			o.Source = identity.Source{Kind: identity.SourceImported, Ref: "csv:upload-1", Mode: identity.ModeActive}
		},
		"archived owner": func(_ *identity.Observation, r *admissionRepo, ref identity.AssetRef) {
			r.SetStatus(ref, identity.StatusArchived)
		},
		"denied owner": func(_ *identity.Observation, r *admissionRepo, ref identity.AssetRef) {
			r.SetStatus(ref, identity.StatusDenied)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, repo := newProvisionalEngine(t, false)
			created := hostinvEstablished(t, e)
			obs := hostinvNameOnly(advertAt.Add(time.Hour), hostinvEndpoint(8443))
			mutate(&obs, repo, created.Asset)
			res, err := e.Resolve(t.Context(), obs)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := repo.Endpoints(created.Asset); len(got) != 0 {
				t.Errorf("outcome %s wrote endpoints %v; only a direct measurement of a live owner may", res.Outcome, hostinvEndpointKeys(got))
			}
			if res.SupportingEndpoints {
				t.Error("SupportingEndpoints set although nothing was attached")
			}
		})
	}
}

func TestSupportingD4_ContestedEvidenceAttachesNoEndpoint(t *testing.T) {
	e, repo := newProvisionalEngine(t, false)
	a := hostinvEstablished(t, e)
	other := direct(advertAt, segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:43"),
		scoped(identity.KindHostname, "build-02", segmentB))
	b := mustResolve(t, e, other)
	if b.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup: second asset outcome = %s", b.Outcome)
	}
	obs := direct(advertAt.Add(time.Hour), segmentB,
		scoped(identity.KindHostname, hostinvHostname, segmentB),
		scoped(identity.KindHostname, "build-02", segmentB))
	obs.Endpoints = []identity.EndpointObservation{hostinvEndpoint(8443)}
	res := mustResolve(t, e, obs)
	if res.Outcome == identity.OutcomeSupporting || res.Outcome == identity.OutcomeMatched {
		t.Fatalf("outcome = %s, want a contested or unresolved outcome for evidence naming two owners", res.Outcome)
	}
	for _, ref := range []identity.AssetRef{a.Asset, b.Asset} {
		if got := repo.Endpoints(ref); len(got) != 0 {
			t.Errorf("contested evidence wrote endpoints %v on %s", hostinvEndpointKeys(got), ref.ID)
		}
	}
}

// hostinvAgentEndpoint is a socket from the agent's run `run`.
func hostinvAgentEndpoint(port int, run string) identity.EndpointObservation {
	ep := hostinvEndpoint(port)
	ep.Source = identity.Source{Kind: identity.SourceMeasured, Ref: hostinvAgentRef + ":" + run, Mode: identity.ModeActive}
	return ep
}

// hostinvAgentReport is a host's own complete report: MAC-decided, with the
// complete-set marker for the agent's prefix.
func hostinvAgentReport(at time.Time, eps ...identity.EndpointObservation) identity.Observation {
	obs := direct(at, segmentB, id(identity.KindMACAddress, hostinvMAC))
	obs.Source = identity.Source{Kind: identity.SourceMeasured, Ref: hostinvAgentRef, Mode: identity.ModeActive}
	obs.Endpoints = eps
	obs.EndpointsComplete = &identity.CompleteEndpointSet{SourcePrefix: hostinvAgentRef + ":"}
	return obs
}

func TestCompleteEndpointSet_AMatchClosesTheSourcesAbsentSockets(t *testing.T) {
	e, repo := newProvisionalEngine(t, false)
	scan := hostinvEndpoint(9443)
	scan.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:scanner", Mode: identity.ModeActive}
	created := hostinvEstablished(t, e, hostinvAgentEndpoint(22, "run1"), hostinvAgentEndpoint(443, "run1"), scan)

	res := mustResolve(t, e, hostinvAgentReport(advertAt.Add(time.Hour), hostinvAgentEndpoint(22, "run2")))
	if res.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome = %s, want matched", res.Outcome)
	}
	want := []string{hostinvEndpoint(443).Key()}
	if got := repo.ClosedEndpoints(created.Asset); !slices.Equal(got, want) {
		t.Errorf("closed = %v, want %v: the agent dropped :443; :22 is still listed and :9443 is the scanner's", got, want)
	}
	if res.EndpointsClosed != 1 {
		t.Errorf("EndpointsClosed = %d, want 1", res.EndpointsClosed)
	}
	var recorded bool
	for _, h := range repo.HistoryFor(created.Asset) {
		if keys, ok := h.Changes["endpoints_closed"].([]string); ok && slices.Equal(keys, want) {
			recorded = true
		}
	}
	if !recorded {
		t.Error("the timeline does not say which endpoints the report closed")
	}

	// The socket comes back: the next report reopens it.
	mustResolve(t, e, hostinvAgentReport(advertAt.Add(2*time.Hour), hostinvAgentEndpoint(22, "run3"), hostinvAgentEndpoint(443, "run3")))
	if got := repo.ClosedEndpoints(created.Asset); len(got) != 0 {
		t.Errorf("closed = %v after the socket was reported again, want none", got)
	}
}

func TestCompleteEndpointSet_ClosesNothingWithoutAMatchOrAMarker(t *testing.T) {
	t.Run("no marker", func(t *testing.T) {
		e, repo := newProvisionalEngine(t, false)
		created := hostinvEstablished(t, e, hostinvAgentEndpoint(22, "run1"), hostinvAgentEndpoint(443, "run1"))
		obs := hostinvAgentReport(advertAt.Add(time.Hour), hostinvAgentEndpoint(22, "run2"))
		obs.EndpointsComplete = nil
		mustResolve(t, e, obs)
		if got := repo.ClosedEndpoints(created.Asset); len(got) != 0 {
			t.Errorf("closed = %v without a complete-set marker", got)
		}
	})
	t.Run("supporting", func(t *testing.T) {
		e, repo := newProvisionalEngine(t, false)
		created := hostinvEstablished(t, e, hostinvAgentEndpoint(22, "run1"), hostinvAgentEndpoint(443, "run1"))
		obs := hostinvNameOnly(advertAt.Add(time.Hour), hostinvAgentEndpoint(22, "run2"))
		obs.Source = identity.Source{Kind: identity.SourceMeasured, Ref: hostinvAgentRef, Mode: identity.ModeActive}
		obs.EndpointsComplete = &identity.CompleteEndpointSet{SourcePrefix: hostinvAgentRef + ":"}
		res := mustResolve(t, e, obs)
		if res.Outcome != identity.OutcomeSupporting {
			t.Fatalf("outcome = %s, want supporting", res.Outcome)
		}
		if got := repo.ClosedEndpoints(created.Asset); len(got) != 0 || res.EndpointsClosed != 0 {
			t.Errorf("supporting evidence closed %v (%d); a report that did not land on the asset says nothing about its sockets", got, res.EndpointsClosed)
		}
	})
	t.Run("supporting on a provisional asset", func(t *testing.T) {
		// The provisional branch is the one supporting path that writes
		// through applyToAsset, so it is where a kept set would reconcile.
		e, repo := newProvisionalEngine(t, true)
		sketch := advert(advertAt, segmentB, scoped(identity.KindHostname, hostinvHostname, segmentB))
		sketch.Endpoints = []identity.EndpointObservation{hostinvAgentEndpoint(22, "run1"), hostinvAgentEndpoint(443, "run1")}
		created := mustResolve(t, e, sketch)
		if created.Outcome != identity.OutcomeProvisional {
			t.Fatalf("setup: outcome = %s, want provisional", created.Outcome)
		}
		obs := hostinvNameOnly(advertAt.Add(time.Hour), hostinvAgentEndpoint(22, "run2"))
		obs.Source = identity.Source{Kind: identity.SourceMeasured, Ref: hostinvAgentRef, Mode: identity.ModeActive}
		obs.EndpointsComplete = &identity.CompleteEndpointSet{SourcePrefix: hostinvAgentRef + ":"}
		res := mustResolve(t, e, obs)
		if res.Outcome != identity.OutcomeSupporting {
			t.Fatalf("outcome = %s, want supporting", res.Outcome)
		}
		if got := repo.ClosedEndpoints(created.Asset); len(got) != 0 {
			t.Errorf("supporting evidence on a provisional asset closed %v", got)
		}
	})
	t.Run("older report", func(t *testing.T) {
		e, repo := newProvisionalEngine(t, false)
		created := hostinvEstablished(t, e, hostinvAgentEndpoint(22, "run1"), hostinvAgentEndpoint(443, "run1"))
		mustResolve(t, e, hostinvAgentReport(advertAt.Add(-time.Hour), hostinvAgentEndpoint(22, "run0")))
		if got := repo.ClosedEndpoints(created.Asset); len(got) != 0 {
			t.Errorf("a replayed older report closed %v, seen after it", got)
		}
	})
}

func TestCompleteEndpointSet_RefusesAPrefixOutsideTheSource(t *testing.T) {
	e, _ := newProvisionalEngine(t, false)
	hostinvEstablished(t, e)
	for name, mutate := range map[string]func(*identity.Observation){
		"foreign prefix":   func(o *identity.Observation) { o.EndpointsComplete.SourcePrefix = "sensor:" },
		"empty prefix":     func(o *identity.Observation) { o.EndpointsComplete.SourcePrefix = "" },
		"endpoint outside": func(o *identity.Observation) { o.Endpoints[0].Source.Ref = "sensor:scanner" },
	} {
		t.Run(name, func(t *testing.T) {
			obs := hostinvAgentReport(advertAt.Add(time.Hour), hostinvAgentEndpoint(22, "run2"))
			mutate(&obs)
			if _, err := e.Resolve(t.Context(), obs); !errors.Is(err, identity.ErrInvalidObservation) {
				t.Errorf("err = %v, want ErrInvalidObservation", err)
			}
		})
	}
}

func TestAttachDecidedEndpoints_WritesThroughIdentityAndRefusesARetiredAsset(t *testing.T) {
	e, repo := newProvisionalEngine(t, false)
	created := hostinvEstablished(t, e)
	obs := identity.Observation{TenantID: tenant, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:x"},
		Endpoints: []identity.EndpointObservation{hostinvEndpoint(8443)}}

	n, err := identity.AttachDecidedEndpoints(t.Context(), repo, obs, created.Asset, identity.DecidedByOperatorLink, advertAt.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("AttachDecidedEndpoints = %d, %v; want 1 endpoint written", n, err)
	}
	var named bool
	for _, h := range repo.HistoryFor(created.Asset) {
		if h.Changes["decided_by"] == string(identity.DecidedByOperatorLink) {
			named = true
		}
	}
	if !named {
		t.Error("the timeline does not name the decision that attached the endpoint")
	}
	if n, err := identity.AttachDecidedEndpoints(t.Context(), repo, obs, created.Asset, identity.DecidedByOperatorLink, advertAt.Add(time.Hour)); err != nil || n != 0 {
		t.Errorf("a repeat = %d, %v; want nothing new", n, err)
	}

	for _, status := range []string{identity.StatusArchived, identity.StatusDenied} {
		repo.SetStatus(created.Asset, status)
		obs.Endpoints = []identity.EndpointObservation{hostinvEndpoint(9443)}
		if n, err := identity.AttachDecidedEndpoints(t.Context(), repo, obs, created.Asset, identity.DecidedByInterrogatedDevice, advertAt.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("%s asset: AttachDecidedEndpoints = %d, %v; want nothing written", status, n, err)
		}
	}
	if got := len(repo.Endpoints(created.Asset)); got != 1 {
		t.Errorf("%d endpoints, want only the one attached while the asset was live", got)
	}
}
