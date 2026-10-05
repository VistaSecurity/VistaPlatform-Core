package services

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The suggestion table of the Observations review spec ( §1), one case
// per row and one per precedence edge. Every case names the row it pins, so a
// failure says which sentence of the spec stopped being true.

var reviewNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

const (
	rDynamic   = identity.ReasonDynamicAddressWithoutDeviceBinding
	rUnplaced  = identity.ReasonNetworkScopeUnresolved
	rRelayed   = "unverified_relayed_advertisement"
	rNameOnly  = identity.ReasonNoDeviceOrAddressBinding
	rNoCollect = identityenrichment.ReasonNoEligibleCollector
)

func scanEvidence() identity.Observation {
	return identity.Observation{
		Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: "192.0.2.17"}},
		Endpoints: []identity.EndpointObservation{
			{Address: "192.0.2.17", Port: 22, Transport: "tcp", Protocol: "ssh"},
			{Address: "192.0.2.17", Port: 8443, Transport: "tcp", Protocol: "tls"},
		},
	}
}

func suggest(state string, reasons []string, enrichment string, ev identity.Observation, lastSeen time.Time) ObservationSuggestion {
	return SuggestObservation(ObservationSuggestionInput{
		State: state, AdmissionReasons: reasons, EnrichmentReason: enrichment, Evidence: ev, LastSeenAt: lastSeen,
		NetworkName: "Office LAN", SourceName: "Platform sensor",
	}, reviewNow)
}

func TestSuggestObservation_TableRows(t *testing.T) {
	recent := reviewNow.Add(-time.Hour)
	nameOnly := identity.Observation{Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "printer"}}}
	addressNoEndpoint := identity.Observation{Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: "192.0.2.17"}}}
	endpointOnly := identity.Observation{Endpoints: []identity.EndpointObservation{{Address: "192.0.2.18", Port: 443, Transport: "tcp"}}}
	for _, tc := range []struct {
		row        string
		state      string
		reasons    []string
		enrichment string
		evidence   identity.Observation
		lastSeen   time.Time
		needs      string
		action     string
		code       string
	}{
		{"dynamic address + address + endpoint → ready", "unresolved", []string{rDynamic}, "", scanEvidence(), recent, NeedsReadyToConfirm, SuggestConfirm, ExplainDynamicAddressAnswered},
		{"dynamic, address only from an endpoint → ready", "unresolved", []string{rDynamic}, "", endpointOnly, recent, NeedsReadyToConfirm, SuggestConfirm, ExplainDynamicAddressAnswered},
		{"network_scope_unresolved → needs network", "unresolved", []string{rUnplaced}, "", scanEvidence(), recent, NeedsNetwork, SuggestAddNetwork, ExplainNetworkNotConfigured},
		{"relayed advertisement → needs sensor", "unresolved", []string{rRelayed}, "", scanEvidence(), recent, NeedsSensor, SuggestSensorOptions, ExplainRelayedAdvertisement},
		{"no eligible collector → needs sensor", "unresolved", []string{rDynamic}, rNoCollect, scanEvidence(), recent, NeedsSensor, SuggestSensorOptions, ExplainNoCollectorInNetwork},
		{"name only → likely noise", "unresolved", []string{rNameOnly}, "", nameOnly, recent, NeedsLikelyNoise, SuggestDismiss, ExplainNameOnly},
		{"no address and no endpoints → likely noise", "unresolved", []string{"insufficient_identity_evidence"}, "", nameOnly, recent, NeedsLikelyNoise, SuggestDismiss, ExplainNoAddressOrService},
		{"last seen > 30 days → likely noise", "unresolved", []string{"insufficient_identity_evidence"}, "", scanEvidence(), reviewNow.Add(-31 * 24 * time.Hour), NeedsLikelyNoise, SuggestDismiss, ExplainNotSeenRecently},
		{"dynamic WITHOUT an endpoint is not ready", "unresolved", []string{rDynamic}, "", addressNoEndpoint, recent, NeedsNone, SuggestNone, ExplainNoSuggestion},
		{"no recognised reason → no suggestion", "unresolved", []string{"insufficient_identity_evidence"}, "", scanEvidence(), recent, NeedsNone, SuggestNone, ExplainNoSuggestion},
		{"exactly 30 days is not yet stale", "unresolved", []string{"insufficient_identity_evidence"}, "", scanEvidence(), reviewNow.Add(-30 * 24 * time.Hour), NeedsNone, SuggestNone, ExplainNoSuggestion},
	} {
		t.Run(tc.row, func(t *testing.T) {
			got := suggest(tc.state, tc.reasons, tc.enrichment, tc.evidence, tc.lastSeen)
			if got.Needs != tc.needs || got.SuggestedAction != tc.action || got.ExplanationCode != tc.code {
				t.Fatalf("got needs=%s action=%s code=%s, want %s/%s/%s", got.Needs, got.SuggestedAction, got.ExplanationCode, tc.needs, tc.action, tc.code)
			}
			if got.SuggestedReason == "" {
				t.Fatal("an unresolved row must carry a suggested reason")
			}
		})
	}
}

// Precedence: each pair puts two reasons on one row and asserts the higher one
// wins. Swapping any two cases of SuggestObservation's switch turns one red.
func TestSuggestObservation_Precedence(t *testing.T) {
	recent := reviewNow.Add(-time.Hour)
	stale := reviewNow.Add(-40 * 24 * time.Hour)
	for _, tc := range []struct {
		name       string
		reasons    []string
		enrichment string
		lastSeen   time.Time
		needs      string
		code       string
	}{
		{"network beats sensor", []string{rRelayed, rUnplaced}, "", recent, NeedsNetwork, ExplainNetworkNotConfigured},
		{"network beats no-collector", []string{rUnplaced}, rNoCollect, recent, NeedsNetwork, ExplainNetworkNotConfigured},
		{"network beats ready", []string{rDynamic, rUnplaced}, "", recent, NeedsNetwork, ExplainNetworkNotConfigured},
		{"network beats noise", []string{rNameOnly, rUnplaced}, "", stale, NeedsNetwork, ExplainNetworkNotConfigured},
		{"relayed beats no-collector wording", []string{rRelayed}, rNoCollect, recent, NeedsSensor, ExplainRelayedAdvertisement},
		{"sensor beats ready", []string{rDynamic, rRelayed}, "", recent, NeedsSensor, ExplainRelayedAdvertisement},
		{"no-collector beats ready", []string{rDynamic}, rNoCollect, recent, NeedsSensor, ExplainNoCollectorInNetwork},
		{"sensor beats noise", []string{rNameOnly, rRelayed}, "", stale, NeedsSensor, ExplainRelayedAdvertisement},
		{"ready beats name-only noise", []string{rNameOnly, rDynamic}, "", recent, NeedsReadyToConfirm, ExplainDynamicAddressAnswered},
		{"ready beats stale", []string{rDynamic}, "", stale, NeedsReadyToConfirm, ExplainDynamicAddressAnswered},
		{"name-only beats stale wording", []string{rNameOnly}, "", stale, NeedsLikelyNoise, ExplainNameOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := suggest("unresolved", tc.reasons, tc.enrichment, scanEvidence(), tc.lastSeen)
			if got.Needs != tc.needs || got.ExplanationCode != tc.code {
				t.Fatalf("got %s/%s, want %s/%s", got.Needs, got.ExplanationCode, tc.needs, tc.code)
			}
		})
	}
}

// Ownership: the dynamic-address row is only "ready to confirm" when no
// existing asset owns one of its identifiers — the decision refuses Confirm
// otherwise.
func TestSuggestObservation_Ownership(t *testing.T) {
	recent := reviewNow.Add(-time.Hour)
	router := uuid.New()
	with := func(owners ...ObservationOwner) ObservationSuggestion {
		return SuggestObservation(ObservationSuggestionInput{
			State: "unresolved", AdmissionReasons: []string{rDynamic}, Evidence: scanEvidence(), LastSeenAt: recent, Owners: owners,
			NetworkName: "Office LAN", SourceName: "Platform sensor",
		}, reviewNow)
	}
	one := with(ObservationOwner{ID: router, Name: "dream-router", Linkable: true})
	if one.Needs != NeedsLinkExisting || one.SuggestedAction != SuggestLink || one.ExplanationCode != ExplainOwnedByAsset || one.LinkAsset == nil || one.LinkAsset.ID != router {
		t.Fatalf("one owner: %+v", one)
	}
	const want = "Linked from Observations: SSH 22 and TLS 8443 seen at 192.0.2.17 on Office LAN (Platform sensor) — already belongs to dream-router."
	if one.SuggestedReason != want {
		t.Fatalf("link reason\n got %q\nwant %q", one.SuggestedReason, want)
	}
	if unnamed := with(ObservationOwner{ID: router, Linkable: true}); !strings.Contains(unnamed.SuggestedReason, "an existing asset") || uuidRE.MatchString(unnamed.SuggestedReason) {
		t.Fatalf("an unnamed owner must read as words, not an id: %q", unnamed.SuggestedReason)
	}
	for name, owners := range map[string][]ObservationOwner{
		"two owners":                   {{ID: router, Linkable: true}, {ID: uuid.New(), Linkable: true}},
		"one owner that cannot link":   {{ID: router, Linkable: false}},
		"two owners, neither can link": {{ID: router}, {ID: uuid.New()}},
	} {
		got := with(owners...)
		if got.Needs != NeedsReview || got.SuggestedAction != SuggestNone || got.ExplanationCode != ExplainOwnedBySeveralAssets || got.LinkAsset != nil || got.SuggestedReason == "" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	if none := with(); none.Needs != NeedsReadyToConfirm {
		t.Fatalf("no owner: %+v", none)
	}
	// Ownership only reshapes the dynamic-address row; the rows above it keep their precedence.
	if got := SuggestObservation(ObservationSuggestionInput{State: "unresolved", AdmissionReasons: []string{rUnplaced}, Evidence: scanEvidence(), LastSeenAt: recent,
		Owners: []ObservationOwner{{ID: router, Linkable: true}}}, reviewNow); got.Needs != NeedsNetwork {
		t.Fatalf("an owned row that needs a network: %s", got.Needs)
	}
}

func TestSuggestObservation_DecidedStatesHaveNoSuggestion(t *testing.T) {
	for _, state := range []string{"linked", "conflict", "dismissed", "expired"} {
		t.Run(state, func(t *testing.T) {
			// The strongest "ready" evidence there is: still nothing to suggest.
			got := suggest(state, []string{rDynamic}, "", scanEvidence(), reviewNow.Add(-time.Hour))
			if got.Needs != NeedsNone || got.SuggestedAction != SuggestNone || got.ExplanationCode != ExplainNotAwaitingReview {
				t.Fatalf("state %s: got %+v, want none", state, got)
			}
			if wantReason := state == "expired"; (got.SuggestedReason != "") != wantReason {
				t.Fatalf("state %s: suggested reason %q (only an expired row can still be dismissed)", state, got.SuggestedReason)
			}
		})
	}
}

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func TestSuggestObservation_ReasonSentences(t *testing.T) {
	got := suggest("unresolved", []string{rDynamic}, "", scanEvidence(), reviewNow.Add(-time.Hour))
	const want = "Confirmed from Observations: SSH 22 and TLS 8443 seen at 192.0.2.17 on Office LAN (Platform sensor)."
	if got.SuggestedReason != want {
		t.Fatalf("confirm reason\n got %q\nwant %q", got.SuggestedReason, want)
	}
	noise := suggest("unresolved", []string{rNameOnly}, "", identity.Observation{Hostname: "lobby-tv"}, reviewNow)
	if !strings.HasPrefix(noise.SuggestedReason, "Dismissed from Observations: A device seen as lobby-tv on Office LAN (Platform sensor)") {
		t.Fatalf("dismiss reason %q", noise.SuggestedReason)
	}
	// A network without a resolved name is left out, never shown as its id.
	in := ObservationSuggestionInput{State: "unresolved", AdmissionReasons: []string{rDynamic}, Evidence: scanEvidence(), LastSeenAt: reviewNow, SourceName: "Discovery scan"}
	if r := SuggestObservation(in, reviewNow).SuggestedReason; uuidRE.MatchString(r) || strings.Contains(r, " on ") {
		t.Fatalf("unnamed network leaked into %q", r)
	}
	// Many services are counted, not listed.
	many := scanEvidence()
	for _, p := range []int{80, 443, 3389, 5900} {
		many.Endpoints = append(many.Endpoints, identity.EndpointObservation{Address: "192.0.2.17", Port: p, Transport: "tcp"})
	}
	if r := suggest("unresolved", []string{rDynamic}, "", many, reviewNow).SuggestedReason; !strings.Contains(r, "TCP 443 and 2 more") {
		t.Fatalf("service list not bounded: %q", r)
	}
}

func TestSummarizeObservation_ReadableAndShortened(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("abcdefgh", 6)
	got := summarizeObservation(identity.Observation{
		Hostname: "nas",
		Identifiers: []identity.Identifier{
			{Kind: identity.KindSSHHostKeyFingerprint, Value: fp},
			{Kind: identity.KindIPAddress, Value: "192.0.2.17"},
			{Kind: identity.KindHostname, Value: "nas"},
		},
	})
	if len(got) != 3 {
		t.Fatalf("summary %+v, want hostname, address and host key once each", got)
	}
	if got[0].Label != "Hostname" || got[1].Label != "IP address" || got[2].Label != "SSH host key" {
		t.Fatalf("order/labels %+v", got)
	}
	if got[2].Value == fp || !strings.Contains(got[2].Value, "…") || len([]rune(got[2].Value)) > displayLimit {
		t.Fatalf("fingerprint not shortened for display: %q", got[2].Value)
	}
	if got[1].Value != "192.0.2.17" {
		t.Fatalf("address altered: %q", got[1].Value)
	}
}

func TestObservationSourceName(t *testing.T) {
	for _, tc := range []struct{ kind, ref, sensor, want string }{
		{"measured", "sensor:3f2a7c1e-1b2c-4d5e-8f90-123456789abc", "Branch sensor", "Branch sensor"},
		{"measured", "sensor:3f2a7c1e-1b2c-4d5e-8f90-123456789abc", "", "Sensor"},
		{"measured", "scan:3f2a7c1e-1b2c-4d5e-8f90-123456789abc", "", "Discovery scan"},
		{"measured", "sensor:pcap", "", "Packet capture"},
		{"measured", "sensor:identity-dns:3f2a7c1e-1b2c-4d5e-8f90-123456789abc", "", "Identity check"},
		{"measured", "cloud:aws", "", "Cloud discovery (AWS)"},
		{"imported", "netbox:3f2a7c1e-1b2c-4d5e-8f90-123456789abc", "", "NetBox import"},
		{"imported", "something-new", "", "Imported source"},
	} {
		got := observationSourceName(tc.kind, tc.ref, tc.sensor)
		if got != tc.want {
			t.Errorf("%s %q: got %q, want %q", tc.kind, tc.ref, got, tc.want)
		}
		if uuidRE.MatchString(got) {
			t.Errorf("%q leaked a UUID", got)
		}
	}
}
