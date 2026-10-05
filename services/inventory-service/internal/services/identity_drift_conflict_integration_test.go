package services

// The drift acceptance test of the Observations review table spec ( §3,
// from §H "stable networks").
//
// On a network that is NOT dynamic an address does identify a device, which is
// why a scan there may create and approve assets directly. The safety question
// that rule raises is what happens when the device BEHIND an address changes: a
// different machine answers at 192.0.2.40 with its own SSH host key, or its own
// MAC. The address still points at the established asset; the device-binding
// identifier says it may be someone else. That must come back for review, and
// must never be folded SILENTLY into the established asset.
//
// Owner Decision 4 of (the drift classifier, shared/identity/drift.go)
// says what "for review" means per case:
//
//   - a different MAC at the address is `replaced`: a conflict or a merge
//     proposal, and nothing written to the established asset;
//   - a different host key on an L3 sighting (no MAC) with nothing else known
//     is `unverified`: matched — the address is all anybody has — AND flagged:
//     an `identity_drift_flagged` timeline entry and a notification carrying
//     both fingerprints, with neither key retired. Before the classifier this
// case matched with no trace at all ( R5), and this test carried it as
//     a strict expected failure.
//
// Driven through the REAL intake (IngestFindingsReport → discoveryObservation →
// the production engine from svc.identityEngine()) on the provisional fixture's
// static segment, in `enforce` admission, which is how the dev cluster that
// prompted this runs.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const (
	driftAddr = "192.0.2.40"
	// RFC 7042 documentation MACs: universally administered, so neither is
	// dropped as an identifier before it reaches the engine.
	driftMAC1 = "00:00:5e:00:53:41"
	driftMAC2 = "00:00:5e:00:53:42"
)

// driftFinding is one active-scan sighting at driftAddr from sensor A. An SSH
// finding is DIRECT because it carries a host key; a TLS one because it carries
// a negotiated cipher suite — either is what lets the first sighting establish
// an asset on a static segment (AssessAdmission's direct_scoped_address).
func driftFinding(f *provisionalFixture, at time.Time, protocol string, raw map[string]interface{}) IngestFinding {
	addr, sensor := driftAddr, f.sensorA.String()
	raw["source"] = "active_scan"
	raw["observed_at"] = at.Format(time.RFC3339Nano)
	finding := IngestFinding{IPAddress: &addr, Protocol: protocol, SourceSensorID: &sensor, RawData: raw}
	port := 22
	if protocol == "TLS" {
		port = 443
		suite, version := "TLS_AES_128_GCM_SHA256", "TLS 1.3"
		finding.CipherSuite, finding.ProtocolVersion = &suite, &version
	}
	finding.Port = &port
	return finding
}

func (f *provisionalFixture) identifierOwners(kind, value string) []string {
	f.t.Helper()
	rows, err := f.raw.Query(`SELECT asset_id::text FROM asset_identifiers WHERE tenant_id=$1 AND kind=$2 AND lower(value)=lower($3) ORDER BY asset_id`, f.tenant, kind, value)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func (f *provisionalFixture) assetLastSeen(assetID string) time.Time {
	f.t.Helper()
	var seen sql.NullTime
	if err := f.raw.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, assetID).Scan(&seen); err != nil {
		f.t.Fatal(err)
	}
	return seen.Time
}

func TestIntegration_StableNetworkDrift_DifferentDeviceBindingNeedsReview(t *testing.T) {
	for _, tc := range []struct {
		name, kind, protocol, first, second string
		raw                                 func(value string) map[string]interface{}
		// flagged: the drift classifier matches and flags (`unverified`);
		// added: a key of a new algorithm — matched, attached, no event;
		// otherwise it must be a conflict or proposal (`replaced`).
		flagged, added bool
	}{
		{
			name: "ssh_host_key", kind: string(identity.KindSSHHostKeyFingerprint), protocol: "SSH",
			first: "SHA256:drift-first-host-key-aaaaaaaaaaaaaaaaaaaaaaaa", second: "SHA256:drift-second-host-key-bbbbbbbbbbbbbbbbbbbbbbb",
			raw: func(v string) map[string]interface{} {
				return map[string]interface{}{"ssh_host_key_fingerprint": v, "ssh_banner": "SSH-2.0-OpenSSH_9.6p1"}
			},
			flagged: true,
		},
		{
			// The probe names each key's type: an ed25519 key, then an RSA key
			// of the same host. A host offers one key per algorithm, so this is
			// another key, not a rotation — attached, nothing retired, no
			// event ( Decision 4).
			name: "ssh_host_key_new_algorithm", kind: string(identity.KindSSHHostKeyFingerprint), protocol: "SSH",
			first: "SHA256:drift-ed25519-host-key-aaaaaaaaaaaaaaaaaaaaa", second: "SHA256:drift-rsa-host-key-bbbbbbbbbbbbbbbbbbbbbbbbb",
			raw: func(v string) map[string]interface{} {
				alg := "ssh-ed25519"
				if strings.Contains(v, "rsa") {
					alg = "rsa-sha2-512"
				}
				return map[string]interface{}{"ssh_host_key_fingerprint": v, "ssh_host_key_type": alg, "ssh_banner": "SSH-2.0-OpenSSH_9.6p1"}
			},
			added: true,
		},
		{
			// TLS, so the only device-binding identifier in play is the MAC.
			name: "mac_address", kind: string(identity.KindMACAddress), protocol: "TLS",
			first: driftMAC1, second: driftMAC2,
			raw: func(v string) map[string]interface{} { return map[string]interface{}{"mac_address": v} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProvisionalFixture(t)
			lc := &fakeLifecycle{}
			var notes []sharedevents.NotificationEvent
			f.svc.eventPublisher = &EventPublisherService{lifecycle: lc, notify: func(n sharedevents.NotificationEvent) error { notes = append(notes, n); return nil }}

			established := f.now.Add(-2 * time.Hour)
			first, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{driftFinding(f, established, tc.protocol, tc.raw(tc.first))}, "monitoring")
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Results) != 1 || first.Results[0].AssetID == "" {
				t.Fatalf("setup: the first sighting did not establish an asset: %+v", first.Results)
			}
			asset := first.Results[0].AssetID
			var status string
			if err := f.raw.QueryRow(`SELECT identity_status FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, asset).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != string(identity.IdentityEstablished) {
				t.Fatalf("setup: identity_status=%s, want established", status)
			}
			if got := f.identifierOwners(string(identity.KindIPAddress), driftAddr); len(got) != 1 || got[0] != asset {
				t.Fatalf("setup: ip_address owners=%v, want [%s]", got, asset)
			}
			if got := f.identifierOwners(tc.kind, tc.first); len(got) != 1 || got[0] != asset {
				t.Fatalf("setup: %s owners=%v, want [%s]", tc.kind, got, asset)
			}
			seenBefore := f.assetLastSeen(asset)
			proposalsBefore := f.mergeProposals()
			lc.got, notes = nil, nil

			// A different device binding now answers at the same static address.
			drift, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{driftFinding(f, f.now.Add(-time.Minute), tc.protocol, tc.raw(tc.second))}, "monitoring")
			if err != nil {
				t.Fatal(err)
			}
			if len(drift.Results) != 1 {
				t.Fatalf("results=%+v, want one", drift.Results)
			}
			got := drift.Results[0]

			if tc.added {
				if got.AssetID != asset || got.Outcome != string(identity.OutcomeMatched) {
					t.Fatalf("outcome=%s asset=%s, want matched on %s", got.Outcome, got.AssetID, asset)
				}
				for _, key := range []string{tc.first, tc.second} {
					if owners := f.identifierOwners(tc.kind, key); len(owners) != 1 || owners[0] != asset {
						t.Errorf("%s owners=%v, want both algorithms' keys on %s", key, owners, asset)
					}
				}
				var algs string
				if err := f.raw.QueryRow(`SELECT string_agg(coalesce(key_algorithm, '?'), ',' ORDER BY key_algorithm) FROM asset_identifiers
					WHERE tenant_id=$1 AND asset_id=$2 AND kind=$3`, f.tenant, asset, tc.kind).Scan(&algs); err != nil {
					t.Fatal(err)
				}
				if algs != "ed25519,rsa" {
					t.Errorf("stored key algorithms = %q, want ed25519,rsa", algs)
				}
				var drift int
				if err := f.raw.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2
					AND action IN ('ssh_host_key_rotated','identity_material_rotated','identity_drift_flagged')`, f.tenant, asset).Scan(&drift); err != nil {
					t.Fatal(err)
				}
				if drift != 0 || len(lc.got) != 0 || len(notes) != 0 {
					t.Errorf("a second algorithm's key produced drift: history=%d events=%+v notifications=%+v", drift, lc.got, notes)
				}
				return
			}
			if !tc.flagged {
				if got.AssetID == asset && got.Outcome == string(identity.OutcomeMatched) {
					t.Errorf("SILENT MATCH: a different %s at %s was matched to the established asset", tc.kind, driftAddr)
				}
				if after := f.assetLastSeen(asset); after.After(seenBefore) {
					t.Errorf("the established asset's last_seen advanced from %s to %s on another device's sighting", seenBefore, after)
				}
				for _, o := range f.identifierOwners(tc.kind, tc.second) {
					if o == asset {
						t.Errorf("the second device's %s was attached to the established asset", tc.kind)
					}
				}
				if got.Outcome != string(identity.OutcomeConflict) && f.mergeProposals() <= proposalsBefore {
					t.Errorf("no conflict and no merge proposal for review: outcome=%s asset=%s", got.Outcome, got.AssetID)
				}
				if len(lc.got) != 0 || len(notes) != 0 {
					t.Errorf("a replaced device published drift events %+v / %+v; it is a proposal", lc.got, notes)
				}
				return
			}

			// Matched AND flagged — never silent.
			if got.AssetID != asset || got.Outcome != string(identity.OutcomeMatched) {
				t.Fatalf("outcome=%s asset=%s, want matched on %s", got.Outcome, got.AssetID, asset)
			}
			for _, key := range []string{tc.first, tc.second} {
				if owners := f.identifierOwners(tc.kind, key); len(owners) != 1 || owners[0] != asset {
					t.Errorf("%s owners=%v, want both keys kept on %s until a person reviews", key, owners, asset)
				}
			}
			var flags int
			var changes string
			if err := f.raw.QueryRow(`SELECT count(*), coalesce(max(changes_json::text), '') FROM asset_history
				WHERE tenant_id=$1 AND asset_id=$2 AND action=$3`, f.tenant, asset, string(identity.ActionIdentityDriftFlagged)).Scan(&flags, &changes); err != nil {
				t.Fatal(err)
			}
			if flags != 1 || !strings.Contains(changes, `"needs_review": true`) || !strings.Contains(changes, tc.second) {
				t.Errorf("identity_drift_flagged entries=%d changes=%s, want one flagged entry naming the new key", flags, changes)
			}
			if len(lc.got) != 1 || lc.got[0].eventType != invevents.EventTypeAssetIdentityDrift {
				t.Errorf("lifecycle events = %+v, want one asset.identity_drift", lc.got)
			}
			if len(notes) != 1 || !strings.Contains(notes[0].Message, tc.first) || !strings.Contains(notes[0].Message, tc.second) {
				t.Errorf("notifications = %+v, want one carrying the old and new fingerprints", notes)
			}
		})
	}
}
