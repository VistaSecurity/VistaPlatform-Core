package matcher

import (
	"strings"
	"testing"
)

const (
	macA, macB   = "00:00:5e:00:53:01", "00:00:5e:00:53:02"
	keyA, keyB   = "SHA256:key-a", "SHA256:key-b"
	certA, certB = "AA:BB:CC", "dd:ee:ff"
	addrA, addrB = "192.0.2.10", "192.0.2.20"
	keyRSA       = "SHA256:key-rsa"
)

// sameAlgorithm is what most cases assume: both host keys are ed25519, so two
// different fingerprints are a same-algorithm change. Cases about algorithms
// set HostKeyAlgorithms themselves (an explicitly empty map means "unknown").
var sameAlgorithm = map[string]string{keyA: "ed25519", keyB: "ed25519", keyRSA: "rsa"}

func ids(kv ...string) map[string][]string {
	out := map[string][]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = append(out[kv[i]], kv[i+1])
	}
	return out
}

// TestClassifyDriftTable is one case per row of the owner's table (Decision 4
// of), plus the cases at its edges.
func TestClassifyDriftTable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       DriftInput
		verdict  DriftVerdict
		rule     string
		evidence map[DriftSignal]string
	}{
		{
			name: "same MAC and IP, new host key: rotated",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
			},
			verdict: DriftRotated, rule: "mac_and_address_kept_key_changed",
			evidence: map[DriftSignal]string{SignalMAC: "agree", SignalAddress: "agree", SignalHostKey: "differ"},
		},
		{
			name: "same MAC, host key and TLS key, new IP with the old one silent: moved",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrB, KindSSHHostKeyFingerprint, keyA), TLSCertFingerprints: []string{certA}},
				Candidate: DriftSide{
					Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA), TLSCertFingerprints: []string{"aabbcc"},
					SilentAddresses: []string{addrA},
				},
			},
			verdict: DriftMoved, rule: "keys_kept_address_changed",
			evidence: map[DriftSignal]string{SignalAddress: "differ", SignalTLSCert: "agree"},
		},
		{
			name: "same IP, new MAC and host key: replaced",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macB, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
			},
			verdict: DriftReplaced, rule: "address_kept_hardware_changed",
		},
		{
			name: "same IP, new MAC, no host key either side: replaced",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macB, KindIPAddress, addrA)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA)},
			},
			verdict: DriftReplaced, rule: "address_kept_hardware_changed",
		},
		{
			name: "same MAC, new host key, TLS key and hostname: reimaged",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "build-07"), TLSCertFingerprints: []string{certB}},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "db-primary"), TLSCertFingerprints: []string{certA}},
			},
			verdict: DriftReimaged, rule: "mac_kept_os_material_changed",
		},
		{
			name: "address only, new host key, TLS and hostname unchanged: rotated",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "db-primary"), TLSCertFingerprints: []string{certA}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "db-primary"), TLSCertFingerprints: []string{certA}},
			},
			verdict: DriftRotated, rule: "address_only_key_changed_rest_agrees",
		},
		{
			name: "address only, new host key, TLS and hostname changed too: replaced",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "build-07"), TLSCertFingerprints: []string{certB}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "db-primary"), TLSCertFingerprints: []string{certA}},
			},
			verdict: DriftReplaced, rule: "address_only_key_changed_rest_changed",
		},
		{
			name: "address only, new host key, nothing else known: unverified",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB), Ports: []string{"22/tcp"}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA), Ports: []string{"22/tcp"}},
			},
			verdict: DriftUnverified, rule: "address_only_key_changed_unconfirmed",
			// One shared port is not a profile.
			evidence: map[DriftSignal]string{SignalPorts: "unknown"},
		},
		{
			name: "address only, new host key, the stable signals disagree with each other: unverified",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "db-primary"), TLSCertFingerprints: []string{certB}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "db-primary"), TLSCertFingerprints: []string{certA}},
			},
			verdict: DriftUnverified, rule: "address_only_key_changed_unconfirmed",
		},
		{
			name: "address only, new host key, a wide port profile agrees: rotated",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB), Ports: []string{"22/tcp", "443/tcp", "5432/tcp"}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA), Ports: []string{"22/tcp", "443/tcp", "5432/tcp", "9100/tcp"}},
			},
			verdict: DriftRotated, rule: "address_only_key_changed_rest_agrees",
		},
		{
			name: "a serial agrees, new host key: rotated even with a new MAC",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindSerialNumber, "SN-1", KindMACAddress, macB, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB)},
				Candidate:   DriftSide{Identifiers: ids(KindSerialNumber, "SN-1", KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
			},
			verdict: DriftRotated, rule: "hardware_id_kept_key_changed",
		},
		{
			name: "a new address beside a live one is an addition, not a move",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrB)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA)},
			},
			verdict:  DriftNone,
			evidence: map[DriftSignal]string{SignalAddress: "unknown"},
		},
		{
			name: "a new IPv4 address while the IPv6 one is live is still a move of the IPv4 address",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrB)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindIPAddress, "2001:db8::1"), SilentAddresses: []string{addrA}},
			},
			verdict: DriftMoved, rule: "keys_kept_address_changed",
		},
		{
			name: "nothing changed",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
			},
			verdict: DriftNone,
		},
		{
			name: "a moved device whose host key ALSO changed is not called moved",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrB, KindSSHHostKeyFingerprint, keyB)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA), SilentAddresses: []string{addrA}},
			},
			verdict: DriftNone,
		},
		{
			name: "generic names neither agree nor differ",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "iphone"), GenericNames: []string{"iphone"}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "iphone")},
			},
			verdict: DriftUnverified, rule: "address_only_key_changed_unconfirmed",
			evidence: map[DriftSignal]string{SignalHostname: "unknown"},
		},
		{
			name: "two algorithms alternating: a key of a new algorithm is another key, not a change",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyRSA)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
			},
			verdict:  DriftNone,
			evidence: map[DriftSignal]string{SignalHostKey: "added"},
		},
		{
			name: "alternating back: the asset holds both algorithms, the probe saw one",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindSSHHostKeyFingerprint, keyRSA)},
			},
			verdict:  DriftNone,
			evidence: map[DriftSignal]string{SignalHostKey: "agree"},
		},
		{
			name: "same algorithm changed while another algorithm is also held: rotated",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB)},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindSSHHostKeyFingerprint, keyRSA)},
			},
			verdict: DriftRotated, rule: "mac_and_address_kept_key_changed",
			evidence: map[DriftSignal]string{SignalHostKey: "differ"},
		},
		{
			name: "address only, a new algorithm appears: added, no verdict",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyRSA)},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA)},
			},
			verdict:  DriftNone,
			evidence: map[DriftSignal]string{SignalHostKey: "added"},
		},
		{
			name: "stored key's algorithm unknown (recorded before algorithms were): no rotation on a MAC-known host",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB), HostKeyAlgorithms: map[string]string{keyB: "ed25519"}},
				Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA), HostKeyAlgorithms: map[string]string{}},
			},
			verdict:  DriftNone,
			evidence: map[DriftSignal]string{SignalHostKey: "unconfirmed"},
		},
		{
			name: "observed key's algorithm unknown, address only: flagged at most",
			in: DriftInput{
				Observation: DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "db-primary"), HostKeyAlgorithms: map[string]string{}},
				Candidate:   DriftSide{Identifiers: ids(KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "db-primary")},
			},
			verdict: DriftUnverified, rule: "address_only_key_changed_unconfirmed",
			evidence: map[DriftSignal]string{SignalHostKey: "unconfirmed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, side := range []*DriftSide{&tc.in.Observation, &tc.in.Candidate} {
				if side.HostKeyAlgorithms == nil {
					side.HostKeyAlgorithms = sameAlgorithm
				}
			}
			got := ClassifyDrift(tc.in)
			if got.Verdict != tc.verdict {
				t.Fatalf("verdict = %q (rule %q), want %q\nevidence: %+v", got.Verdict, got.Rule, tc.verdict, got.Evidence)
			}
			if got.Rule != tc.rule {
				t.Errorf("rule = %q, want %q", got.Rule, tc.rule)
			}
			for s, want := range tc.evidence {
				if a := got.Agreement(s); a != want {
					t.Errorf("%s = %s, want %s", s, a, want)
				}
			}
			if len(got.Evidence) != len(DriftSignals) {
				t.Errorf("evidence has %d signals, want all %d", len(got.Evidence), len(DriftSignals))
			}
			if tc.verdict != DriftNone && !strings.Contains(got.Explanation, tc.rule) {
				t.Errorf("explanation %q does not name its rule", got.Explanation)
			}
		})
	}
}

// TestDriftExplanationCarriesNoValues: like the matcher's own explanation, a
// drift explanation names the SIGNAL, never the fingerprint or address.
func TestDriftExplanationCarriesNoValues(t *testing.T) {
	got := ClassifyDrift(DriftInput{
		Observation: DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyB, KindHostname, "build-07"), TLSCertFingerprints: []string{certB}, HostKeyAlgorithms: sameAlgorithm},
		Candidate:   DriftSide{Identifiers: ids(KindMACAddress, macA, KindIPAddress, addrA, KindSSHHostKeyFingerprint, keyA, KindHostname, "db-primary"), TLSCertFingerprints: []string{certA}, HostKeyAlgorithms: sameAlgorithm},
	})
	if got.Verdict != DriftReimaged {
		t.Fatalf("setup: verdict = %q", got.Verdict)
	}
	for _, v := range []string{macA, keyA, keyB, certA, certB, addrA, "build-07", "db-primary"} {
		if strings.Contains(strings.ToLower(got.Explanation), strings.ToLower(v)) {
			t.Errorf("explanation leaks %q: %s", v, got.Explanation)
		}
	}
	for _, phrase := range []string{"unchanged: hardware address", "changed: SSH host key, TLS certificate, name"} {
		if !strings.Contains(got.Explanation, phrase) {
			t.Errorf("explanation %q lacks %q", got.Explanation, phrase)
		}
	}
}

// TestDriftTableRowsAreComplete: every row has a name, a verdict, a condition
// and a sentence, and the owner's rows are all present. (That each row is the
// FIRST match for some input is what TestClassifyDriftTable's per-row cases
// show.)
func TestDriftTableRowsAreComplete(t *testing.T) {
	names := map[string]bool{}
	for _, r := range DriftTable {
		if names[r.Name] {
			t.Errorf("duplicate row name %q", r.Name)
		}
		names[r.Name] = true
		if r.Summary == "" || r.Verdict == DriftNone || len(r.When) == 0 {
			t.Errorf("row %q is incomplete: %+v", r.Name, r)
		}
	}
	for _, want := range []string{
		"hardware_id_kept_key_changed", "address_kept_hardware_changed", "mac_kept_os_material_changed",
		"mac_and_address_kept_key_changed", "keys_kept_address_changed", "address_only_key_changed_rest_agrees",
		"address_only_key_changed_rest_changed", "address_only_key_changed_unconfirmed",
	} {
		if !names[want] {
			t.Errorf("row %q is missing from DriftTable", want)
		}
	}
}
