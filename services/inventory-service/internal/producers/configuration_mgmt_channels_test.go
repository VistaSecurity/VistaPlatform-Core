package producers

// foldManagementPlane, the decision behind the asset-subject
// plaintext_management finding (P-08), without a database.
//
// The integration twin (configuration_plaintext_sources_integration_test.go)
// proves the read pairs each answer with its own source's protocol and that the
// lifecycle follows; this file pins the combination rule itself.

import (
	"testing"
	"time"
)

func obsAt(protocol string, plaintext bool, source string, at time.Time) mgmtObservation {
	v := plaintext
	return mgmtObservation{Protocol: protocol, Plaintext: &v, SourceRef: source, ObservedAt: at}
}

func protocolsOf(s []mgmtObservation) []string {
	out := make([]string, 0, len(s))
	for _, o := range s {
		out = append(out, o.Protocol)
	}
	return out
}

func TestFoldManagementPlane(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	expired := func(o mgmtObservation) mgmtObservation { o.Expired = true; return o }

	cases := []struct {
		name          string
		obs           []mgmtObservation
		wantPlaintext []string
		wantAnswered  bool
		wantWithheld  bool
	}{
		{
			name:         "no answers is not assessed",
			wantAnswered: false,
		},
		{
			// P-08 itself: SNMP v2c raised, an HTTPS API run came later.
			name: "a later HTTPS false does not clear SNMP v2c",
			obs: []mgmtObservation{
				obsAt("snmpv2c", true, "interrogation:a", t0),
				obsAt("https", false, "interrogation:b", t1),
			},
			wantPlaintext: []string{"snmpv2c"},
			wantAnswered:  true,
		},
		{
			name: "a later SSH false does not clear SNMP v2c",
			obs: []mgmtObservation{
				obsAt("snmpv2c", true, "interrogation:a", t0),
				obsAt("ssh", false, "interrogation:b", t1),
			},
			wantPlaintext: []string{"snmpv2c"},
			wantAnswered:  true,
		},
		{
			// The Cisco collector's false is positive evidence about telnet.
			name: "the CLI channel's later SSH false retracts its telnet",
			obs: []mgmtObservation{
				obsAt("telnet", true, "interrogation:a", t0),
				obsAt("ssh", false, "interrogation:b", t1),
			},
			wantAnswered: true,
		},
		{
			name: "telnet re-enabled after SSH-only comes back",
			obs: []mgmtObservation{
				obsAt("ssh", false, "interrogation:a", t0),
				obsAt("telnet", true, "interrogation:b", t1),
			},
			wantPlaintext: []string{"telnet"},
			wantAnswered:  true,
		},
		{
			name: "the web channel's later HTTPS false retracts its HTTP",
			obs: []mgmtObservation{
				obsAt("http", true, "interrogation:a", t0),
				obsAt("https", false, "interrogation:b", t1),
			},
			wantAnswered: true,
		},
		{
			// A future SNMPv3 collector says nothing about v2c.
			name: "an SNMPv3 false does not speak for v2c",
			obs: []mgmtObservation{
				obsAt("snmpv2c", true, "interrogation:a", t0),
				obsAt("snmpv3", false, "interrogation:b", t1),
			},
			wantPlaintext: []string{"snmpv2c"},
			wantAnswered:  true,
		},
		{
			name: "two plaintext channels are both named",
			obs: []mgmtObservation{
				obsAt("telnet", true, "interrogation:b", t1),
				obsAt("snmpv2c", true, "interrogation:a", t0),
				obsAt("https", false, "interrogation:c", t2),
			},
			wantPlaintext: []string{"snmpv2c", "telnet"},
			wantAnswered:  true,
		},
		{
			name:         "HTTPS only is an answer and no finding",
			obs:          []mgmtObservation{obsAt("https", false, "interrogation:a", t0)},
			wantAnswered: true,
		},
		{
			// Expired is "stopped knowing": no finding from it, and the asset
			// is withheld from the sweep rather than resolved — even though a
			// current HTTPS answer exists, because that answer is about HTTPS.
			name: "an expired SNMP true beside a current HTTPS false is withheld, not resolved",
			obs: []mgmtObservation{
				expired(obsAt("snmpv2c", true, "interrogation:a", t0)),
				obsAt("https", false, "interrogation:b", t1),
			},
			wantAnswered: true,
			wantWithheld: true,
		},
		{
			name:         "an expired true alone is withheld and not assessed",
			obs:          []mgmtObservation{expired(obsAt("telnet", true, "interrogation:a", t0))},
			wantAnswered: false,
			wantWithheld: true,
		},
		{
			// The newest answer in the channel decides, expired or not: a
			// fresh false after an expired true is a real retraction.
			name: "a current false after an expired true in the same channel resolves",
			obs: []mgmtObservation{
				expired(obsAt("telnet", true, "interrogation:a", t0)),
				obsAt("ssh", false, "interrogation:b", t1),
			},
			wantAnswered: true,
		},
		{
			name: "an unparseable answer is no answer",
			obs: []mgmtObservation{
				{Protocol: "snmpv2c", SourceRef: "interrogation:a", ObservedAt: t0},
			},
			wantAnswered: false,
		},
		{
			name: "a tie at one instant keeps the finding",
			obs: []mgmtObservation{
				obsAt("ssh", false, "interrogation:a", t0),
				obsAt("telnet", true, "interrogation:b", t0),
			},
			wantPlaintext: []string{"telnet"},
			wantAnswered:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := foldManagementPlane(c.obs)
			got := protocolsOf(v.Plaintext)
			if len(got) != len(c.wantPlaintext) {
				t.Fatalf("plaintext channels = %v, want %v", got, c.wantPlaintext)
			}
			for i := range got {
				if got[i] != c.wantPlaintext[i] {
					t.Fatalf("plaintext channels = %v, want %v", got, c.wantPlaintext)
				}
			}
			if v.Answered != c.wantAnswered {
				t.Errorf("Answered = %v, want %v", v.Answered, c.wantAnswered)
			}
			withheld := len(v.Plaintext) == 0 && v.ExpiredPlaintext
			if withheld != c.wantWithheld {
				t.Errorf("withheld = %v, want %v", withheld, c.wantWithheld)
			}
		})
	}
}
