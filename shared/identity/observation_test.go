package identity

import (
	"testing"
	"time"
)

var testTime = time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

// TestSourceProducer pins the mapping the `observation` query target relies on:
// QUERY_LANGUAGE §8 turns the approval-rule condition
// `source: sensor_discoveries` into `source:sensor`, and this is what that
// predicate reads.
func TestSourceProducer(t *testing.T) {
	cases := map[string]string{
		"sensor":          "sensor",
		"sensor:pcap":     "sensor",
		"cloud:aws":       "cloud",
		"cloud:azure":     "cloud",
		"cmdb:servicenow": "cmdb",
		"import:csv":      "import",
		"manual":          "manual",
		"":                "",
		":leading":        "",
		"a:b:c":           "a",
	}
	for ref, want := range cases {
		if got := (Source{Ref: ref}).Producer(); got != want {
			t.Errorf("Source{Ref: %q}.Producer() = %q, want %q", ref, got, want)
		}
	}
}

func TestSourceValid(t *testing.T) {
	if !(Source{Kind: SourceMeasured, Ref: "sensor"}).Valid() {
		t.Error("a measured source with a ref is not valid")
	}
	for _, bad := range []Source{
		{Kind: SourceMeasured, Ref: "   "},
		{Kind: SourceMeasured},
		{Kind: SourceKind("telepathy"), Ref: "x"},
		{Ref: "x"},
		{},
	} {
		if bad.Valid() {
			t.Errorf("%+v reported itself valid; a value with no readable provenance cannot be audited or filtered", bad)
		}
	}
}

func TestSourceKindValid(t *testing.T) {
	for _, k := range []SourceKind{SourceMeasured, SourceDeclared, SourceImported, SourceInferred} {
		if !k.Valid() {
			t.Errorf("%s.Valid() = false", k)
		}
	}
	for _, bad := range []SourceKind{"", "unknown", "Measured", "system"} {
		if bad.Valid() {
			t.Errorf("%q reported itself a valid source kind; there is no fifth kind and 'unknown' is deliberately not one", bad)
		}
	}
}

func TestNetworkIsExternal(t *testing.T) {
	// ADR-0002 D1 says "external" and the live classifier says "third_party".
	// Both must mean outside, or half the discoveries land in the wrong class.
	for _, outside := range []string{OwnershipExternal, OwnershipThirdParty} {
		if !(Network{Ownership: outside}).IsExternal() {
			t.Errorf("ownership %q is not treated as outside the tenant's space", outside)
		}
	}
	for _, inside := range []string{OwnershipInternal, OwnershipUnknown, "", "corporate"} {
		if (Network{Ownership: inside}).IsExternal() {
			t.Errorf("ownership %q was treated as external; an unregistered internal subnet is still the tenant's", inside)
		}
	}
}

func TestAssetRefZero(t *testing.T) {
	if !(AssetRef{}).Zero() {
		t.Error("the zero AssetRef does not report itself zero")
	}
	if !(AssetRef{TenantID: "t"}).Zero() {
		t.Error("a ref with a tenant but no id names no asset and must report zero")
	}
	if (AssetRef{TenantID: "t", ID: "a"}).Zero() {
		t.Error("a populated ref reported itself zero")
	}
}

func TestSanitizeKeepsTheGoodAndReportsTheBad(t *testing.T) {
	o := Observation{
		TenantID: "t",
		Identifiers: []Identifier{
			{Kind: KindSerialNumber, Value: " SN-1 "},
			{Kind: KindMACAddress, Value: "nope"},
			{Kind: KindFQDN, Value: "Host.Example.COM."},
			{Kind: Kind("badge"), Value: "7"},
		},
	}
	clean, rejected := o.Sanitize()

	if len(clean.Identifiers) != 2 {
		t.Fatalf("kept %+v, want the serial and the fqdn", clean.Identifiers)
	}
	if clean.Identifiers[0].Value != "SN-1" || clean.Identifiers[1].Value != "host.example.com" {
		t.Errorf("kept identifiers are not normalised: %+v", clean.Identifiers)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected %+v, want the bad MAC and the unknown kind", rejected)
	}
	for _, r := range rejected {
		if r.Err == nil {
			t.Errorf("rejected identifier %+v carries no reason", r.Identifier)
		}
	}
	// The original is untouched: Sanitize returns a copy.
	if len(o.Identifiers) != 4 {
		t.Errorf("Sanitize mutated its receiver: %+v", o.Identifiers)
	}
}

func TestDedupeIdentifiersKeepsTheHighestConfidence(t *testing.T) {
	got := dedupeIdentifiers([]Identifier{
		{Kind: KindSerialNumber, Value: "SN-1", Confidence: 0.4},
		{Kind: KindSerialNumber, Value: "SN-1", Confidence: 0.9},
		{Kind: KindSerialNumber, Value: "SN-1", Scope: "profile-1", Confidence: 0.5},
	})
	if len(got) != 2 {
		t.Fatalf("dedupe = %+v, want two: the scoped one is a different identifier", got)
	}
	if got[0].Confidence != 0.9 {
		t.Errorf("dedupe kept confidence %v, want the higher 0.9", got[0].Confidence)
	}
}

func TestDisplayNameFallbacks(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		ids  []Identifier
		want string
	}{
		{
			name: "an explicit display name wins when it is at least as good",
			obs:  Observation{DisplayName: "db-1.example.com", Hostname: "db-1"},
			ids:  []Identifier{{Kind: KindHostname, Value: "db-1"}},
			want: "db-1.example.com",
		},
		{
			name: "a better measured name beats a synthetic display name",
			obs:  Observation{DisplayName: "4c6e0a87d480.local", Hostname: "linux-2"},
			want: "linux-2",
		},
		{
			name: "a canonical FQDN beats a short hostname",
			obs:  Observation{Hostname: "db-1"},
			ids:  []Identifier{{Kind: KindFQDN, Value: "db-1.example.com"}},
			want: "db-1.example.com",
		},
		{
			name: "then an fqdn before an ip",
			ids:  []Identifier{{Kind: KindIPAddress, Value: "192.0.2.1"}, {Kind: KindFQDN, Value: "db-1.example.com"}},
			want: "db-1.example.com",
		},
		{
			name: "then an endpoint",
			obs:  Observation{Endpoints: []EndpointObservation{{Address: "192.0.2.9", Port: 443}}},
			want: "192.0.2.9",
		},
		{
			name: "and never a blank",
			want: "unidentified",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := displayNameFor(tc.obs, tc.ids); got != tc.want {
				t.Errorf("displayNameFor = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStampEndpointsDropsAddresslessAndDeduplicates(t *testing.T) {
	src := Source{Kind: SourceMeasured, Ref: "sensor"}
	got := stampEndpoints([]EndpointObservation{
		{Address: "192.0.2.1", Port: 443, Transport: "tcp"},
		{Address: "192.0.2.1", Port: 443, Transport: "tcp"}, // duplicate
		{Port: 443, Transport: "tcp"},                       // no address, no fqdn
		{FQDN: "api.example.com"},                           // at rest
	}, src, testTime)

	if len(got) != 2 {
		t.Fatalf("stamped %+v, want two endpoints", got)
	}
	if got[1].Transport != "none" {
		t.Errorf("an endpoint with no transport was stamped %q, want 'none'", got[1].Transport)
	}
	for _, ep := range got {
		if ep.Source.Ref != "sensor" || ep.SeenAt.IsZero() {
			t.Errorf("endpoint %+v was not stamped with provenance", ep)
		}
	}
}
