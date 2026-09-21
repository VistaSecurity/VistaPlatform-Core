package identity

import (
	"slices"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name    string
		kind    Kind
		in      string
		want    string
		wantErr string // substring; empty means the value must be accepted
	}{
		// Opaque kinds: trimmed, case preserved.
		{name: "agent id trimmed", kind: KindAgentID, in: "  agent-7f3a  ", want: "agent-7f3a"},
		{name: "agent id keeps case", kind: KindAgentID, in: "Agent-7F3A", want: "Agent-7F3A"},
		{name: "cloud resource id as-is", kind: KindCloudResourceID, in: " arn:aws:ec2:us-east-1:1234:instance/i-0AbC ", want: "arn:aws:ec2:us-east-1:1234:instance/i-0AbC"},
		{name: "cmdb sys id as-is", kind: KindCMDBSysID, in: "a1b2C3", want: "a1b2C3"},
		{name: "serial trimmed", kind: KindSerialNumber, in: "\tJ7K2L9\n", want: "J7K2L9"},
		{name: "ssh fingerprint keeps base64 case", kind: KindSSHHostKeyFingerprint, in: "SHA256:aZ0+/bQ", want: "SHA256:aZ0+/bQ"},

		// MAC.
		{name: "mac colon lowercased", kind: KindMACAddress, in: "AA:BB:CC:DD:EE:FF", want: "aa:bb:cc:dd:ee:ff"},
		{name: "mac hyphen form", kind: KindMACAddress, in: "aa-bb-cc-dd-ee-01", want: "aa:bb:cc:dd:ee:01"},
		{name: "mac cisco dotted form", kind: KindMACAddress, in: "aabb.ccdd.ee02", want: "aa:bb:cc:dd:ee:02"},
		{name: "mac bare form", kind: KindMACAddress, in: "aabbccddee03", want: "aa:bb:cc:dd:ee:03"},
		{name: "mac too short", kind: KindMACAddress, in: "aa:bb:cc", wantErr: "6 hex digits, want 12"},
		{name: "mac too long", kind: KindMACAddress, in: "aa:bb:cc:dd:ee:ff:00", wantErr: "14 hex digits, want 12"},
		{name: "mac non-hex", kind: KindMACAddress, in: "gg:bb:cc:dd:ee:ff", wantErr: "not hex"},
		{name: "mac all zero rejected", kind: KindMACAddress, in: "00:00:00:00:00:00", wantErr: "all-zero"},
		{name: "mac broadcast rejected", kind: KindMACAddress, in: "ff:ff:ff:ff:ff:ff", wantErr: "broadcast"},

		// FQDN.
		{name: "fqdn lowercased", kind: KindFQDN, in: "Host.Example.COM", want: "host.example.com"},
		{name: "fqdn trailing dot stripped", kind: KindFQDN, in: "host.example.com.", want: "host.example.com"},
		{name: "fqdn service labels allowed", kind: KindFQDN, in: "_ldap._tcp.example.com", want: "_ldap._tcp.example.com"},
		{name: "fqdn single label rejected", kind: KindFQDN, in: "localhost", wantErr: "single label"},
		{name: "fqdn wildcard rejected", kind: KindFQDN, in: "*.example.com", wantErr: "not valid in a DNS name"},
		{name: "fqdn empty label rejected", kind: KindFQDN, in: "host..example.com", wantErr: "empty label"},
		{name: "fqdn with a space rejected", kind: KindFQDN, in: "host .example.com", wantErr: "not valid in a DNS name"},
		{name: "fqdn over length rejected", kind: KindFQDN, in: strings.Repeat("a", 250) + ".com", wantErr: "over the 253 limit"},

		// Hostname.
		{name: "hostname lowercased", kind: KindHostname, in: " Printer-2 ", want: "printer-2"},
		{name: "hostname single label allowed", kind: KindHostname, in: "printer-2", want: "printer-2"},
		{name: "hostname slash rejected", kind: KindHostname, in: "printer/2", wantErr: "not valid in a DNS name"},

		// IP.
		{name: "ipv4", kind: KindIPAddress, in: " 192.0.2.10 ", want: "192.0.2.10"},
		{name: "ipv6 canonicalised", kind: KindIPAddress, in: "2001:0DB8:0000:0000:0000:0000:0000:0001", want: "2001:db8::1"},
		{name: "ipv4 in ipv6 unmapped", kind: KindIPAddress, in: "::ffff:192.0.2.10", want: "192.0.2.10"},
		{name: "ipv6 zone dropped", kind: KindIPAddress, in: "fe80::1%eth0", want: "fe80::1"},
		{name: "ip unspecified rejected", kind: KindIPAddress, in: "0.0.0.0", wantErr: "unspecified"},
		{name: "ip v6 unspecified rejected", kind: KindIPAddress, in: "::", wantErr: "unspecified"},
		{name: "ip garbage rejected", kind: KindIPAddress, in: "192.0.2.999", wantErr: "not an IP address"},
		{name: "ip with a port rejected", kind: KindIPAddress, in: "192.0.2.10:443", wantErr: "not an IP address"},

		// Universal rejections.
		{name: "empty rejected", kind: KindSerialNumber, in: "", wantErr: "value is empty"},
		{name: "whitespace only rejected", kind: KindSerialNumber, in: "   \t ", wantErr: "value is empty"},
		{name: "control character rejected", kind: KindSerialNumber, in: "SN\x001", wantErr: "control character"},
		{name: "unknown kind rejected", kind: Kind("badge_number"), in: "1234", wantErr: "unknown identifier kind"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.kind, tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Normalize(%s, %q) = %q, want an error containing %q", tc.kind, tc.in, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Normalize(%s, %q) error = %v, want it to contain %q", tc.kind, tc.in, err, tc.wantErr)
				}
				if got != "" {
					t.Errorf("a rejected value returned %q, want the empty string", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%s, %q): %v", tc.kind, tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%s, %q) = %q, want %q", tc.kind, tc.in, got, tc.want)
			}
			// Idempotence: normalising a normalised value changes nothing.
			again, err := Normalize(tc.kind, got)
			if err != nil {
				t.Fatalf("Normalize is not idempotent: second pass on %q failed: %v", got, err)
			}
			if again != got {
				t.Errorf("Normalize is not idempotent: %q → %q", got, again)
			}
		})
	}
}

func TestKindValid(t *testing.T) {
	for _, k := range DefaultPrecedenceList() {
		if !k.Valid() {
			t.Errorf("%s is in the default precedence but Valid() says no", k)
		}
	}
	for _, bad := range []Kind{"", "Agent_ID", "badge_number", "ip"} {
		if bad.Valid() {
			t.Errorf("%q is not an identifier kind but Valid() says it is", bad)
		}
	}
}

// TestKindRegistryAgreesWithAssetClass pins this package's kind vocabulary to
// the generated class registry's. They are two spellings of one list
// (ADR-0002 D3) and a drift between them would silently drop a kind from every
// precedence walk — KindsFromStrings discards what it does not recognise.
func TestKindRegistryAgreesWithAssetClass(t *testing.T) {
	want := assetclass.IdentifierKinds
	// AllKinds, not DefaultPrecedenceList: `name` is a valid kind that is NOT
	// in the default precedence order, and the registry carries the whole
	// vocabulary. Comparing against the default order here would fail on a kind
	// that is correctly absent from it.
	got := AllKinds()
	if len(got) != len(want) {
		t.Fatalf("identity has %d kinds, assetclass has %d: %v vs %v", len(got), len(want), got, want)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("kind %d: identity has %q, assetclass has %q — the default precedence orders must match", i, got[i], want[i])
		}
	}

	// And every class's precedence must be expressible: nothing dropped.
	for _, c := range assetclass.All {
		converted := KindsFromStrings(c.IdentifierPrecedence)
		if len(converted) != len(c.IdentifierPrecedence) {
			t.Errorf("class %s: %d of %d precedence kinds are unknown to identity (%v)",
				c.Key, len(c.IdentifierPrecedence)-len(converted), len(c.IdentifierPrecedence), c.IdentifierPrecedence)
		}
	}
}

func TestDefaultPrecedenceListIsACopy(t *testing.T) {
	a := DefaultPrecedenceList()
	a[0] = KindIPAddress
	b := DefaultPrecedenceList()
	if b[0] != KindAgentID {
		t.Fatalf("mutating a returned precedence list corrupted the package default: %v", b)
	}
}

func TestRequiresScope(t *testing.T) {
	scoped := []Kind{KindHostname, KindIPAddress}
	for _, k := range DefaultPrecedenceList() {
		want := slices.Contains(scoped, k)
		if k.RequiresScope() != want {
			t.Errorf("%s.RequiresScope() = %v, want %v", k, k.RequiresScope(), want)
		}
	}
}

func TestClassPrecedence(t *testing.T) {
	t.Run("a cloud class excludes mac_address", func(t *testing.T) {
		got, ok := classPrecedence(assetclass.KeyCloudResource)
		if !ok {
			t.Fatal("cloud_resource is not in the registry")
		}
		if slices.Contains(got, KindMACAddress) {
			t.Errorf("cloud_resource precedence contains mac_address: %v", got)
		}
		if !slices.Contains(got, KindCloudResourceID) {
			t.Errorf("cloud_resource precedence is missing cloud_resource_id: %v", got)
		}
	})
	t.Run("a service class identifies by name and nothing else", func(t *testing.T) {
		// ADR-0002 D3 erratum. It used to be EMPTY — no independent identity at
		// all — which made a service unidentifiable rather than dependently
		// identified: manual create refused one for carrying no identifier.
		got, ok := classPrecedence(assetclass.KeyBusinessService)
		if !ok {
			t.Fatal("business_service is not in the registry")
		}
		if len(got) != 1 || got[0] != KindName {
			t.Errorf("business_service precedence = %v, want [name]", got)
		}
	})
	t.Run("an unknown key is absent, not empty", func(t *testing.T) {
		if _, ok := classPrecedence("dell_poweredge"); ok {
			t.Error("a tenant leaf subclass must not be reported as present in the generated registry")
		}
	})
}

// TestScopeIsRejectedOnAGlobalKind pins the fix for a hole the uniqueness
// invariant had: the scope is part of the unique key, so a scope on a kind
// that has none splits it. One serial number arriving once bare and once
// carrying whatever segment the collector happened to know became two rows,
// two owners and two assets — with no conflict and no merge proposal, because
// the two keys never collided.
//
// Both polarities are pinned here: a scope on a global kind must be rejected,
// AND a scope on each of the three scoped kinds must still be accepted. A
// guard that rejected everything would pass the first half alone.
func TestScopeIsRejectedOnAGlobalKind(t *testing.T) {
	for _, k := range DefaultPrecedenceList() {
		value := map[Kind]string{
			KindSensorID:              "sensor-1",
			KindAgentID:               "agent-1",
			KindCloudResourceID:       "arn:aws:ec2:eu-west-1:1:instance/i-1",
			KindSerialNumber:          "SN-1",
			KindCMDBSysID:             "a1b2c3",
			KindSSHHostKeyFingerprint: "SHA256:aZ0",
			KindMACAddress:            "aa:bb:cc:dd:ee:01",
			KindFQDN:                  "host.example.com",
			KindHostname:              "host",
			KindIPAddress:             "192.0.2.1",
		}[k]

		t.Run(string(k)+"/scoped", func(t *testing.T) {
			got, err := Identifier{Kind: k, Value: value, Scope: " segment-1 "}.Normalized()
			if k.AcceptsScope() {
				if err != nil {
					t.Fatalf("a scope on %s was rejected: %v", k, err)
				}
				if got.Scope != "segment-1" {
					t.Errorf("scope = %q, want it trimmed to %q", got.Scope, "segment-1")
				}
				return
			}
			if err == nil {
				t.Fatalf("a scope on %s was accepted; key %q silently forks the uniqueness index", k, got.Key())
			}
			if !strings.Contains(err.Error(), "scope") {
				t.Errorf("error = %v, want it to name the scope", err)
			}
		})

		t.Run(string(k)+"/unscoped", func(t *testing.T) {
			if _, err := (Identifier{Kind: k, Value: value}.Normalized()); err != nil {
				t.Fatalf("an unscoped %s was rejected: %v", k, err)
			}
		})
	}
}

func TestIdentifierKeyDistinguishesScope(t *testing.T) {
	a := Identifier{Kind: KindHostname, Value: "printer-2", Scope: "segment-1"}
	b := Identifier{Kind: KindHostname, Value: "printer-2", Scope: "segment-2"}
	if a.Key() == b.Key() {
		t.Fatalf("two scopes produced one key: %q", a.Key())
	}
}

// FuzzNormalize checks the three properties that must hold for every input:
// it never panics, an accepted value is idempotent under a second pass, and an
// accepted value never carries surrounding whitespace.
func FuzzNormalize(f *testing.F) {
	seeds := []string{
		"", " ", "host.example.com.", "AA:BB:CC:DD:EE:FF", "192.0.2.1", "::ffff:10.0.0.1",
		"fe80::1%eth0", "aabb.ccdd.eeff", "SHA256:aZ0+/bQ", "arn:aws:ec2:eu-west-1:1:i/i-0a",
		"\x00", "...", "-", strings.Repeat("a", 300), "0.0.0.0", "*.example.com",
	}
	for _, s := range seeds {
		for _, k := range DefaultPrecedenceList() {
			f.Add(string(k), s)
		}
	}
	f.Fuzz(func(t *testing.T, kind, value string) {
		got, err := Normalize(Kind(kind), value)
		if err != nil {
			if got != "" {
				t.Fatalf("Normalize(%q, %q) returned %q alongside error %v", kind, value, got, err)
			}
			return
		}
		if got == "" {
			t.Fatalf("Normalize(%q, %q) accepted the value and returned the empty string", kind, value)
		}
		if strings.TrimSpace(got) != got {
			t.Fatalf("Normalize(%q, %q) = %q, which has surrounding whitespace", kind, value, got)
		}
		again, err := Normalize(Kind(kind), got)
		if err != nil {
			t.Fatalf("Normalize(%q, %q) = %q, which then failed to normalise: %v", kind, value, got, err)
		}
		if again != got {
			t.Fatalf("Normalize(%q) is not idempotent: %q → %q → %q", kind, value, got, again)
		}
	})
}
