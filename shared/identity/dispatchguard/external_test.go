package dispatchguard

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Explicit external targets ( W5.13b). Addresses: RFC 5737 / RFC 3849
// documentation space is itself RESERVED by this guard (refused on every path),
// so it is what the "always refused" cases use. A PUBLIC address the guard
// must accept cannot come from a documentation range for exactly that reason;
// those cases use example.com's historical allocation (93.184.216.0/24,
// 2606:2800:21f::/48), the same block targets_test.go already uses for "an
// arbitrary public host". Names are example.com names, resolved by a stub.

var (
	onPolicy       = ExternalPolicy{Enabled: true, MaxAddresses: DefaultExternalTargetAddresses}
	offPolicy      = ExternalPolicy{Enabled: false, MaxAddresses: DefaultExternalTargetAddresses}
	personConfirms = ManualOptions{Policy: onPolicy, Confirmed: true, PersonInitiated: true}
	personAsks     = ManualOptions{Policy: onPolicy, Confirmed: false, PersonInitiated: true}
)

// stubResolver answers from a map, so rebinding can be staged by editing it.
type stubResolver map[string][]string

func (r stubResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range r[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

// manual parses and resolves raw targets exactly as the dispatch API does.
func manual(t *testing.T, r stubResolver, raws ...string) []ResolvedTarget {
	t.Helper()
	parsed := make([]ManualTarget, 0, len(raws))
	for _, raw := range raws {
		p, err := ParseManualTarget(raw)
		if err != nil {
			t.Fatalf("ParseManualTarget(%q): %v", raw, err)
		}
		parsed = append(parsed, p)
	}
	resolved, err := ResolveManualTargets(context.Background(), r, parsed)
	if err != nil {
		t.Fatalf("ResolveManualTargets(%v): %v", raws, err)
	}
	return resolved
}

func externalNames(ext []ExternalTarget) []string {
	out := make([]string, 0, len(ext))
	for _, e := range ext {
		out = append(out, e.Target)
	}
	sort.Strings(out)
	return out
}

func TestParseManualTarget(t *testing.T) {
	for _, tc := range []struct {
		in         string
		input      string
		host, port string
	}{
		{in: "93.184.216.34", input: "93.184.216.34"},
		{in: " 93.184.216.0/24 ", input: "93.184.216.0/24"},
		{in: "93.184.216.10-93.184.216.20", input: "93.184.216.10-93.184.216.20"},
		{in: "fd00::1", input: "fd00::1"},
		{in: "::ffff:93.184.216.34", input: "93.184.216.34"},
		{in: "www.example.com", input: "www.example.com", host: "www.example.com"},
		{in: "WWW.Example.COM.", input: "www.example.com", host: "www.example.com"},
		{in: "https://www.example.com/login?next=/", input: "www.example.com", host: "www.example.com"},
		{in: "https://www.example.com:8443/", input: "www.example.com", host: "www.example.com", port: "8443"},
		{in: "www.example.com:8443", input: "www.example.com", host: "www.example.com", port: "8443"},
		{in: "https://[2606:2800:21f:cb07::1]:443/", input: "2606:2800:21f:cb07::1", port: "443"},
		{in: "http://93.184.216.34", input: "93.184.216.34"},
	} {
		got, err := ParseManualTarget(tc.in)
		if err != nil {
			t.Errorf("ParseManualTarget(%q) = %v, want accepted", tc.in, err)
			continue
		}
		wantPort := 0
		if tc.port != "" {
			for _, ch := range tc.port {
				wantPort = wantPort*10 + int(ch-'0')
			}
		}
		if got.Input != tc.input || got.Host != tc.host || got.Port != wantPort {
			t.Errorf("ParseManualTarget(%q) = {Input:%q Host:%q Port:%d}, want {Input:%q Host:%q Port:%d}",
				tc.in, got.Input, got.Host, got.Port, tc.input, tc.host, wantPort)
		}
	}
	for _, bad := range []string{
		"", "   ", "exa mple.com", "-bad.example.com", "bad-.example.com", "under_score.example.com",
		"https://", "https://www.example.com:99999/", "www.example.com:0", "example.com/path",
		"fe80::1%eth0", strings.Repeat("a", 64) + ".example.com",
	} {
		if _, err := ParseManualTarget(bad); err == nil {
			t.Errorf("ParseManualTarget(%q) accepted, want refused", bad)
		}
	}
}

// TestAuthorizeManual_PublicTargetsWithConfirmation — the Q10 polarity: every
// form a person can name outside the registered networks scans once confirmed,
// and the confirmed set is exactly what the audit event will record.
func TestAuthorizeManual_PublicTargetsWithConfirmation(t *testing.T) {
	s := scope([]string{"203.0.114.0/24"}, nil)
	r := stubResolver{"www.example.com": {"93.184.216.34", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"}}
	targets := manual(t, r,
		"93.184.216.34",               // public IP
		"93.184.216.0/24",             // public block
		"93.184.216.10-93.184.216.20", // public range
		"https://www.example.com/",    // URL
		"2606:2800:21f:cb07::/116",    // IPv6 block at the bound
		"10.0.0.5",                    // private: in scope, not external
		"203.0.114.9",                 // registered public segment: in scope, not external
	)
	ext, err := s.AuthorizeManual(targets, personConfirms)
	if err != nil {
		t.Fatalf("confirmed external targets refused: %v", err)
	}
	want := []string{"2606:2800:21f:cb07::/116", "93.184.216.0/24", "93.184.216.10-93.184.216.20", "93.184.216.34", "https://www.example.com/"}
	if got := externalNames(ext); !reflect.DeepEqual(got, want) {
		t.Fatalf("external = %v, want %v", got, want)
	}
	for _, e := range ext {
		if e.Target == "https://www.example.com/" {
			if !reflect.DeepEqual(e.Addresses, []string{"93.184.216.34", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"}) {
				t.Fatalf("hostname audit addresses = %v, want both resolved addresses", e.Addresses)
			}
		}
	}
}

// TestAuthorizeManual_UnconfirmedListsTheExternalTargets — without the flag the
// request is refused and the refusal NAMES the external targets, so a UI can
// ask and a script cannot scan a third party by accident.
func TestAuthorizeManual_UnconfirmedListsTheExternalTargets(t *testing.T) {
	s := scope(nil, nil)
	r := stubResolver{"www.example.com": {"93.184.216.34"}, "intranet.example.com": {"10.1.2.3"}}
	_, err := s.AuthorizeManual(manual(t, r, "10.0.0.5", "93.184.216.34", "www.example.com", "intranet.example.com"), personAsks)
	ext, ok := IsExternalTargetsError(err)
	if !ok {
		t.Fatalf("err = %v, want ExternalTargetsError", err)
	}
	if ext.Code != CodeExternalTargetsUnconfirmed {
		t.Fatalf("code = %q, want %q", ext.Code, CodeExternalTargetsUnconfirmed)
	}
	if got, want := externalNames(ext.Targets), []string{"93.184.216.34", "www.example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listed = %v, want %v (internal targets must not be listed)", got, want)
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatal("unconfirmed external targets must still be ErrDenied")
	}
	// And a request with nothing external needs no confirmation at all.
	if _, err := s.AuthorizeManual(manual(t, r, "10.0.0.5", "intranet.example.com"), personAsks); err != nil {
		t.Fatalf("internal-only request refused: %v", err)
	}
}

// TestAuthorizeManual_SizeBound — external blocks are bounded; private and
// registered ones are not (today's behaviour).
func TestAuthorizeManual_SizeBound(t *testing.T) {
	s := scope([]string{"93.186.0.0/16"}, nil) // a registered public segment far over the bound
	for _, tc := range []struct {
		target string
		policy ExternalPolicy
		ok     bool
	}{
		{"93.184.208.0/20", onPolicy, true},             // 4096, the default bound
		{"93.184.192.0/19", onPolicy, false},            // 8192
		{"93.184.216.0-93.184.232.0", onPolicy, false},  // 4097
		{"93.184.216.0-93.184.231.255", onPolicy, true}, // 4096 as a range
		{"2606:2800:21f:cb07::/116", onPolicy, true},    // 4096
		{"2606:2800:21f:cb07::/115", onPolicy, false},   // 8192
		{"2606:2800::/32", onPolicy, false},             // 2^96: saturates, still refused
		{"::/0", onPolicy, false},                       // everything
		{"93.184.216.0/24", ExternalPolicy{Enabled: true, MaxAddresses: 256}, true},
		{"93.184.216.0/23", ExternalPolicy{Enabled: true, MaxAddresses: 256}, false},
		{"10.0.0.0/8", onPolicy, true},    // private: unbounded as today
		{"93.186.0.0/16", onPolicy, true}, // registered segment: unbounded as today
	} {
		opts := personConfirms
		opts.Policy = tc.policy
		_, err := s.AuthorizeManual(manual(t, nil, tc.target), opts)
		if (err == nil) != tc.ok {
			t.Errorf("AuthorizeManual(%q, max=%d) err = %v, want ok=%v", tc.target, tc.policy.MaxAddresses, err, tc.ok)
			continue
		}
		if !tc.ok {
			if _, refused := IsRefusedTargetsError(err); !refused {
				t.Errorf("%q over the bound: err = %v, want RefusedTargetsError", tc.target, err)
			}
		}
	}
}

// TestAuthorizeManual_ReservedRefusedEvenWhenConfirmed is the SSRF half:
// consent from a tenant user is not consent from the platform. Every class, by
// literal and by a name that resolves to it, confirmed and all.
func TestAuthorizeManual_ReservedRefusedEvenWhenConfirmed(t *testing.T) {
	s := scope(nil, []string{"10.43.0.0/16"}) // the cluster's Service CIDR, as an operator names it
	r := stubResolver{
		"metadata.example.com": {"169.254.169.254"},
		"loop.example.com":     {"127.0.0.1"},
		"mixed.example.com":    {"93.184.216.34", "127.0.0.1"}, // one bad answer taints the name
		"v6loop.example.com":   {"93.184.216.34", "::1"},
		"cluster.example.com":  {"10.43.0.10"},
		"mapped.example.com":   {"::ffff:169.254.169.254"},
	}
	for name, target := range map[string]string{
		"loopback":               "127.0.0.1",
		"cloud metadata":         "169.254.169.254",
		"link-local block":       "169.254.0.0/16",
		"loopback v6":            "::1",
		"link-local v6":          "fe80::1",
		"carrier-grade NAT":      "100.64.0.1",
		"documentation":          "192.0.2.10",
		"documentation v6":       "2001:db8::1",
		"multicast":              "224.0.0.1",
		"unspecified":            "0.0.0.0",
		"broadcast":              "255.255.255.255",
		"NAT64":                  "64:ff9b::a9fe:a9fe",
		"mapped address":         "::ffff:169.254.169.254",
		"mapped CIDR":            "::ffff:169.254.169.0/120",
		"range across mapped":    "::fffe:ffff:ffff-::1:0:0:0",
		"cluster CIDR address":   "10.43.0.1",
		"range into metadata":    "169.254.169.250-169.254.169.255",
		"name → metadata":        "metadata.example.com",
		"URL → metadata":         "http://metadata.example.com/latest/meta-data/",
		"name → loopback":        "loop.example.com",
		"name → public+loopback": "mixed.example.com",
		"name → public+v6 loop":  "v6loop.example.com",
		"name → cluster CIDR":    "cluster.example.com",
		"name → mapped metadata": "mapped.example.com",
	} {
		_, err := s.AuthorizeManual(manual(t, r, target), personConfirms)
		refused, ok := IsRefusedTargetsError(err)
		if !ok {
			t.Errorf("%s: AuthorizeManual(%q) confirmed = %v, want RefusedTargetsError", name, target, err)
			continue
		}
		if len(refused.Targets) != 1 || refused.Targets[0].Reason == "" {
			t.Errorf("%s: refusal %+v does not name the target with a reason", name, refused.Targets)
		}
	}
}

// TestAuthorizeManual_RefusalListsEveryRefusedTarget — a person fixes the whole
// list at once, and refusal outranks the confirmation question.
func TestAuthorizeManual_RefusalListsEveryRefusedTarget(t *testing.T) {
	s := scope(nil, nil)
	_, err := s.AuthorizeManual(manual(t, nil, "127.0.0.1", "93.184.216.34", "169.254.169.254"), personAsks)
	refused, ok := IsRefusedTargetsError(err)
	if !ok {
		t.Fatalf("err = %v, want RefusedTargetsError", err)
	}
	var got []string
	for _, r := range refused.Targets {
		got = append(got, r.Target)
	}
	if !reflect.DeepEqual(got, []string{"127.0.0.1", "169.254.169.254"}) {
		t.Fatalf("refused = %v, want both reserved targets", got)
	}
	if !strings.Contains(refused.Targets[1].Reason, "metadata") {
		t.Errorf("metadata refusal reason = %q, want it to say why", refused.Targets[1].Reason)
	}
}

// TestAuthorizeManual_NotPersonInitiatedNeverScansPublic — the automatic,
// identity and service-to-service paths: the flag is not theirs to give.
func TestAuthorizeManual_NotPersonInitiatedNeverScansPublic(t *testing.T) {
	s := scope([]string{"203.0.114.0/24"}, nil)
	opts := ManualOptions{Policy: onPolicy, Confirmed: true, PersonInitiated: false}
	for _, target := range []string{"93.184.216.34", "93.184.216.0/28", "www.example.com"} {
		_, err := s.AuthorizeManual(manual(t, stubResolver{"www.example.com": {"93.184.216.34"}}, target), opts)
		refused, ok := IsRefusedTargetsError(err)
		if !ok || !strings.Contains(refused.Targets[0].Reason, "outside the network segments") {
			t.Errorf("unattended %q with the flag = %v, want refused as outside the registered networks", target, err)
		}
	}
	if _, err := s.AuthorizeManual(manual(t, nil, "10.0.0.5", "203.0.114.9"), opts); err != nil {
		t.Fatalf("unattended in-scope targets refused: %v", err)
	}
}

// TestAuthorizeManual_SwitchOffIsTodaysBehaviour: with the operator switch off,
// AuthorizeManual agrees with the pre-existing Authorize on every literal,
// confirmed or not — the differential is the proof "off" changed nothing.
func TestAuthorizeManual_SwitchOffIsTodaysBehaviour(t *testing.T) {
	s := scope([]string{"203.0.114.0/24"}, []string{"10.99.0.0/16"})
	for _, target := range []string{
		"10.0.0.5", "192.168.1.0/24", "172.16.4.1-172.16.4.9", "fd00::1", "203.0.114.7",
		"93.184.216.34", "93.184.216.0/24", "2606:2800:21f:cb07::1", "127.0.0.1", "169.254.169.254",
		"10.99.1.1", "10.98.255.250-10.99.0.5", "100.64.0.1",
	} {
		for _, confirmed := range []bool{false, true} {
			before := s.Authorize(target) == nil
			_, err := s.AuthorizeManual(manual(t, nil, target), ManualOptions{Policy: offPolicy, Confirmed: confirmed, PersonInitiated: true})
			if after := err == nil; after != before {
				t.Errorf("switch off, confirmed=%v: %q allowed=%v, today allowed=%v", confirmed, target, after, before)
			}
			if !before && err != nil {
				if ext, ok := IsExternalTargetsError(err); ok && ext.Code != CodeExternalTargetsDisabled {
					t.Errorf("switch off: %q code = %q, want %q", target, ext.Code, CodeExternalTargetsDisabled)
				}
			}
		}
	}
}

// TestAuthorizeDispatch_ConsentCoversOnlyWhatWasConfirmed is the processor's
// re-check over expanded addresses ( W5.13b review, item 5): consent is
// the confirmed ranges and addresses, not the whole job.
func TestAuthorizeDispatch_ConsentCoversOnlyWhatWasConfirmed(t *testing.T) {
	s := scope(nil, nil)
	confirmed := []string{"93.184.216.0/28", "93.184.217.9"}
	for _, ok := range []string{"93.184.216.1", "93.184.216.15", "93.184.217.9", "10.0.0.5"} {
		if err := s.AuthorizeDispatch([]string{ok}, DispatchConsent{Ranges: confirmed, TotalAddresses: 17}, onPolicy); err != nil {
			t.Errorf("%s: confirmed or in-scope address refused at dispatch: %v", ok, err)
		}
	}
	for _, outside := range []string{"93.184.216.16", "93.184.217.10", "2606:2800:21f:cb07::1"} {
		if err := s.AuthorizeDispatch([]string{outside}, DispatchConsent{Ranges: confirmed, TotalAddresses: 17}, onPolicy); err == nil {
			t.Errorf("%s: a public address nobody confirmed passed because the JOB had consent", outside)
		}
	}
	if err := s.AuthorizeDispatch([]string{"93.184.216.1"}, DispatchConsent{}, onPolicy); err == nil {
		t.Fatal("unconfirmed job scanned a public address")
	}
	err := s.AuthorizeDispatch([]string{"93.184.216.1"}, DispatchConsent{Ranges: confirmed, TotalAddresses: 17}, offPolicy)
	if ext, ok := IsExternalTargetsError(err); !ok || ext.Code != CodeExternalTargetsDisabled {
		t.Fatalf("operator switch turned off after queueing: err=%v, want external_targets_disabled", err)
	}
	if err := s.AuthorizeDispatch([]string{"93.184.216.1", "169.254.169.254"}, DispatchConsent{Ranges: append(confirmed, "169.254.169.254"), TotalAddresses: 18}, onPolicy); err == nil {
		t.Fatal("confirmed job reached the metadata address at dispatch")
	}
	// A registered segment withdrawn after creation: the address is now
	// external and was never itself confirmed.
	registered := scope([]string{"93.185.0.0/24"}, nil)
	if err := registered.AuthorizeDispatch([]string{"93.185.0.9"}, DispatchConsent{Ranges: confirmed, TotalAddresses: 17}, onPolicy); err != nil {
		t.Fatalf("registered address refused: %v", err)
	}
	if err := s.AuthorizeDispatch([]string{"93.185.0.9"}, DispatchConsent{Ranges: confirmed, TotalAddresses: 17}, onPolicy); err == nil {
		t.Fatal("an address whose segment was withdrawn rode on the job's consent for other targets")
	}
}

func TestResolvedTarget_ScanAddressesArePinnedAndPreferIPv4(t *testing.T) {
	r := stubResolver{"www.example.com": {"2606:2800:21f:cb07::1", "93.184.216.34", "::ffff:93.184.216.35"}, "v6.example.com": {"2606:2800:21f:cb07::1"}}
	got := manual(t, r, "www.example.com", "v6.example.com", "93.184.216.0/30")
	if want := []string{"93.184.216.34", "93.184.216.35"}; !reflect.DeepEqual(got[0].ScanAddresses(), want) {
		t.Errorf("ScanAddresses = %v, want %v (IPv4 preferred, mapped unmapped)", got[0].ScanAddresses(), want)
	}
	if want := []string{"2606:2800:21f:cb07::1"}; !reflect.DeepEqual(got[1].ScanAddresses(), want) {
		t.Errorf("v6-only ScanAddresses = %v, want %v", got[1].ScanAddresses(), want)
	}
	if got[2].ScanAddresses() != nil {
		t.Errorf("literal target pinned %v, want nil", got[2].ScanAddresses())
	}
	if _, err := ResolveManualTargets(context.Background(), r, []ManualTarget{{Entered: "nx.example.com", Input: "nx.example.com", Host: "nx.example.com"}}); err == nil {
		t.Error("an unresolvable name was accepted")
	}
}

// TestParseAndResolve_ListEveryBadEntry — a request with several bad entries
// names all of them, so the person fixes the list once.
func TestParseAndResolve_ListEveryBadEntry(t *testing.T) {
	_, err := ParseManualTargets([]string{"93.184.216.34", "exa mple.com", "https://www.example.com:0/", "10.0.0.1"})
	refused, ok := IsRefusedTargetsError(err)
	if !ok || len(refused.Targets) != 2 {
		t.Fatalf("ParseManualTargets err = %v, want both bad entries listed", err)
	}
	parsed, err := ParseManualTargets([]string{"nx1.example.com", "www.example.com", "nx2.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ResolveManualTargets(context.Background(), stubResolver{"www.example.com": {"93.184.216.34"}}, parsed)
	refused, ok = IsRefusedTargetsError(err)
	if !ok || len(refused.Targets) != 2 || refused.Targets[0].Target != "nx1.example.com" || refused.Targets[1].Target != "nx2.example.com" {
		t.Fatalf("ResolveManualTargets err = %v, want both unresolvable names listed", err)
	}
}

// TestExternalPolicyFromEnv: the switch is a strict boolean and fails CLOSED
// ( W5.13b review, item 3) — unset, unrecognised, 0/no/off all mean off.
func TestExternalPolicyFromEnv(t *testing.T) {
	on := func(max, job uint64) ExternalPolicy {
		return ExternalPolicy{Enabled: true, MaxAddresses: max, MaxJobAddresses: job}
	}
	off := func(max, job uint64) ExternalPolicy {
		return ExternalPolicy{Enabled: false, MaxAddresses: max, MaxJobAddresses: job}
	}
	for _, tc := range []struct {
		enabled, max, job string
		want              ExternalPolicy
	}{
		{"", "", "", off(4096, 16384)}, // unset: something dropped the switch
		{"true", "", "", on(4096, 16384)},
		{" TRUE ", "", "", on(4096, 16384)},
		{"1", "", "", on(4096, 16384)},
		{"yes", "", "", on(4096, 16384)},
		{"on", "", "", on(4096, 16384)},
		{"false", "", "", off(4096, 16384)},
		{"0", "", "", off(4096, 16384)},
		{"no", "", "", off(4096, 16384)},
		{"off", "", "", off(4096, 16384)},
		{"enabled", "", "", off(4096, 16384)}, // unrecognised: off
		{"ture", "", "", off(4096, 16384)},
		{"true", "256", "", on(256, 16384)},
		{"true", "1", "", on(1, 16384)},
		{"true", "0", "", on(4096, 16384)},
		{"true", "4097", "", on(4096, 16384)},
		{"true", "lots", "", on(4096, 16384)},
		{"true", "", "1000", on(4096, 1000)},
		{"true", "", "16385", on(4096, 16384)}, // lowered, never raised
		{"true", "", "0", on(4096, 16384)},
	} {
		t.Setenv(EnvExternalTargetsEnabled, tc.enabled)
		t.Setenv(EnvExternalTargetMaxAddresses, tc.max)
		t.Setenv(EnvExternalJobMaxAddresses, tc.job)
		if got := ExternalPolicyFromEnv(); got != tc.want {
			t.Errorf("env(enabled=%q, max=%q, job=%q) = %+v, want %+v", tc.enabled, tc.max, tc.job, got, tc.want)
		}
	}
}

// TestAuthorizeManual_JobTotalBound ( W5.13b review, item 4): each target
// under the per-target bound, the job over the total.
func TestAuthorizeManual_JobTotalBound(t *testing.T) {
	s := scope(nil, nil)
	blocks := []string{"93.184.208.0/20", "93.184.224.0/20", "93.184.240.0/20", "93.185.0.0/20"} // 4 x 4096 = 16384
	if _, err := s.AuthorizeManual(manual(t, nil, blocks...), personConfirms); err != nil {
		t.Fatalf("exactly the job bound refused: %v", err)
	}
	_, err := s.AuthorizeManual(manual(t, nil, append(blocks, "93.185.16.1")...), personConfirms)
	if refused, ok := IsRefusedTargetsError(err); !ok || !strings.Contains(refused.Targets[0].Reason, "16384") {
		t.Fatalf("one address over the job bound: err=%v, want a refusal naming the bound", err)
	}
	// Names count by the addresses they are pinned to.
	lower := personConfirms
	lower.Policy.MaxJobAddresses = 2
	r := stubResolver{"www.example.com": {"93.184.216.34", "93.184.216.35"}}
	if _, err := s.AuthorizeManual(manual(t, r, "www.example.com"), lower); err != nil {
		t.Fatalf("two pinned addresses under a bound of two refused: %v", err)
	}
	if _, err := s.AuthorizeManual(manual(t, r, "www.example.com", "93.184.217.1"), lower); err == nil {
		t.Fatal("three external addresses passed a job bound of two")
	}
	// In-scope targets do not count.
	if _, err := s.AuthorizeManual(manual(t, nil, "10.0.0.0/8", "93.184.217.1"), lower); err != nil {
		t.Fatalf("private block counted against the external job bound: %v", err)
	}
}

// TestAuthorizeManual_RefusedNameDoesNotEchoItsAddresses ( W5.13b review,
// item 6): the API must not become a resolver for the platform's DNS.
func TestAuthorizeManual_RefusedNameDoesNotEchoItsAddresses(t *testing.T) {
	s := scope(nil, []string{"10.43.0.0/16"})
	r := stubResolver{"cluster.example.com": {"10.43.0.10"}, "metadata.example.com": {"169.254.169.254"}}
	_, err := s.AuthorizeManual(manual(t, r, "cluster.example.com", "metadata.example.com"), personConfirms)
	refused, ok := IsRefusedTargetsError(err)
	if !ok || len(refused.Targets) != 2 {
		t.Fatalf("err = %v, want both names refused", err)
	}
	for _, rt := range refused.Targets {
		if strings.Contains(rt.Reason, "10.43") || strings.Contains(rt.Reason, "169.254") {
			t.Errorf("%s: the refusal leaks what the name resolved to: %q", rt.Target, rt.Reason)
		}
	}
	if strings.Contains(err.Error(), "10.43.0.10") {
		t.Errorf("the error text leaks the resolved address: %v", err)
	}
}

// TestParseManualTarget_PlatformDNSAndBrokenRanges ( W5.13b review,
// items 6 and 7).
func TestParseManualTarget_PlatformDNSAndBrokenRanges(t *testing.T) {
	for _, name := range []string{
		"web01", "localhost", "kubernetes", "kubernetes.default.svc", "vista-postgres.vista.svc",
		"api.vista.svc.cluster.local", "metadata.google.internal", "instance-data.ec2.internal", "anything.localhost",
	} {
		_, err := ParseManualTarget(name)
		if err == nil || !strings.Contains(err.Error(), "own DNS") {
			t.Errorf("ParseManualTarget(%q) = %v, want a refusal naming the platform's DNS", name, err)
		}
	}
	for in, want := range map[string]string{
		"93.184.216.34-93.184.216.1": "ends before it starts",
		"93.184.216.1-2606:2800::1":  "mixes an IPv4 and an IPv6",
	} {
		_, err := ParseManualTarget(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseManualTarget(%q) = %v, want %q", in, err, want)
		}
	}
	// Not over-strict: ordinary multi-label names still parse.
	for _, name := range []string{"www.example.com", "internal.example.com", "svc.example.com", "localhost.example.com"} {
		if _, err := ParseManualTarget(name); err != nil {
			t.Errorf("ParseManualTarget(%q) refused: %v", name, err)
		}
	}
}

// TestEmbeddedIPv4Forms ( W5.13b review, item 1): IPv6 forms that carry
// an IPv4 address are judged by that address, on every path.
func TestEmbeddedIPv4Forms(t *testing.T) {
	s := scope(nil, []string{"10.43.0.0/16"})
	for name, target := range map[string]string{
		"IPv4-compatible metadata":     "::a9fe:a9fe",
		"IPv4-compatible loopback":     "::127.0.0.1",
		"IPv4-compatible block":        "::a9fe:0/112",
		"SIIT translated metadata":     "::ffff:0:a9fe:a9fe",
		"local-use NAT64":              "64:ff9b:1::a9fe:a9fe",
		"well-known NAT64":             "64:ff9b::7f00:1",
		"6to4 of metadata":             "2002:a9fe:a9fe::1",
		"6to4 of loopback":             "2002:7f00:1::",
		"6to4 of the cluster CIDR":     "2002:0a2b:0001::1",
		"6to4 range reaching loopback": "2002:7eff:ffff::-2002:7f00:1::",
		"Teredo client metadata":       "2001:0:5db8:d822:0:0:5601:5601", // client 169.254.169.254, bit-inverted
		"Teredo client loopback":       "2001:0:5db8:d822:0:0:80ff:fffe", // client 127.0.0.1 obfuscated
		"Teredo range":                 "2001:0:5db8:d822::-2001:0:5db8:d822::ff",
	} {
		_, err := s.AuthorizeManual(manual(t, nil, target), personConfirms)
		if _, ok := IsRefusedTargetsError(err); !ok {
			t.Errorf("%s: AuthorizeManual(%q) confirmed = %v, want refused", name, target, err)
		}
		if err := s.Authorize(target); err == nil {
			t.Errorf("%s: Authorize(%q) = nil, want refused on the existing path too", name, target)
		}
	}
	// Public 6to4 / Teredo addresses embedding public IPv4 are external, not refused.
	for _, target := range []string{"2002:5db8:d822::1", "2001:0:5db8:d822:0:0:a247:27de"} {
		if _, err := s.AuthorizeManual(manual(t, nil, target), personConfirms); err != nil {
			t.Errorf("%s: a 6to4/Teredo address carrying a public IPv4 refused: %v", target, err)
		}
	}
}

// TestPlatformFetchGuard: the OCSP-style fetch guard allows public addresses
// only — reserved, platform-excluded, embedded and PRIVATE space refused.
func TestPlatformFetchGuard(t *testing.T) {
	guard := TargetScope{excluded: append(append([]netip.Prefix{}, reservedPrefixes...), netip.MustParsePrefix("10.43.0.0/16"))}.fetchGuard
	for _, bad := range []string{
		"127.0.0.1", "169.254.169.254", "::1", "fe80::1", "0.0.0.0", "100.64.0.1", "224.0.0.1",
		"10.43.0.10", "10.0.0.5", "172.16.0.1", "192.168.1.1", "fd00::1",
		"::ffff:169.254.169.254", "::a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
		"2002:a00:1::", "2002:c0a8:101::1", "2001:0:5db8:d822:0:0:f5ff:fffe", // 6to4 of 10.0.0.1 / 192.168.1.1, Teredo client 10.0.0.1 (review N5)
	} {
		if err := guard(netip.MustParseAddr(bad)); err == nil {
			t.Errorf("fetch guard allowed %s", bad)
		}
	}
	for _, good := range []string{"93.184.216.34", "2606:2800:21f:cb07::1"} {
		if err := guard(netip.MustParseAddr(good)); err != nil {
			t.Errorf("fetch guard refused public %s: %v", good, err)
		}
	}
	// And the exported constructor builds it from the real lists.
	if err := PlatformFetchGuard()(netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Error("PlatformFetchGuard() allowed the metadata address")
	}
	if err := PlatformFetchGuard()(netip.MustParseAddr("93.184.216.34")); err != nil {
		t.Errorf("PlatformFetchGuard() refused a public address: %v", err)
	}
}

// TestAuthorizeDispatch_CurrentBoundsStopQueuedWork (review N2): a job
// confirmed under the old limits is re-judged against the CURRENT ones.
func TestAuthorizeDispatch_CurrentBoundsStopQueuedWork(t *testing.T) {
	s := scope(nil, nil)
	consent := DispatchConsent{Ranges: []string{"93.184.216.0/24"}, TotalAddresses: 256}
	if err := s.AuthorizeDispatch([]string{"93.184.216.1"}, consent, onPolicy); err != nil {
		t.Fatalf("under the default bounds: %v", err)
	}
	lowerJob := onPolicy
	lowerJob.MaxJobAddresses = 255
	if err := s.AuthorizeDispatch([]string{"93.184.216.1"}, consent, lowerJob); err == nil {
		t.Fatal("job bound lowered below the job's total after queueing, still scanned")
	}
	lowerTarget := onPolicy
	lowerTarget.MaxAddresses = 128
	if err := s.AuthorizeDispatch([]string{"93.184.216.1"}, consent, lowerTarget); err == nil {
		t.Fatal("per-target bound lowered below a confirmed /24 after queueing, still scanned")
	}
	// In-scope addresses of the same job are not held back by it.
	if err := s.AuthorizeDispatch([]string{"10.0.0.5"}, consent, lowerJob); err != nil {
		t.Fatalf("a private address in an over-bound job refused: %v", err)
	}
}

// TestExternalAddressTotal counts what AuthorizeManual counted: a literal's
// size, a name's pinned addresses.
func TestExternalAddressTotal(t *testing.T) {
	s := scope(nil, nil)
	r := stubResolver{"www.example.com": {"93.184.216.34", "93.184.216.35", "2606:2800:21f:cb07::1"}}
	ext, err := s.AuthorizeManual(manual(t, r, "93.184.217.0/28", "93.184.218.1", "www.example.com", "10.0.0.0/8"), personConfirms)
	if err != nil {
		t.Fatal(err)
	}
	if got := ExternalAddressTotal(ext); got != 16+1+2 {
		t.Fatalf("total = %d, want 19 (the /28, one address, the name's two pinned IPv4 addresses; private not counted)", got)
	}
}
