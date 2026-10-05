package deviceinterrogation

import "testing"

// Unknown stays unknown ( W1.2): a collector reports a protocol version
// only when it read one. Each test drives the REAL collector — through the
// sanitising Registry wrapper where the collector has a fake appliance — and
// checks both directions: no version where nothing stated one, the stated one
// where something did.

func tlsAssets(result *InterrogateResult) []CryptoAsset {
	var out []CryptoAsset
	for _, a := range result.Assets {
		if a.Protocol == "TLS" {
			out = append(out, a)
		}
	}
	return out
}

func sshAsset(t *testing.T, result *InterrogateResult) CryptoAsset {
	t.Helper()
	for _, a := range result.Assets {
		if a.Protocol == "SSH" {
			return a
		}
	}
	t.Fatalf("no SSH asset in %d assets", len(result.Assets))
	return CryptoAsset{}
}

func versionOf(a CryptoAsset) string {
	if a.ProtocolVersion == nil {
		return "<unmeasured>"
	}
	return *a.ProtocolVersion
}

// The Cisco SSH management row's version is the banner's. `SSH-1.99` is a
// server that still accepts SSH-1 (catalogue risk 78): it used to be written
// as the constant "SSH-2.0" (risk 15).
func TestCiscoSSH_ProtocolVersionComesFromTheBanner(t *testing.T) {
	for _, c := range []struct {
		banner, want string
	}{
		{"SSH-1.99-Cisco-1.25", "SSH-1.99"},
		{"SSH-2.0-Cisco-1.25", "SSH-2.0"},
	} {
		t.Run(c.banner, func(t *testing.T) {
			f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, serverVersion: c.banner,
				outputs: fakeCiscoOutputs(t), userLevelResponses: fakeCiscoUserLevel(t)})
			result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
			if err != nil {
				t.Fatalf("interrogate: %v", err)
			}
			a := sshAsset(t, result)
			if got := versionOf(a); got != c.want {
				t.Errorf("SSH protocol version = %s, want %s (banner %q)", got, c.want, a.SSHInfo.Banner)
			}
		})
	}
}

// With no SSH session there is no banner, and so no version.
func TestCiscoSSHInfo_NoBannerIsNoVersion(t *testing.T) {
	c := &ciscoSSHClient{host: "192.0.2.10", port: 22}
	if a := c.collectSSHInfo(); a.ProtocolVersion != nil {
		t.Errorf("SSH row without a banner has version %q, want unmeasured", *a.ProtocolVersion)
	}
}

// `show webvpn` names no protocol version, and a `show ssl` that lists only
// ciphers names none either: both rows are unmeasured. A `show ssl` that does
// state versions keeps them.
func TestCiscoSSH_TLSRowsCarryOnlyStatedVersions(t *testing.T) {
	outputs := fakeCiscoOutputs(t)
	outputs["show webvpn"] = "WebVPN SSL VPN Server is enabled on interface outside\n"
	outputs["show ssl"] = "Cipher: AES256-SHA\nCipher: AES128-SHA\n"
	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, outputs: outputs, userLevelResponses: fakeCiscoUserLevel(t)})
	result, err := interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	rows := tlsAssets(result)
	if len(rows) != 2 {
		t.Fatalf("want the show ssl and WebVPN rows, got %d TLS assets", len(rows))
	}
	for _, a := range rows {
		if a.ProtocolVersion != nil || len(a.TLSVersions) > 0 {
			t.Errorf("TLS row %v: version %s, versions %v — nothing stated one", a.Metadata, versionOf(a), a.TLSVersions)
		}
	}

	outputs["show ssl"] = "Accept connections using TLSv1.2 or greater and negotiate to TLSv1.2 or greater\nCipher: AES256-SHA\n"
	f = startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, outputs: outputs, userLevelResponses: fakeCiscoUserLevel(t)})
	result, err = interrogateFake(t, f, Credentials{Username: "netops", Password: fakeCiscoPW})
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	measured := 0
	for _, a := range tlsAssets(result) {
		if a.ProtocolVersion != nil {
			measured++
			if *a.ProtocolVersion != "TLS 1.2" {
				t.Errorf("stated version = %q, want TLS 1.2", *a.ProtocolVersion)
			}
		}
	}
	if measured != 1 {
		t.Errorf("%d rows carry a version, want exactly the show ssl row", measured)
	}
}

// A banner naming no version the catalogue carries is not a measurement of
// one.
func TestSSHBannerProtocolVersion(t *testing.T) {
	for banner, want := range map[string]string{
		"SSH-1.99-Cisco-1.25":   "SSH-1.99",
		"SSH-2.0-OpenSSH_9.6\r": "SSH-2.0",
		"":                      "<unmeasured>",
		"SSH-3.0-future":        "<unmeasured>",
		"HTTP/1.1 400":          "<unmeasured>",
	} {
		if got := versionOf(CryptoAsset{ProtocolVersion: sshBannerProtocolVersion(banner)}); got != want {
			t.Errorf("sshBannerProtocolVersion(%q) = %s, want %s", banner, got, want)
		}
	}
}

// F5: BIG-IP states versions through the profile's options, not a version
// field. With no `tlsVersion` the version is unmeasured unless the options
// leave exactly one; what they refuse is recorded either way.
func TestF5VIPVersions_OnlyWhatTheProfileStates(t *testing.T) {
	c := &f5Client{}
	vip := f5VirtualServer{Name: "vs_test", Destination: "/Common/198.51.100.10:443"}
	for _, tc := range []struct {
		name         string
		profile      f5SSLProfile
		wantVersion  string
		wantVersions []string
		wantDisabled []string
	}{
		{name: "no version field, no options", profile: f5SSLProfile{Name: "p"}, wantVersion: "<unmeasured>"},
		{
			name:         "options leave TLS 1.2 and 1.3",
			profile:      f5SSLProfile{Name: "p", Options: []string{"dont-insert-empty-fragments", "no-tlsv1", "no-tlsv1.1", "no-sslv3"}},
			wantVersion:  "<unmeasured>",
			wantDisabled: []string{"SSL 3.0", "TLS 1.0", "TLS 1.1"},
		},
		{
			name:         "default options leave TLS 1.0 possible",
			profile:      f5SSLProfile{Name: "p", Options: []string{"dont-insert-empty-fragments", "no-tlsv1.3"}},
			wantVersion:  "<unmeasured>",
			wantDisabled: []string{"TLS 1.3"},
		},
		{
			name:         "options leave only TLS 1.2",
			profile:      f5SSLProfile{Name: "p", Options: []string{"no-sslv3", "no-tlsv1", "no-tlsv1.1", "no-tlsv1.3"}},
			wantVersion:  "TLS 1.2",
			wantVersions: []string{"TLS 1.2"},
			wantDisabled: []string{"SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.3"},
		},
		{name: "version field stated", profile: f5SSLProfile{Name: "p", TLSVersion: "1.0-1.2"}, wantVersion: "1.0-1.2", wantVersions: []string{"TLS 1.2", "TLS 1.1", "TLS 1.0"}},
		{name: "version field unparseable", profile: f5SSLProfile{Name: "p", TLSVersion: "weird"}, wantVersion: "weird"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := c.convertVIPToAsset(t.Context(), vip, &tc.profile, "198.51.100.10", 443)
			if got := versionOf(a); got != tc.wantVersion {
				t.Errorf("version = %s, want %s", got, tc.wantVersion)
			}
			if !equalStrings(a.TLSVersions, tc.wantVersions) {
				t.Errorf("TLSVersions = %v, want %v", a.TLSVersions, tc.wantVersions)
			}
			got, _ := a.Metadata["tls_versions_disabled"].([]string)
			if !equalStrings(got, tc.wantDisabled) {
				t.Errorf("tls_versions_disabled = %v, want %v", got, tc.wantDisabled)
			}
		})
	}
}

// iControl REST calls the list `tmOptions`; tmsh and some releases send a
// "{ a b }" string. Neither key present is "nothing stated" (nil).
func TestF5ProfileOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		item map[string]interface{}
		want []string
	}{
		{"tmOptions array", map[string]interface{}{"tmOptions": []interface{}{"no-tlsv1", "no-tlsv1.1"}}, []string{"no-tlsv1", "no-tlsv1.1"}},
		{"options array", map[string]interface{}{"options": []interface{}{"no-sslv3"}}, []string{"no-sslv3"}},
		{"tmsh string", map[string]interface{}{"tmOptions": "{ dont-insert-empty-fragments no-tlsv1.3 }"}, []string{"dont-insert-empty-fragments", "no-tlsv1.3"}},
		{"none", map[string]interface{}{"tmOptions": "none"}, []string{}},
		{"absent", map[string]interface{}{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := f5ProfileOptions(tc.item)
			if (got == nil) != (tc.want == nil) || !equalStrings(got, tc.want) {
				t.Errorf("f5ProfileOptions = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// f5ParseTLSVersionRange no longer answers "TLS 1.2" for a value it cannot
// read.
func TestF5ParseTLSVersionRange_NoSafeDefault(t *testing.T) {
	if got := f5ParseTLSVersionRange("unrecognised"); len(got) != 0 {
		t.Errorf("unreadable range = %v, want nothing", got)
	}
	if got := f5ParseTLSVersionRange("1.2-1.3"); !equalStrings(got, []string{"TLS 1.3", "TLS 1.2"}) {
		t.Errorf("1.2-1.3 = %v", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
