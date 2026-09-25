package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// TestF5Interrogate_CipherStringExclusionsAreNotFeatures drives the real
// collector against client-ssl profiles carrying cipher STRINGS (P-05). The
// hardened profile excludes aNULL, RC4, 3DES and MD5; the old collector stored
// the string as the cipher suite and substring-matched MD5 out of "!MD5" as
// the hash, so the VIP scored Critical. No typed crypto field may name an
// excluded algorithm, and nothing may be reported for a string that enables
// no resolvable suite.
func TestF5Interrogate_CipherStringExclusionsAreNotFeatures(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mgmt/shared/authn/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":{"token":"fake-token"}}`))
	})
	mux.HandleFunc("/mgmt/tm/sys/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":{}}`))
	})
	mux.HandleFunc("/mgmt/tm/ltm/virtual", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[
			{"name":"vs-hardened","destination":"/Common/198.51.100.20:443","enabled":true,"profiles":[{"name":"clientssl-hardened"}]},
			{"name":"vs-default","destination":"/Common/198.51.100.21:443","enabled":true,"profiles":[{"name":"clientssl-default"}]},
			{"name":"vs-explicit","destination":"/Common/198.51.100.22:443","enabled":true,"profiles":[{"name":"clientssl-explicit"}]},
			{"name":"vs-group","destination":"/Common/198.51.100.23:443","enabled":true,"profiles":[{"name":"clientssl-group"}]},
			{"name":"vs-mixed","destination":"/Common/198.51.100.24:443","enabled":true,"profiles":[{"name":"clientssl-mixed"}]}
		]}`))
	})
	mux.HandleFunc("/mgmt/tm/ltm/profile/client-ssl", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[
			{"name":"clientssl-hardened","ciphers":"ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5","tlsVersion":"1.2"},
			{"name":"clientssl-default","ciphers":"DEFAULT:!SSLv3:!RC4","tlsVersion":"1.2"},
			{"name":"clientssl-explicit","ciphers":"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!RC4:!3DES:!MD5","tlsVersion":"1.2"},
			{"name":"clientssl-group","ciphers":"none","cipherGroup":"/Common/f5-secure","tlsVersion":"1.2"},
			{"name":"clientssl-mixed","ciphers":"ECDHE-RSA-AES256-GCM-SHA384:DEFAULT:!RC4","tlsVersion":"1.2"}
		]}`))
	})
	mux.HandleFunc("/mgmt/tm/ltm/profile/server-ssl", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	result, err := newF5Client(srv.URL, "admin", "admin", "", true).interrogate(context.Background())
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	byHost := map[string]CryptoAsset{}
	for _, a := range result.Assets {
		byHost[a.Hostname] = a
	}

	// typedCrypto is everything a consumer scores: none of it may name an
	// algorithm the profile excluded. The cipher suite field is read the way
	// every consumer reads it — through the parser, which never counts an
	// excluded token — because an unresolved string travels in it verbatim.
	typedCrypto := func(a CryptoAsset) string {
		parts := append([]string{}, a.SupportedCiphers...)
		for _, p := range []*string{a.HashAlgorithm, a.KeyExchangeAlg} {
			if p != nil {
				parts = append(parts, *p)
			}
		}
		if a.CipherSuite != nil {
			parts = append(parts, cryptoparse.SuitesPossiblyInUse(*a.CipherSuite)...)
		}
		return strings.ToUpper(strings.Join(parts, " "))
	}

	for _, host := range []string{"vs-hardened", "vs-default", "vs-explicit"} {
		a, ok := byHost[host]
		if !ok {
			t.Fatalf("no asset for %s", host)
		}
		got := typedCrypto(a)
		for _, excluded := range []string{"MD5", "RC4", "3DES", "CBC3", "NULL"} {
			if strings.Contains(got, excluded) {
				t.Errorf("%s: excluded %s appears in the typed crypto fields: %q", host, excluded, got)
			}
		}
		if _, ok := a.Metadata["cipher_string"].(string); !ok {
			t.Errorf("%s: the raw cipher string must be kept in metadata", host)
		}
	}

	// Nothing resolves: unknown stays unknown. No suite, hash, key exchange or
	// size is claimed; the unresolved string itself is what travels in the
	// cipher suite field, so inventory can record the row as partially
	// assessed instead of scoring it on its protocol version alone.
	for _, host := range []string{"vs-hardened", "vs-default"} {
		a := byHost[host]
		if a.HashAlgorithm != nil || a.KeyExchangeAlg != nil || a.KeySize != nil || len(a.SupportedCiphers) > 0 {
			t.Errorf("%s: a string that enables no resolvable suite must claim no component, got hash=%v kex=%v size=%v supported=%v",
				host, a.HashAlgorithm, a.KeyExchangeAlg, a.KeySize, a.SupportedCiphers)
		}
		raw, _ := a.Metadata["cipher_string"].(string)
		if a.CipherSuite == nil || *a.CipherSuite != raw {
			t.Errorf("%s: an unresolved string must travel verbatim as the cipher suite, got %v want %q", host, a.CipherSuite, raw)
		}
		if complete, _ := a.Metadata["cipher_string_complete"].(bool); complete {
			t.Errorf("%s: recorded as complete", host)
		}
	}
	// One suite is named, the rest is DEFAULT: that suite is enabled, but no
	// hash, key exchange or key size may be read off it for the whole set.
	mixed := byHost["vs-mixed"]
	if strings.Join(mixed.SupportedCiphers, ",") != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("vs-mixed: supported = %v, want the one named suite", mixed.SupportedCiphers)
	}
	if mixed.HashAlgorithm != nil || mixed.KeyExchangeAlg != nil || mixed.KeySize != nil {
		t.Errorf("vs-mixed: components claimed for a partially known set: hash=%v kex=%v size=%v",
			mixed.HashAlgorithm, mixed.KeyExchangeAlg, mixed.KeySize)
	}
	if mixed.CipherSuite == nil || *mixed.CipherSuite != "ECDHE-RSA-AES256-GCM-SHA384:DEFAULT:!RC4" {
		t.Errorf("vs-mixed: the unresolved string must travel verbatim, got %v", mixed.CipherSuite)
	}

	// A profile that takes its ciphers from a group carries no string at all.
	if g := byHost["vs-group"]; g.CipherSuite != nil || len(g.SupportedCiphers) > 0 {
		t.Errorf("vs-group: cipher fields set from a cipher group: %v / %v", g.CipherSuite, g.SupportedCiphers)
	}
	if un, _ := byHost["vs-hardened"].Metadata["cipher_string_unexpanded"].([]string); len(un) != 1 || un[0] != "ECDHE+AES-GCM" {
		t.Errorf("vs-hardened: unexpanded = %v, want [ECDHE+AES-GCM]", un)
	}
	if ex, _ := byHost["vs-hardened"].Metadata["cipher_string_excluded"].([]string); strings.Join(ex, ",") != "aNULL,RC4,3DES,MD5" {
		t.Errorf("vs-hardened: excluded = %v", ex)
	}
	if g := byHost["vs-group"].Metadata["cipher_group"]; g != "/Common/f5-secure" {
		t.Errorf("vs-group: cipher_group = %v", g)
	}

	// An explicit list resolves: every enabled suite, and only the components
	// they all share.
	explicit := byHost["vs-explicit"]
	if strings.Join(explicit.SupportedCiphers, ",") != "ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256" {
		t.Errorf("vs-explicit: supported = %v", explicit.SupportedCiphers)
	}
	if explicit.CipherSuite == nil || *explicit.CipherSuite != "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256" {
		t.Errorf("vs-explicit: cipher suite = %v", explicit.CipherSuite)
	}
	if explicit.KeyExchangeAlg == nil || *explicit.KeyExchangeAlg != "ECDHE" {
		t.Errorf("vs-explicit: key exchange = %v, want ECDHE (shared by both suites)", explicit.KeyExchangeAlg)
	}
	if explicit.HashAlgorithm != nil {
		t.Errorf("vs-explicit: the suites differ in hash, so none may be claimed; got %q", *explicit.HashAlgorithm)
	}
	if explicit.KeySize != nil {
		t.Errorf("vs-explicit: the suites differ in key length, so none may be claimed; got %d", *explicit.KeySize)
	}
}
