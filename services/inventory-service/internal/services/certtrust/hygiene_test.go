package certtrust

import (
	"reflect"
	"testing"
)

func TestApplyTrustToHygiene(t *testing.T) {
	const sct = "Certificate missing Signed Certificate Timestamps (SCTs) — not logged in Certificate Transparency"
	for _, tc := range []struct {
		name       string
		flags      []string
		validation string
		trust      string
		want       []string
	}{
		{"probe untrusted, no tenant verdict: the flag stands", []string{sct}, "untrusted_ca", "", []string{sct, HygieneUntrustedCA}},
		{"probe untrusted, tenant verdict untrusted", []string{HygieneUntrustedCA}, "untrusted_ca", StatusUntrusted, []string{HygieneUntrustedCA}},
		{"tenant trusted the CA: no untrusted flag", []string{sct, HygieneUntrustedCA}, "untrusted_ca", StatusPrivateTrusted, []string{sct}},
		{"public root per the bundle: no untrusted flag", []string{HygieneUntrustedCA}, "untrusted_ca", StatusPublic, []string{}},
		{"tenant distrusted the CA: distrusted replaces untrusted", []string{HygieneUntrustedCA, sct}, "untrusted_ca", StatusDistrusted, []string{sct, HygieneDistrustedCA}},
		{"distrusted although the probe said valid", nil, "valid", StatusDistrusted, []string{HygieneDistrustedCA}},
		{"a removed distrust takes its flag with it", []string{HygieneDistrustedCA}, "valid", StatusPublic, []string{}},
		{"incomplete verdict leaves the probe's answer", []string{}, "untrusted_ca", StatusIncomplete, []string{HygieneUntrustedCA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyTrustToHygiene(tc.flags, tc.validation, tc.trust)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
