package deviceinterrogation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Every collector that turns a vendor response into asset metadata must project
// onto an allowlist rather than copy the object. These tests feed each converter
// a realistic response WITH the secret fields that vendor actually returns, and
// assert the material does not survive.
//
// The redaction backstop in redact.go would catch most of these by field name.
// That is deliberately not what is being tested here — the point is that the
// data is never collected, so these tests call the converters directly, before
// any redaction runs.

// poison is a value that must never appear in a converted asset.
const poison = "MUST-NOT-BE-COLLECTED"

func assertNoPoison(t *testing.T, label string, v interface{}) {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", label, err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("%s: collected material that should have been projected away: %s", label, blob)
	}
}

// FortiOS `vpn.ipsec/phase1-interface` carries psksecret — the tunnel's
// pre-shared key — alongside the proposal we want.
func TestFortinetIPSecProjection_DropsPreSharedKey(t *testing.T) {
	c := &fortinetClient{}
	asset := c.convertIPSecToAsset(map[string]interface{}{
		"name":           "branch-tunnel",
		"remote-gw":      "198.51.100.7",
		"proposal":       "aes256-sha256",
		"dhgrp":          "14",
		"psksecret":      poison,
		"ppk-secret":     poison,
		"authpasswd":     poison,
		"ipv4-split-inc": poison, // not secret, just not on the allowlist
	})

	assertNoPoison(t, "fortinet ipsec", asset)
	if asset.Hostname != "branch-tunnel" {
		t.Errorf("identity lost: %+v", asset)
	}
	if asset.Metadata["dh_group"] != "14" {
		t.Errorf("posture lost: %#v", asset.Metadata)
	}
	if asset.CipherSuite == nil || *asset.CipherSuite != "aes256-sha256" {
		t.Errorf("proposal lost: %+v", asset.CipherSuite)
	}
}

func TestFortinetSSLVPNProjection_DropsUnlistedFields(t *testing.T) {
	c := &fortinetClient{}
	asset := c.convertSSLVPNToAsset(map[string]interface{}{
		"server_hostname": "vpn.example.net",
		"port":            float64(10443),
		"cipher":          "TLS-AES-256-GCM-SHA384",
		"tls_version":     "TLS 1.3",
		"server_cert":     "Fortinet_SSL",
		"x-auth-secret":   poison,
		"admin-password":  poison,
	})

	assertNoPoison(t, "fortinet sslvpn", asset)
	if asset.Hostname != "vpn.example.net" || asset.Port != 10443 {
		t.Errorf("identity lost: %+v", asset)
	}
	if asset.Metadata["certificate_name"] != "Fortinet_SSL" {
		t.Errorf("certificate reference lost: %#v", asset.Metadata)
	}
}

// FortiOS `certificate/local` returns the certificate's own private key.
func TestFortinetCertificateProjection_DropsPrivateKey(t *testing.T) {
	out := processFortinetCertificate(map[string]interface{}{
		"name":        "Fortinet_SSL",
		"private-key": poison,
		"password":    poison,
		"csr":         poison,
		"range":       "global",
	})

	assertNoPoison(t, "fortinet certificate", out)
	if out["name"] != "Fortinet_SSL" {
		t.Errorf("certificate identity lost: %#v", out)
	}
}

// The generic HTTP interrogator reads a device-configurable endpoint, so the
// response shape is under the remote device's control.
func TestHTTPCertificateProjection_DropsUnlistedFields(t *testing.T) {
	out := projectHTTPCertificate(map[string]interface{}{
		"subject":          "CN=api.example.net",
		"issuer":           "CN=Example CA",
		"serial_number":    "0A1B2C",
		"not_after":        "2027-01-01T00:00:00Z",
		"key_algorithm":    "RSA",
		"key_size":         2048,
		"private_key_pem":  poison,
		"passphrase":       poison,
		"enrollment_token": poison,
		"vendor_blob":      map[string]interface{}{"nested": poison},
	})

	assertNoPoison(t, "http certificate", out)
	if out["subject"] != "CN=api.example.net" || out["key_size"] != 2048 {
		t.Errorf("certificate detail lost: %#v", out)
	}
}

// Hyphenated and camelCase spellings must fold to the same fragment — FortiOS
// says `private-key`, PAN-OS says `private_key`, some APIs say `privateKey`.
func TestIsSecretFieldName_FoldsSeparators(t *testing.T) {
	for _, name := range []string{
		"private-key", "private_key", "privateKey", "Private Key",
		"psk-secret", "psk_secret", "x-api-key", "x.api.key",
		"admin-password", "shared-secret",
	} {
		if !redact.IsSecretName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
	// The load-bearing half: these END in "key", so the catch-all suffix rule
	// would redact them. Only folding lets them match the safe list, which is
	// spelled with underscores. Without folding these are false positives and we
	// lose the public-key algorithm we are in business to report.
	for _, name := range []string{"public-key", "public key", "Public-Key"} {
		if redact.IsSecretName(name) {
			t.Errorf("posture field %q was redacted; separator folding is not being applied", name)
		}
	}
	for _, name := range []string{"key-size", "key-algorithm", "host-key-type"} {
		if redact.IsSecretName(name) {
			t.Errorf("posture field %q was redacted after separator folding", name)
		}
	}
}

// Projection has to be WIRED, not merely available. This drives the real
// interrogator against a stub device so a future refactor that drops the
// projectHTTPCertificate call is caught, which a direct unit call cannot see.
func TestHTTPInterrogator_ProjectionIsWired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"certificates":[{
			"subject": "CN=api.example.net",
			"key_algorithm": "RSA",
			"private_key_pem": "` + poison + `",
			"passphrase": "` + poison + `"
		}]}`))
	}))
	defer srv.Close()

	result, err := (&HTTPInterrogator{}).Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "generic_http", ManagementURL: srv.URL, Hostname: ""},
		Credentials{},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	assertNoPoison(t, "http interrogator (wired)", result)

	if len(result.Assets) == 0 {
		t.Fatal("no assets returned — the stub response was not parsed")
	}
	if result.Assets[0].Metadata["subject"] != "CN=api.example.net" {
		t.Errorf("certificate detail lost: %#v", result.Assets[0].Metadata)
	}
}

// Every projection allowlist in this package, checked against the one predicate
// that decides whether a field name is material.
//
// This is the layer the per-collector tests cannot reach. A collector that
// builds its result entry field by field — fortinetInterfaces does, and so do
// the UniFi projections — is already safe by construction, so widening its
// allowlist with `psksecret` leaks nothing TODAY and no test notices. The leak
// arrives later, when someone copies the projected map somewhere instead of
// picking fields out of it, and by then the allowlist has carried a secret name
// for months with a green suite behind it.
//
// redact.IsSecretName's own doc names this as its contract: "the one a caller
// building its own projection allowlist should consult (ADR-0004 D4: every
// allowlist widening reviews the new field names against this)." This is that
// review, run by the machine.
//
// To mutation-test: add "psksecret" to fortinetInterfaceFields, or "passphrase"
// to f5HardwareFields, and this fails.
func TestProjectionAllowlists_NameNoSecretFields(t *testing.T) {
	allowlists := map[string][]string{
		"fortinetInterfaceFields":        fortinetInterfaceFields,
		"fortinetMonitorInterfaceFields": fortinetMonitorInterfaceFields,
		"fortinetRouteFields":            fortinetRouteFields,
		"fortinetSSLVPNFields":           fortinetSSLVPNFields,
		"fortinetIPSecTunnelFields":      fortinetIPSecTunnelFields,
		"fortinetCertificateFields":      fortinetCertificateFields,
		"fortinetSystemStatusFields":     fortinetSystemStatusFields,
		"f5SystemVersionFields":          f5SystemVersionFields,
		"f5HardwareFields":               f5HardwareFields,
		"unifiDeviceInventoryFields":     unifiDeviceInventoryFields,
		"unifiDeviceStructuredFields":    unifiDeviceStructuredFields,
		"unifiPortFields":                unifiPortFields,
		"unifiEthernetFields":            unifiEthernetFields,
		"unifiLLDPFields":                unifiLLDPFields,
		"unifiUplinkFields":              unifiUplinkFields,
		"unifiClientInventoryFields":     unifiClientInventoryFields,
		"httpCertificateFields":          httpCertificateFields,
	}

	// A walker that checks nothing passes vacuously.
	total := 0
	for _, fields := range allowlists {
		total += len(fields)
	}
	if len(allowlists) < 16 || total < 60 {
		t.Fatalf("only %d allowlists / %d field names were checked; the test has stopped covering the package", len(allowlists), total)
	}

	for name, fields := range allowlists {
		for _, field := range fields {
			if redact.IsSecretName(field) {
				t.Errorf("%s names %q, which redact.IsSecretName reads as secret material. An allowlist is the layer that decides what is COLLECTED; the backstop is not a licence to name a secret here.", name, field)
			}
		}
	}
}

// --- the projections nothing observed -------------------------------------
//
// The tests above call a converter and assert the material is absent. That
// catches a projection whose output is READ AS A WHOLE. It does not catch one
// whose output is then picked apart field by field by its caller, because in
// that shape removing the projection changes nothing any assertion can see —
// the caller asks for `name` and `mac` and gets them either way.
//
// Three of this package's projections are in exactly that shape, and the gate-2
// sweep found all three surviving a mutation that deleted them outright:
// unifiProject (the nested device tables), projectFortinet over the interface
// allowlists, and projectF5 over `sys/version`. "Safe by construction" is a true
// statement about today's callers and a promise about nobody else's, and the
// comments on those allowlists make the promise out loud.
//
// The tests below assert the promise itself: the OUTPUT of each projection
// carries nothing but the names its allowlist lists. They fail when a
// projection is widened — including with a field that is material without being
// NAMED like one, which redact.IsSecretName cannot see and the allowlist-name
// test below therefore cannot catch (`secondaryip` is the worked example: a
// nested FortiOS table whose entries carry the PPPoE password).
//
// Where the projection is reached through a function these tests can call —
// unifiTableEntries, f5Client.getSystemInfo — they also fail when it is
// REMOVED. FortiOS is the one residual: projectFortinet is called inline inside
// fortinetInterfaces, whose output is then built field by field, so deleting
// the call changes nothing observable from outside. That is recorded rather
// than papered over; the guard there is the bounded output plus the
// allowlist-name test, and the leak it defends against arrives the day a caller
// copies a projected entry instead of picking fields out of it.

// assertKeysWithin fails when a projected object carries a key its allowlist
// does not name.
func assertKeysWithin(t *testing.T, label string, got map[string]interface{}, allow []string) {
	t.Helper()
	allowed := make(map[string]bool, len(allow))
	for _, f := range allow {
		allowed[f] = true
	}
	if len(got) == 0 {
		t.Fatalf("%s: the projection returned nothing, so this proves nothing", label)
	}
	for key := range got {
		if !allowed[key] {
			t.Errorf("%s: projected key %q is not on its allowlist %v", label, key, allow)
		}
	}
}

// The UniFi nested device tables. Each entry of port_table / ethernet_table /
// lldp_table is projected by unifiTableEntries, and the fixture carries the
// x_-prefixed controller secrets and the unbounded `system_desc` banner that
// projection exists to drop.
func TestUnifiTableProjections_OutputIsBoundedByItsAllowlist(t *testing.T) {
	device := unifiSwitchFixture()

	for _, tc := range []struct {
		table string
		allow []string
	}{
		{"port_table", unifiPortFields},
		{"ethernet_table", unifiEthernetFields},
		{"lldp_table", unifiLLDPFields},
	} {
		entries := unifiTableEntries(device, tc.table)
		if len(entries) == 0 {
			t.Fatalf("%s: no entries projected; the fixture no longer exercises this table", tc.table)
		}
		assertNoPoison(t, "unifi "+tc.table, entries)
		for i, entry := range entries {
			assertKeysWithin(t, fmt.Sprintf("unifi %s[%d]", tc.table, i), entry, tc.allow)
		}
	}

	// The uplink object is projected on its own, by unifiUplinkEdge.
	uplink, ok := device["uplink"].(map[string]interface{})
	if !ok {
		t.Fatal("the fixture no longer carries an uplink object")
	}
	projected := unifiProject(uplink, unifiUplinkFields)
	assertNoPoison(t, "unifi uplink", projected)
	assertKeysWithin(t, "unifi uplink", projected, unifiUplinkFields)

	// The fixture must really carry the material, or every assertion above is
	// the absence of something that was never there.
	blob, _ := json.Marshal(device)
	if !strings.Contains(string(blob), poison) {
		t.Fatal("the UniFi switch fixture no longer carries secret-shaped fields; this test now proves nothing")
	}
}

// The FortiOS interface allowlists. `system/interface` is CONFIGURATION, and
// the fixture carries the PPPoE password, the dialup psksecret and the nested
// secondaryip table alongside the addressing we want.
func TestFortinetInterfaceProjections_OutputIsBoundedByItsAllowlist(t *testing.T) {
	configured := fortinetResultsFromJSON(t, fortinetInterfaceResponse)
	running := fortinetMonitorResultsFromJSON(t, fortinetMonitorInterfaceResponse)
	routes := fortinetResultsFromJSON(t, fortinetRouteResponse)

	for i, raw := range configured {
		projected := projectFortinet(raw, fortinetInterfaceFields)
		assertNoPoison(t, fmt.Sprintf("fortinet cmdb interface[%d]", i), projected)
		assertKeysWithin(t, fmt.Sprintf("fortinet cmdb interface[%d]", i), projected, fortinetInterfaceFields)
	}
	for i, raw := range running {
		projected := projectFortinet(raw, fortinetMonitorInterfaceFields)
		assertNoPoison(t, fmt.Sprintf("fortinet monitor interface[%d]", i), projected)
		assertKeysWithin(t, fmt.Sprintf("fortinet monitor interface[%d]", i), projected, fortinetMonitorInterfaceFields)
	}
	// The route allowlist has ONE field, and what it projects is the customer's
	// routing table. A widening here is the largest single leak in this package
	// by volume.
	for i, raw := range routes {
		projected := projectFortinet(raw, fortinetRouteFields)
		assertKeysWithin(t, fmt.Sprintf("fortinet route[%d]", i), projected, fortinetRouteFields)
	}

	if !strings.Contains(fortinetInterfaceResponse, poison) {
		t.Fatal("the FortiOS interface fixture no longer carries secret-shaped fields; this test now proves nothing")
	}
}

// F5 `sys/version`, read through the REAL client and BEFORE any redaction.
//
// This is the projection the gate-2 sweep found genuinely unguarded rather than
// merely unobserved: its only test drove the interrogator through Registry.Get,
// so Sanitize scrubbed `adminPassphrase` and `sslPrivateKey` by NAME and the
// test stayed green with projectF5 deleted. The backstop is name-based, so a
// vendor field that is sensitive without being named like one — a licence key
// under `Title`, a support-contract id — would have reached DeviceInfo on every
// F5 interrogation with nothing failing.
func TestF5SystemVersionProjection_RunsBeforeAnyRedaction(t *testing.T) {
	srv := newF5OpsTestServer(t)
	defer srv.Close()
	c := newF5Client(srv.URL, "admin", "admin", "", true)

	info, err := c.getSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("getSystemInfo: %v", err)
	}

	assertNoPoison(t, "f5 sys/version", info)
	assertKeysWithin(t, "f5 sys/version", info, f5SystemVersionFields)
	if info["Version"] != "17.1.1.3" || info["Product"] != "BIG-IP" {
		t.Errorf("the version identity was lost by the projection: %#v", info)
	}
	if !strings.Contains(f5VersionResponse, poison) {
		t.Fatal("the F5 sys/version fixture no longer carries secret-shaped fields; this test now proves nothing")
	}
}
