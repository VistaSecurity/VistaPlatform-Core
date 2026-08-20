package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PAN-OS response fixtures.
//
// A `type=config&action=get` call does NOT echo the queried xpath back: PAN-OS
// roots <result> at the LAST node of the xpath. These fixtures are that real
// shape, which is what B-14 got wrong — the extractors bound
// <result><config><devices>… and therefore matched nothing on every device,
// while the interrogation still reported success.
//
// The entries carry the neighbouring fields a real appliance returns so the
// tests also demonstrate the projection: only the modelled elements are read,
// everything else is discarded structurally by encoding/xml.
const panSSLDecryptResponse = `<response status="success" code="19">
  <result total-count="2" count="2">
    <ssl-decrypt>
      <entry name="ssl-fwd-proxy-default">
        <certificate><ca>forward-trust-ca</ca></certificate>
        <notify-user>yes</notify-user>
        <disabled-ssl-exclude-cert-from-predefined>
          <member>*.example.com</member>
        </disabled-ssl-exclude-cert-from-predefined>
      </entry>
      <entry name="ssl-inbound-inspect">
        <certificate><ca>inbound-inspect-ca</ca></certificate>
      </entry>
    </ssl-decrypt>
  </result>
</response>`

// The security-rules xpath ends at <rules>, so <result> holds it directly.
const panSecurityRulesResponse = `<response status="success" code="19">
  <result total-count="2" count="2">
    <rules>
      <entry name="allow-web-outbound" uuid="0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9">
        <to><member>untrust</member></to>
        <from><member>trust</member></from>
        <source><member>198.51.100.0/24</member></source>
        <destination><member>any</member></destination>
        <application><member>ssl</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
        <ssl><decrypt>yes</decrypt></ssl>
      </entry>
      <entry name="allow-dns" uuid="1b2c3d4e-5f60-7182-93a4-b5c6d7e8f9a0">
        <to><member>untrust</member></to>
        <from><member>trust</member></from>
        <application><member>dns</member></application>
        <action>allow</action>
      </entry>
    </rules>
  </result>
</response>`

// A multi-vsys device answers an unqualified `entry` xpath with one block per
// match. Taking only the first would silently drop every other vsys.
const panMultiVsysRulesResponse = `<response status="success" code="19">
  <result total-count="2" count="2">
    <rules>
      <entry name="vsys1-decrypt-all"><ssl><decrypt>yes</decrypt></ssl></entry>
    </rules>
    <rules>
      <entry name="vsys2-decrypt-all"><ssl><decrypt>yes</decrypt></ssl></entry>
    </rules>
  </result>
</response>`

// `xpath=/config` (and some management paths) return the full tree instead. The
// extractor must keep working against that nesting too.
const panFullConfigResponse = `<response status="success" code="19">
  <result>
    <config version="11.1.0" urldb="paloaltonetworks">
      <devices>
        <entry name="localhost.localdomain">
          <network>
            <profiles>
              <ssl-decrypt>
                <entry name="ssl-fwd-proxy-default">
                  <certificate><ca>forward-trust-ca</ca></certificate>
                </entry>
              </ssl-decrypt>
            </profiles>
          </network>
        </entry>
      </devices>
    </config>
  </result>
</response>`

const panEmptyResultResponse = `<response status="success" code="7"><result/></response>`

const panErrorResponse = `<response status="error" code="403"><result><msg>Invalid credentials</msg></result></response>`

// newPanTestClient wires a panClient to a fake PAN-OS XML API that answers each
// config xpath from the supplied fixtures.
func newPanTestClient(t *testing.T, sslDecrypt, rules string) (*panClient, func()) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		q := r.URL.Query()
		switch {
		case q.Get("type") == "keygen" || r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`<response status="success"><result><key>FAKEAPIKEY==</key></result></response>`))
		case q.Get("type") == "op":
			_, _ = w.Write([]byte(`<response status="success"><result><system><hostname>fw-edge-01</hostname></system></result></response>`))
		case strings.Contains(q.Get("xpath"), "ssl-decrypt"):
			_, _ = w.Write([]byte(sslDecrypt))
		case strings.Contains(q.Get("xpath"), "rules"):
			_, _ = w.Write([]byte(rules))
		default:
			_, _ = w.Write([]byte(panEmptyResultResponse))
		}
	})
	srv := httptest.NewServer(handler)
	c := newPanClient(srv.URL, "admin", "admin", true)
	c.apiKey = "FAKEAPIKEY=="
	return c, srv.Close
}

// TestPanGetSSLDecryptProfiles_RealResponseShape is the direct regression guard
// for B-14: against the shape PAN-OS actually returns, the old
// Result.Config.Devices.Entry path yielded zero profiles.
func TestPanGetSSLDecryptProfiles_RealResponseShape(t *testing.T) {
	c, closeSrv := newPanTestClient(t, panSSLDecryptResponse, panSecurityRulesResponse)
	defer closeSrv()

	profiles, err := c.getSSLDecryptProfiles(context.Background())
	if err != nil {
		t.Fatalf("getSSLDecryptProfiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 ssl-decrypt profiles, got %d: %+v", len(profiles), profiles)
	}
	if profiles[0].Name != "ssl-fwd-proxy-default" {
		t.Errorf("profile[0].Name = %q; want %q", profiles[0].Name, "ssl-fwd-proxy-default")
	}
	if profiles[0].Certificate.CA != "forward-trust-ca" {
		t.Errorf("profile[0].Certificate.CA = %q; want %q", profiles[0].Certificate.CA, "forward-trust-ca")
	}
	if profiles[1].Name != "ssl-inbound-inspect" {
		t.Errorf("profile[1].Name = %q; want %q", profiles[1].Name, "ssl-inbound-inspect")
	}
}

// TestPanGetSSLDecryptProfiles_FullConfigShape pins that the walk still finds
// the block when a response nests it under <config><devices>.
func TestPanGetSSLDecryptProfiles_FullConfigShape(t *testing.T) {
	c, closeSrv := newPanTestClient(t, panFullConfigResponse, panSecurityRulesResponse)
	defer closeSrv()

	profiles, err := c.getSSLDecryptProfiles(context.Background())
	if err != nil {
		t.Fatalf("getSSLDecryptProfiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "ssl-fwd-proxy-default" {
		t.Fatalf("expected the nested profile to be found, got %+v", profiles)
	}
}

func TestPanGetSSLDecryptProfiles_EmptyAndError(t *testing.T) {
	t.Run("empty result is not an error", func(t *testing.T) {
		c, closeSrv := newPanTestClient(t, panEmptyResultResponse, panSecurityRulesResponse)
		defer closeSrv()
		profiles, err := c.getSSLDecryptProfiles(context.Background())
		if err != nil {
			t.Fatalf("getSSLDecryptProfiles: %v", err)
		}
		if len(profiles) != 0 {
			t.Fatalf("expected no profiles, got %+v", profiles)
		}
	})
	t.Run("error status is reported", func(t *testing.T) {
		c, closeSrv := newPanTestClient(t, panErrorResponse, panSecurityRulesResponse)
		defer closeSrv()
		if _, err := c.getSSLDecryptProfiles(context.Background()); err == nil {
			t.Fatal("expected an error for status=\"error\", got nil")
		}
	})
}

// TestPanGetSecurityRules_RealResponseShape is the second half of B-14.
//
// NOTE: whether a PAN-OS security rule carries an <ssl><decrypt> child at all
// (decryption policy lives in its own rulebase on current PAN-OS) is a separate
// question from the decode root, and is deliberately NOT changed here — the
// fixture reproduces the shape this collector models.
func TestPanGetSecurityRules_RealResponseShape(t *testing.T) {
	c, closeSrv := newPanTestClient(t, panSSLDecryptResponse, panSecurityRulesResponse)
	defer closeSrv()

	rules, err := c.getSecurityRules(context.Background())
	if err != nil {
		t.Fatalf("getSecurityRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d: %+v", len(rules), rules)
	}
	if rules[0].Name != "allow-web-outbound" || rules[0].SSL.Decrypt != "yes" {
		t.Errorf("rules[0] = {%q, %q}; want {allow-web-outbound, yes}", rules[0].Name, rules[0].SSL.Decrypt)
	}
	if rules[1].SSL.Decrypt != "" {
		t.Errorf("rules[1].SSL.Decrypt = %q; want empty (no ssl element)", rules[1].SSL.Decrypt)
	}
}

func TestPanGetSecurityRules_MultipleVsysBlocks(t *testing.T) {
	c, closeSrv := newPanTestClient(t, panSSLDecryptResponse, panMultiVsysRulesResponse)
	defer closeSrv()

	rules, err := c.getSecurityRules(context.Background())
	if err != nil {
		t.Fatalf("getSecurityRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected one rule from each <rules> block, got %d: %+v", len(rules), rules)
	}
	if rules[0].Name != "vsys1-decrypt-all" || rules[1].Name != "vsys2-decrypt-all" {
		t.Errorf("got rules %q, %q; want vsys1-decrypt-all, vsys2-decrypt-all", rules[0].Name, rules[1].Name)
	}
}

// TestPanInterrogate_ProducesAssets is the user-visible claim: a firewall doing
// SSL decryption yields assets, where before it yielded none while the device
// page reported a successful interrogation.
func TestPanInterrogate_ProducesAssets(t *testing.T) {
	c, closeSrv := newPanTestClient(t, panSSLDecryptResponse, panSecurityRulesResponse)
	defer closeSrv()

	result, err := c.interrogate(context.Background())
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}

	// 2 ssl-decrypt profiles + the 1 rule carrying an ssl-decrypt action.
	if len(result.Assets) != 3 {
		t.Fatalf("expected 3 assets, got %d: %+v", len(result.Assets), result.Assets)
	}

	byHost := make(map[string]CryptoAsset, len(result.Assets))
	for _, a := range result.Assets {
		byHost[a.Hostname] = a
	}
	for _, want := range []string{"ssl-fwd-proxy-default", "ssl-inbound-inspect", "allow-web-outbound"} {
		if _, ok := byHost[want]; !ok {
			t.Errorf("no asset for %q", want)
		}
	}
	if ca := byHost["ssl-fwd-proxy-default"].Metadata["certificate_ca"]; ca != "forward-trust-ca" {
		t.Errorf("certificate_ca = %v; want forward-trust-ca", ca)
	}
	// Posture only: the surrounding vendor fields in the fixture must not be
	// carried into the asset metadata.
	for host, asset := range byHost {
		for k := range asset.Metadata {
			switch k {
			case "profile_name", "profile_type", "certificate_ca", "rule_name", "ssl_decrypt":
			default:
				t.Errorf("%s: unexpected metadata key %q — the collector must project onto its allowlist", host, k)
			}
		}
	}
}

// TestPanFindElements_ConsumesMatchedElementWhole guards the walker against
// double-counting a same-named descendant.
func TestPanFindElements_ConsumesMatchedElementWhole(t *testing.T) {
	body := `<response status="success"><result><rules><entry name="outer"><rules><entry name="inner"/></rules></entry></rules></result></response>`
	blocks, err := panFindElements[panRules](body, "rules")
	if err != nil {
		t.Fatalf("panFindElements: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 top-level <rules> block, got %d", len(blocks))
	}
	if len(blocks[0].Entry) != 1 || blocks[0].Entry[0].Name != "outer" {
		t.Errorf("expected only the outer entry, got %+v", blocks[0].Entry)
	}
}

// TestPanFindElements_IgnoresElementsOutsideResult keeps the walk scoped to
// <result>, so an element of the same name elsewhere in the envelope cannot be
// mistaken for config data.
func TestPanFindElements_IgnoresElementsOutsideResult(t *testing.T) {
	body := `<response status="success"><rules><entry name="not-config"/></rules><result><rules><entry name="real"/></rules></result></response>`
	blocks, err := panFindElements[panRules](body, "rules")
	if err != nil {
		t.Fatalf("panFindElements: %v", err)
	}
	if len(blocks) != 1 || len(blocks[0].Entry) != 1 || blocks[0].Entry[0].Name != "real" {
		t.Fatalf("expected only the in-result block, got %+v", blocks)
	}
}
