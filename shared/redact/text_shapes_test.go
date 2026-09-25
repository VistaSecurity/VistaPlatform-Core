package redact

import (
	"strings"
	"testing"
)

// The structured shapes, in both polarities. Each masked case is a shape a
// credential has actually been seen in, inside a string that reached a
// persisted field: a vendor error body, an echoed header, a configuration line.
// Each kept case is posture or prose that a stricter rule would have eaten.
func TestTextStructuredSecrets(t *testing.T) {
	masked := []struct {
		name, in string
		gone     []string // every one must be absent from the output
		keep     []string // and every one of these must survive
	}{
		{"F5 401 body echoing the token and password",
			`API returned status 401: {"X-F5-Auth-Token":"F5TOKSECRET1","token":"F5TOKSECRET2","password":"F5PWSECRET3","code":401}`,
			[]string{"F5TOKSECRET1", "F5TOKSECRET2", "F5PWSECRET3"}, []string{"401", `"code":401`}},
		{"F5 login response with a nested token object",
			`{"token":{"token":"NESTEDTOK1","userName":"admin"}}`,
			[]string{"NESTEDTOK1"}, nil},
		{"FortiOS body quoting a PSK",
			`API returned status 500: {"psksecret":"ENC FGPSKSECRET1","status":"error"}`,
			[]string{"FGPSKSECRET1"}, []string{`"status":"error"`}},
		{"JSON with spaces and a bare value",
			`{ "password" : "hunter2", "pin": 123456, "key_size": 2048 }`,
			[]string{"hunter2", "123456"}, []string{`"key_size": 2048`}},
		{"escaped JSON inside a %q-formatted error",
			`body "{\"api_key\":\"ESCAPEDKEY1\",\"model\":\"FGT60F\"}"`,
			[]string{"ESCAPEDKEY1"}, []string{"FGT60F"}},
		{"JSON string cut off by a byte bound",
			`{"secret":"TRUNCATEDSECRE`,
			[]string{"TRUNCATEDSECRE"}, nil},
		{"UniFi meta.msg quoting a password",
			`API error: password: UNIFIPW1`,
			[]string{"UNIFIPW1"}, []string{"API error"}},
		{"header style on its own line",
			"HTTP/1.1 401\nX-F5-Auth-Token: HDRTOKEN1\nContent-Type: application/json",
			[]string{"HDRTOKEN1"}, []string{"Content-Type: application/json"}},
		{"YAML style",
			"device:\n  community: s3cr3tcomm\n  model: C9300",
			[]string{"s3cr3tcomm"}, []string{"model: C9300"}},
		{"Authorization: Bearer",
			`request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.SECRETJWT`,
			[]string{"eyJhbGciOiJIUzI1NiJ9", "SECRETJWT"}, []string{"Authorization"}},
		{"Authorization: Basic",
			`Authorization: Basic YWRtaW46aHVudGVyMg==`,
			[]string{"YWRtaW46aHVudGVyMg=="}, nil},
		{"Authorization as a JSON member",
			`{"Authorization":"Bearer JSONBEARER1"}`,
			[]string{"JSONBEARER1"}, nil},
		{"enable secret with a type",
			`enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0`,
			[]string{"$1$mERr$hx5rVt7rPNoS4wqbXKX7m0"}, []string{"enable secret 5"}},
		{"enable password in clear",
			`enable password Cisco123`,
			[]string{"Cisco123"}, nil},
		{"username secret",
			`username admin privilege 15 secret 9 $9$SCRYPTHASH`,
			[]string{"$9$SCRYPTHASH"}, []string{"username admin privilege 15 secret 9"}},
		{"username password type 7",
			`username ops password 7 0822455D0A16`,
			[]string{"0822455D0A16"}, nil},
		{"crypto isakmp key",
			`crypto isakmp key ISAKMPPSK1 address 203.0.113.10`,
			[]string{"ISAKMPPSK1"}, []string{"address 203.0.113.10"}},
		{"pre-shared-key",
			` ikev1 pre-shared-key ASAPSK1`,
			[]string{"ASAPSK1"}, nil},
		{"pre-shared-key local with a type",
			`pre-shared-key local 0 LOCALPSK1`,
			[]string{"LOCALPSK1"}, nil},
		{"snmp-server community",
			`snmp-server community SNMPCOMM1 RO`,
			[]string{"SNMPCOMM1"}, []string{"RO"}},
		{"key-string",
			` key-string 7 KEYSTRING1`,
			[]string{"KEYSTRING1"}, nil},
		{"tacacs-server key",
			`tacacs-server host 192.0.2.5 key 7 TACACSKEY1`,
			[]string{"TACACSKEY1"}, nil},
		{"userinfo with @ in the password",
			`Get "https://admin:p@ss@w0rd@192.0.2.1/api/": EOF`,
			[]string{"p@ss", "w0rd", "admin:"}, []string{"192.0.2.1/api/"}},
		{"userinfo with / in the password",
			`Get "https://admin:pa/ss/wd@192.0.2.1/mgmt": EOF`,
			[]string{"pa/ss", "admin:"}, []string{"192.0.2.1/mgmt"}},
	}
	for _, c := range masked {
		got := Text(c.in)
		for _, g := range c.gone {
			if strings.Contains(got, g) {
				t.Errorf("%s: Text(%q) = %q; %q survived", c.name, c.in, got, g)
			}
		}
		if !strings.Contains(got, Marker) {
			t.Errorf("%s: Text(%q) = %q; want the %s marker so the backstop is visible", c.name, c.in, got, Marker)
		}
		for _, k := range c.keep {
			if !strings.Contains(got, k) {
				t.Errorf("%s: Text(%q) = %q; %q was destroyed with the secret", c.name, c.in, got, k)
			}
		}
	}

	// Posture and prose must come through untouched. A redactor that eats
	// these is the same bug pointed the other way.
	kept := []string{
		"failed to get API key: API request failed with status 401",
		"failed to decode token: invalid character 'x' looking for beginning of value",
		"x509: certificate signed by unknown authority",
		`Get "https://192.0.2.1/api/v2/cmdb/system/status": dial tcp 192.0.2.1:443: connect: connection refused`,
		`{"key_size": 2048, "public_key": "MFkwEwYHKoZI", "key_algorithm": "RSA"}`,
		`{"status":"error","http_status":403,"error":-37}`,
		"authentication_algorithm: sha256",
		"key_exchange: ECDHE",
		"ssl cipher tlsv1.2 high",
		"crypto map OUTSIDE 10 ipsec-isakmp",
		"show crypto isakmp sa",
		"https://vendor.example/support?contact=ops@example.com",
		"API error: api.err.NoPermission",
		"Output cut at 262144 bytes; the facts derived from it are partial",
	}
	for _, in := range kept {
		if got := Text(in); got != in {
			t.Errorf("Text(%q) = %q; it must be left alone", in, got)
		}
	}
}
