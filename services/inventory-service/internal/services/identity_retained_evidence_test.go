package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRetainedEvidenceTypedProjectionAndSecretExclusion(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	cases := []struct {
		kind, payload                                  string
		facts, software, endpoints, certificates, keys int
	}{
		{"host_inventory", `{"facts":[{"key":"os.name","value":"Linux"},{"key":"unknown.secret","value":"DO_NOT_EXPOSE"}],"assets":[{"port":443,"protocol":"tcp"}],"device_info":{"packages":[{"name":"openssl","credential":"DO_NOT_EXPOSE"}],"cert_stores":[{"path":"DO_NOT_EXPOSE","certs":[{"fingerprint_sha256":"` + fingerprint + `","not_after":"2020-01-01T00:00:00Z","subject_dn":"DO_NOT_EXPOSE"}]}],"password":"DO_NOT_EXPOSE"}}`, 1, 1, 1, 1, 0},
		{"peer", `{"Observations":{"Facts":[{"key":"hw.model","value":"DO_NOT_EXPOSE"}],"Relationships":[{"attributes":{"password":"DO_NOT_EXPOSE"}}]},"Source":{"ref":"interrogation:test"}}`, 1, 0, 0, 0, 0},
		{"cloud", `{"Device":{"DeviceType":"aws_kms","Password":"DO_NOT_EXPOSE","Metadata":{"key_id":"DO_NOT_EXPOSE","crypto_configs":[{"protocol":"TLS","port":443,"certificate":{"fingerprint_sha256":"` + fingerprint + `","pem":"-----BEGIN PRIVATE KEY-----DO_NOT_EXPOSE"}}]}},"Enumeration":{"Facts":{"hw.vendor":"DO_NOT_EXPOSE"}},"Observation":{"source":{"ref":"cloud:aws"}}}`, 1, 0, 1, 1, 1},
		{"crypto", `{"protocol":"SSH","port":22,"raw_data":{"ssh_host_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","private_key":"DO_NOT_EXPOSE","token":"DO_NOT_EXPOSE"}}`, 0, 0, 1, 0, 1},
		{"passive_host", `{"kind":"host_observation","raw_data":{"host_observation":{"vendor":"Example","model":"Model","attributes":{"password":"DO_NOT_EXPOSE"}}}}`, 2, 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			out := RetainedEvidenceSummary{Kind: tc.kind, Protocols: []string{}, Certificates: []RetainedCertificateSummary{}}
			if err := projectRetainedEvidence(&out, []byte(tc.payload)); err != nil {
				t.Fatal(err)
			}
			if out.FactsCount != tc.facts || out.SoftwareCount != tc.software || out.EndpointsCount != tc.endpoints || out.CertificatesCount != tc.certificates || out.KeysCount != tc.keys {
				t.Fatalf("unexpected projection %+v", out)
			}
			data, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "DO_NOT_EXPOSE") || strings.Contains(string(data), "PRIVATE KEY") {
				t.Fatalf("secret escaped safe projection: %s", data)
			}
			if tc.kind == "host_inventory" && (out.Certificates[0].Expired == nil || !*out.Certificates[0].Expired) {
				t.Fatal("credible expired certificate evidence lost")
			}
		})
	}
}
func TestRetainedCertificateExamplesAreBoundedAndCountsDeduplicated(t *testing.T) {
	out := RetainedEvidenceSummary{}
	for repeat := 0; repeat < 2; repeat++ {
		for i := 0; i < 15; i++ {
			appendRetainedCertificate(&out, retainedCertificateInput{FingerprintSHA256: fmt.Sprintf("%064x", i+1)})
		}
	}
	appendRetainedCertificate(&out, retainedCertificateInput{FingerprintSHA256: "not a fingerprint"})
	if out.CertificatesCount != 15 || len(out.Certificates) != retainedCertificateLimit {
		t.Fatalf("count=%d examples=%d", out.CertificatesCount, len(out.Certificates))
	}
}
