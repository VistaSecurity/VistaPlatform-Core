package jobunits

// TLSValidationMetadata is the one mapping of a shared TLS probe's validation
// outcome onto canonical top-level metadata keys. Scan-engine findings
// (TLSProbeMetadata) and the cloud collectors' handshake both take it from
// here, so these cases pin the keys inventory reads.

import (
	"reflect"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

func TestTLSValidationMetadata(t *testing.T) {
	cases := []struct {
		name string
		res  shareddisc.ProbeResult
		want map[string]interface{}
	}{
		{
			name: "trusted chain, OCSP good, SCT present",
			res: shareddisc.ProbeResult{
				CertValidationStatus: "valid",
				Metadata: map[string]interface{}{
					"cert_has_sct": true, "cert_sct_source": "embedded", "cert_is_ev": true,
					"ocsp_status": "good", "server_requests_client_cert": false,
				},
			},
			want: map[string]interface{}{
				"cert_validation_status": "valid", "cert_validation_error": "",
				"cert_has_sct": true, "cert_sct_source": "embedded", "cert_is_ev": true,
				"ocsp_status": "good", "server_requests_client_cert": false,
			},
		},
		{
			name: "self-signed keeps the verifier's error and an explicit false SCT",
			res: shareddisc.ProbeResult{
				CertValidationStatus: "self_signed",
				CertValidationError:  "x509: certificate signed by unknown authority",
				Metadata:             map[string]interface{}{"cert_has_sct": false, "cert_sct_source": "none"},
			},
			want: map[string]interface{}{
				"cert_validation_status": "self_signed",
				"cert_validation_error":  "x509: certificate signed by unknown authority",
				"cert_has_sct":           false, "cert_sct_source": "none",
			},
		},
		{
			name: "expired",
			res:  shareddisc.ProbeResult{CertValidationStatus: "expired", CertValidationError: "x509: certificate has expired"},
			want: map[string]interface{}{"cert_validation_status": "expired", "cert_validation_error": "x509: certificate has expired"},
		},
		{
			name: "OCSP revoked with detail and a known-bad CA",
			res: shareddisc.ProbeResult{
				CertValidationStatus: "valid",
				Metadata: map[string]interface{}{
					"ocsp_status": "revoked", "ocsp_detail": "revoked 2026-01-02 (keyCompromise)", "cert_known_bad_ca": "Example Bad CA",
				},
			},
			want: map[string]interface{}{
				"cert_validation_status": "valid", "cert_validation_error": "",
				"ocsp_status": "revoked", "ocsp_detail": "revoked 2026-01-02 (keyCompromise)", "cert_known_bad_ca": "Example Bad CA",
			},
		},
		{
			name: "OCSP unknown",
			res:  shareddisc.ProbeResult{CertValidationStatus: "valid", Metadata: map[string]interface{}{"ocsp_status": "unknown"}},
			want: map[string]interface{}{"cert_validation_status": "valid", "cert_validation_error": "", "ocsp_status": "unknown"},
		},
		{
			name: "no recorded status reads unknown, never empty; unmeasured keys stay absent",
			res:  shareddisc.ProbeResult{Metadata: map[string]interface{}{"tls_version_raw": 772}},
			want: map[string]interface{}{"cert_validation_status": "unknown", "cert_validation_error": ""},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := TLSValidationMetadata(&c.res)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("TLSValidationMetadata = %#v\nwant %#v", got, c.want)
			}
			// The scan-engine finding carries exactly the same values.
			full := TLSProbeMetadata(&c.res, nil)
			for k, v := range c.want {
				if !reflect.DeepEqual(full[k], v) {
					t.Errorf("TLSProbeMetadata[%q] = %#v, want %#v", k, full[k], v)
				}
			}
		})
	}
}

// TLSValidationKeys names every key the mapping can emit, so a consumer that
// forwards by name cannot miss one.
func TestTLSValidationKeysCoverTheMapping(t *testing.T) {
	res := shareddisc.ProbeResult{CertValidationStatus: "valid", Metadata: map[string]interface{}{}}
	for _, k := range tlsValidationMetaKeys {
		res.Metadata[k] = "x"
	}
	listed := map[string]bool{}
	for _, k := range TLSValidationKeys() {
		listed[k] = true
	}
	for k := range TLSValidationMetadata(&res) {
		if !listed[k] {
			t.Errorf("TLSValidationMetadata emits %q but TLSValidationKeys does not list it", k)
		}
	}
}
