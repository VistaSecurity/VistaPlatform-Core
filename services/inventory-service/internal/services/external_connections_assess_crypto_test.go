package services

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// strPtr is a test helper that returns a pointer to a string.
func strPtr(s string) *string { return &s }

// boolPtr is a test helper that returns a pointer to a bool.
func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// assessKeyExchangeSize
// ---------------------------------------------------------------------------

func TestAssessKeyExchangeSize(t *testing.T) {
	t.Parallel()

	svc := &ExternalConnectionsService{}

	tests := []struct {
		name       string
		kex        *string
		keySize    *int
		wantEmpty  bool
		wantSubstr string // substring expected in first reason
	}{
		{
			name:      "nil key size — no reasons",
			kex:       strPtr("DHE"),
			keySize:   nil,
			wantEmpty: true,
		},
		{
			name:      "zero key size — no reasons",
			kex:       strPtr("DHE"),
			keySize:   intPtr(0),
			wantEmpty: true,
		},
		{
			name:       "DHE 480-bit — critical",
			kex:        strPtr("DHE"),
			keySize:    intPtr(480),
			wantSubstr: "Critical",
		},
		{
			name:       "DHE 512-bit — critical",
			kex:        strPtr("DHE"),
			keySize:    intPtr(512),
			wantSubstr: "Critical",
		},
		{
			name:       "DHE 768-bit — critical (< 1024)",
			kex:        strPtr("DHE"),
			keySize:    intPtr(768),
			wantSubstr: "Critical",
		},
		{
			name:       "DHE 1024-bit — weak (< 2048)",
			kex:        strPtr("DHE"),
			keySize:    intPtr(1024),
			wantSubstr: "Weak",
		},
		{
			name:      "DHE 2048-bit — acceptable, no reasons",
			kex:       strPtr("DHE"),
			keySize:   intPtr(2048),
			wantEmpty: true,
		},
		{
			name:      "DHE 4096-bit — acceptable, no reasons",
			kex:       strPtr("DHE"),
			keySize:   intPtr(4096),
			wantEmpty: true,
		},
		{
			name:       "DH-480 explicit code — critical",
			kex:        strPtr("DH-480"),
			keySize:    intPtr(480),
			wantSubstr: "Critical",
		},
		{
			name:       "RSA 512-bit — critical",
			kex:        strPtr("RSA"),
			keySize:    intPtr(512),
			wantSubstr: "Critical",
		},
		{
			name:       "RSA 1024-bit — weak",
			kex:        strPtr("RSA"),
			keySize:    intPtr(1024),
			wantSubstr: "Weak",
		},
		{
			name:      "RSA 2048-bit — acceptable",
			kex:       strPtr("RSA"),
			keySize:   intPtr(2048),
			wantEmpty: true,
		},
		{
			name:       "STATIC-RSA — no forward secrecy",
			kex:        strPtr("STATIC-RSA"),
			keySize:    intPtr(2048),
			wantSubstr: "forward secrecy",
		},
		{
			name:       "STATIC-RSA weak key — RSA size check",
			kex:        strPtr("STATIC-RSA"),
			keySize:    intPtr(512),
			wantSubstr: "Critical",
		},
		{
			name:      "ECDHE — no key size check (not DH/RSA)",
			kex:       strPtr("ECDHE"),
			keySize:   intPtr(256),
			wantEmpty: true,
		},
		{
			name:      "nil kex — no check",
			kex:       nil,
			keySize:   intPtr(480),
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := models.ExternalConnectionUpsert{
				KeyExchangeAlgorithm: tt.kex,
				KeySize:              tt.keySize,
			}
			reasons := svc.assessKeyExchangeSize(input)
			if tt.wantEmpty {
				if len(reasons) != 0 {
					t.Fatalf("expected no reasons, got %v", reasons)
				}
				return
			}
			if len(reasons) == 0 {
				t.Fatal("expected reasons, got none")
			}
			found := false
			for _, r := range reasons {
				if strings.Contains(r, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected a reason containing %q, got %v", tt.wantSubstr, reasons)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// assessCertPublicKeySize
// ---------------------------------------------------------------------------

func TestAssessCertPublicKeySize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		alg        *string
		size       *int
		wantEmpty  bool
		wantSubstr string
	}{
		{name: "nil size", alg: strPtr("RSA"), size: nil, wantEmpty: true},
		{name: "RSA 4096 — ok", alg: strPtr("RSA"), size: intPtr(4096), wantEmpty: true},
		{name: "RSA 2048 — ok", alg: strPtr("RSA"), size: intPtr(2048), wantEmpty: true},
		{name: "RSA 1024 — weak", alg: strPtr("RSA"), size: intPtr(1024), wantSubstr: "Weak"},
		{name: "RSA 512 — critical", alg: strPtr("RSA"), size: intPtr(512), wantSubstr: "Critical"},
		{name: "ECDSA 256 — ok", alg: strPtr("ECDSA"), size: intPtr(256), wantEmpty: true},
		{name: "ECDSA 224 — ok (boundary)", alg: strPtr("ECDSA"), size: intPtr(224), wantEmpty: true},
		{name: "ECDSA 160 — weak", alg: strPtr("ECDSA"), size: intPtr(160), wantSubstr: "Weak"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := models.ExternalConnectionUpsert{
				CertPublicKeyAlgorithm: tt.alg,
				CertPublicKeySize:      tt.size,
			}
			reasons := assessCertPublicKeySize(input)
			if tt.wantEmpty {
				if len(reasons) != 0 {
					t.Fatalf("expected no reasons, got %v", reasons)
				}
				return
			}
			if len(reasons) == 0 {
				t.Fatal("expected reasons, got none")
			}
			if !strings.Contains(reasons[0], tt.wantSubstr) {
				t.Fatalf("expected reason containing %q, got %q", tt.wantSubstr, reasons[0])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// assessCertSignatureAlgorithm
// ---------------------------------------------------------------------------

func TestAssessCertSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sigAlg     *string
		wantEmpty  bool
		wantSubstr string
	}{
		{name: "nil", sigAlg: nil, wantEmpty: true},
		{name: "empty", sigAlg: strPtr(""), wantEmpty: true},
		{name: "SHA256WithRSA — ok", sigAlg: strPtr("SHA256WithRSA"), wantEmpty: true},
		{name: "ECDSAWithSHA384 — ok", sigAlg: strPtr("ECDSAWithSHA384"), wantEmpty: true},
		{name: "SHA1WithRSA — weak", sigAlg: strPtr("SHA1WithRSA"), wantSubstr: "SHA-1"},
		{name: "sha1WithRSAEncryption — weak (case insensitive)", sigAlg: strPtr("sha1WithRSAEncryption"), wantSubstr: "SHA-1"},
		{name: "MD5WithRSA — critical", sigAlg: strPtr("MD5WithRSA"), wantSubstr: "MD5"},
		{name: "MD2WithRSA — critical", sigAlg: strPtr("MD2WithRSA"), wantSubstr: "MD2"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := models.ExternalConnectionUpsert{
				CertSignatureAlgorithm: tt.sigAlg,
			}
			reasons := assessCertSignatureAlgorithm(input)
			if tt.wantEmpty {
				if len(reasons) != 0 {
					t.Fatalf("expected no reasons, got %v", reasons)
				}
				return
			}
			if len(reasons) == 0 {
				t.Fatal("expected reasons, got none")
			}
			if !strings.Contains(reasons[0], tt.wantSubstr) {
				t.Fatalf("expected reason containing %q, got %q", tt.wantSubstr, reasons[0])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// assessCertValidationStatus
// ---------------------------------------------------------------------------

func TestAssessCertValidationStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     *string
		wantEmpty  bool
		wantSubstr string
	}{
		{name: "nil", status: nil, wantEmpty: true},
		{name: "valid", status: strPtr("valid"), wantEmpty: true},
		{name: "empty", status: strPtr(""), wantEmpty: true},
		{name: "self_signed", status: strPtr("self_signed"), wantSubstr: "self-signed"},
		{name: "expired", status: strPtr("expired"), wantSubstr: "expired"},
		{name: "hostname_mismatch", status: strPtr("hostname_mismatch"), wantSubstr: "hostname"},
		{name: "untrusted_ca", status: strPtr("untrusted_ca"), wantSubstr: "untrusted"},
		{name: "incomplete_chain", status: strPtr("incomplete_chain"), wantSubstr: "Incomplete"},
		{name: "revoked", status: strPtr("revoked"), wantSubstr: "revoked"},
		{name: "unknown_status", status: strPtr("something_weird"), wantSubstr: "something_weird"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := models.ExternalConnectionUpsert{
				CertValidationStatus: tt.status,
			}
			reasons := assessCertValidationStatus(input)
			if tt.wantEmpty {
				if len(reasons) != 0 {
					t.Fatalf("expected no reasons, got %v", reasons)
				}
				return
			}
			if len(reasons) == 0 {
				t.Fatal("expected reasons, got none")
			}
			if !strings.Contains(reasons[0], tt.wantSubstr) {
				t.Fatalf("expected reason containing %q, got %q", tt.wantSubstr, reasons[0])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// assessSensorCertFlags
// ---------------------------------------------------------------------------

func TestAssessSensorCertFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      models.ExternalConnectionUpsert
		wantCount  int
		wantSubstr string // substring in any reason
	}{
		{
			name:      "no flags set — no reasons",
			input:     models.ExternalConnectionUpsert{},
			wantCount: 0,
		},
		{
			name: "known-bad CA",
			input: models.ExternalConnectionUpsert{
				CertKnownBadCA: strPtr("Superfish"),
			},
			wantCount:  1,
			wantSubstr: "Superfish",
		},
		{
			name: "missing SCTs",
			input: models.ExternalConnectionUpsert{
				CertHasSCT: boolPtr(false),
			},
			wantCount:  1,
			wantSubstr: "SCT",
		},
		{
			name: "has SCTs — no reason",
			input: models.ExternalConnectionUpsert{
				CertHasSCT: boolPtr(true),
			},
			wantCount: 0,
		},
		{
			name: "no subject",
			input: models.ExternalConnectionUpsert{
				CertNoSubject: true,
			},
			wantCount:  1,
			wantSubstr: "no Subject",
		},
		{
			name: "no common name",
			input: models.ExternalConnectionUpsert{
				CertNoCommonName: true,
			},
			wantCount:  1,
			wantSubstr: "no Common Name",
		},
		{
			name: "OCSP revoked",
			input: models.ExternalConnectionUpsert{
				OCSPStatus: strPtr("revoked"),
			},
			wantCount:  1,
			wantSubstr: "revoked",
		},
		{
			name: "OCSP revoked when cert_validation already revoked — no duplicate OCSP reason",
			input: models.ExternalConnectionUpsert{
				CertValidationStatus: strPtr("revoked"),
				OCSPStatus:           strPtr("revoked"),
			},
			wantCount: 0,
		},
		{
			name: "OCSP good — no reason",
			input: models.ExternalConnectionUpsert{
				OCSPStatus: strPtr("good"),
			},
			wantCount: 0,
		},
		{
			name: "multiple flags combine",
			input: models.ExternalConnectionUpsert{
				CertKnownBadCA: strPtr("eDellRoot"),
				CertHasSCT:     boolPtr(false),
				CertNoSubject:  true,
			},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reasons := assessSensorCertFlags(tt.input)
			if len(reasons) != tt.wantCount {
				t.Fatalf("expected %d reasons, got %d: %v", tt.wantCount, len(reasons), reasons)
			}
			if tt.wantSubstr != "" && len(reasons) > 0 {
				found := false
				for _, r := range reasons {
					if strings.Contains(r, tt.wantSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected a reason containing %q, got %v", tt.wantSubstr, reasons)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isWeakProtocol
// ---------------------------------------------------------------------------

func TestIsWeakProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		protocol string
		version  *string
		want     bool
	}{
		{"TLS", strPtr("1.0"), true},
		{"TLS", strPtr("1.1"), true},
		{"TLS", strPtr("1.2"), false},
		{"TLS", strPtr("1.3"), false},
		{"TLS", nil, false},
		{"SSL", nil, true},
		{"SSLv3", nil, true},
		{"HTTPS", nil, false},
		{"SSH", nil, false},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_%v", tt.protocol, tt.version)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := isWeakProtocol(tt.protocol, tt.version)
			if got != tt.want {
				t.Fatalf("isWeakProtocol(%q, %v) = %v, want %v", tt.protocol, tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hasWeakTLSVersion
// ---------------------------------------------------------------------------

func TestHasWeakTLSVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		versions []string
		want     bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"TLS 1.2 only", []string{"TLS 1.2"}, false},
		{"TLS 1.2 and 1.3", []string{"TLS 1.2", "TLS 1.3"}, false},
		{"includes TLS 1.0", []string{"TLS 1.0", "TLS 1.2"}, true},
		{"includes TLS 1.1", []string{"TLS 1.1", "TLS 1.2"}, true},
		{"includes SSLv3", []string{"SSLv3", "TLS 1.2"}, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hasWeakTLSVersion(tt.versions)
			if got != tt.want {
				t.Fatalf("hasWeakTLSVersion(%v) = %v, want %v", tt.versions, got, tt.want)
			}
		})
	}
}
