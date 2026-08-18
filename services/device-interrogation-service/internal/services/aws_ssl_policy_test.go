package services

import (
	"reflect"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// ---------------------------------------------------------------------------
// The regression this file exists for.
//
// getSSLPolicyDetails used to ignore SslPolicy.SslProtocols entirely and set
// {"TLS 1.2", "TLS 1.3"} for ANY policy that had ANY cipher. A listener on
// ELBSecurityPolicy-TLS-1-0-2015-04 — which permits TLS 1.0 — was therefore
// reported as modern-only. protocol_version is what isWeakProtocol reads in
// assessCrypto, so a TLS 1.0 listener could not be detected or scored at all:
// the platform reported a weak protocol as strong.
//
// The table below pins real AWS predefined policies to the protocol sets AWS
// actually publishes for them.
// ---------------------------------------------------------------------------

// sslPolicy builds an SslPolicy the way DescribeSSLPolicies returns one.
func sslPolicy(name string, protocols []string, ciphers ...string) elbv2types.SslPolicy {
	p := elbv2types.SslPolicy{
		Name:         awsconfig.String(name),
		SslProtocols: protocols,
	}
	for i, c := range ciphers {
		prio := int32(i + 1)
		p.Ciphers = append(p.Ciphers, elbv2types.Cipher{
			Name:     awsconfig.String(c),
			Priority: &prio,
		})
	}
	return p
}

func TestSSLPolicyDetails_RealAWSPolicies(t *testing.T) {
	tests := []struct {
		name          string
		policy        elbv2types.SslPolicy
		wantProtocols []string
		wantMin       string
		wantMax       string
	}{
		{
			// THE case that motivated this fix. Legacy policy; TLS 1.0 allowed.
			name: "ELBSecurityPolicy-TLS-1-0-2015-04 permits TLS 1.0",
			policy: sslPolicy("ELBSecurityPolicy-TLS-1-0-2015-04",
				[]string{"TLSv1", "TLSv1.1", "TLSv1.2"},
				"ECDHE-ECDSA-AES128-GCM-SHA256", "AES128-SHA"),
			wantProtocols: []string{"TLS 1.0", "TLS 1.1", "TLS 1.2"},
			wantMin:       "TLS 1.0",
			wantMax:       "TLS 1.2",
		},
		{
			name: "ELBSecurityPolicy-2016-08 permits TLS 1.0",
			policy: sslPolicy("ELBSecurityPolicy-2016-08",
				[]string{"TLSv1", "TLSv1.1", "TLSv1.2"},
				"ECDHE-ECDSA-AES128-GCM-SHA256"),
			wantProtocols: []string{"TLS 1.0", "TLS 1.1", "TLS 1.2"},
			wantMin:       "TLS 1.0",
			wantMax:       "TLS 1.2",
		},
		{
			name: "ELBSecurityPolicy-TLS-1-1-2017-01 floors at TLS 1.1",
			policy: sslPolicy("ELBSecurityPolicy-TLS-1-1-2017-01",
				[]string{"TLSv1.1", "TLSv1.2"},
				"ECDHE-ECDSA-AES128-GCM-SHA256"),
			wantProtocols: []string{"TLS 1.1", "TLS 1.2"},
			wantMin:       "TLS 1.1",
			wantMax:       "TLS 1.2",
		},
		{
			name: "ELBSecurityPolicy-TLS-1-2-2017-01 is TLS 1.2 only",
			policy: sslPolicy("ELBSecurityPolicy-TLS-1-2-2017-01",
				[]string{"TLSv1.2"},
				"ECDHE-ECDSA-AES128-GCM-SHA256"),
			wantProtocols: []string{"TLS 1.2"},
			wantMin:       "TLS 1.2",
			wantMax:       "TLS 1.2",
		},
		{
			name: "ELBSecurityPolicy-TLS13-1-2-2021-06 permits TLS 1.2 and 1.3",
			policy: sslPolicy("ELBSecurityPolicy-TLS13-1-2-2021-06",
				[]string{"TLSv1.2", "TLSv1.3"},
				"TLS_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"),
			wantProtocols: []string{"TLS 1.2", "TLS 1.3"},
			wantMin:       "TLS 1.2",
			wantMax:       "TLS 1.3",
		},
		{
			name: "ELBSecurityPolicy-TLS13-1-3-2021-06 is TLS 1.3 only",
			policy: sslPolicy("ELBSecurityPolicy-TLS13-1-3-2021-06",
				[]string{"TLSv1.3"},
				"TLS_AES_128_GCM_SHA256"),
			wantProtocols: []string{"TLS 1.3"},
			wantMin:       "TLS 1.3",
			wantMax:       "TLS 1.3",
		},
		{
			// AWS returns protocols unordered in principle; output must be
			// deterministic weakest-first regardless of input order.
			name: "protocol ordering is normalised, not input-dependent",
			policy: sslPolicy("ELBSecurityPolicy-Reordered",
				[]string{"TLSv1.3", "TLSv1", "TLSv1.2", "TLSv1.1"},
				"ECDHE-ECDSA-AES128-GCM-SHA256"),
			wantProtocols: []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"},
			wantMin:       "TLS 1.0",
			wantMax:       "TLS 1.3",
		},
		{
			// A policy with ciphers but no protocols must report NOTHING.
			// This is the exact shape the old code fabricated TLS 1.2/1.3 for.
			name: "ciphers without protocols fabricate nothing",
			policy: sslPolicy("ELBSecurityPolicy-NoProtocolsReported",
				nil,
				"ECDHE-ECDSA-AES128-GCM-SHA256", "AES128-SHA"),
			wantProtocols: []string{},
			wantMin:       "",
			wantMax:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := sslPolicyDetailsFromPolicy(tt.policy)

			got, ok := details["protocols"].([]string)
			if !ok {
				t.Fatalf("protocols missing or wrong type: %#v", details["protocols"])
			}
			if !reflect.DeepEqual(got, tt.wantProtocols) {
				t.Fatalf("protocols = %v, want %v", got, tt.wantProtocols)
			}

			gotMin, _ := details["min_protocol_version"].(string)
			if gotMin != tt.wantMin {
				t.Errorf("min_protocol_version = %q, want %q", gotMin, tt.wantMin)
			}
			gotMax, _ := details["max_protocol_version"].(string)
			if gotMax != tt.wantMax {
				t.Errorf("max_protocol_version = %q, want %q", gotMax, tt.wantMax)
			}

			// Raw values are always preserved verbatim so a future AWS
			// spelling we do not recognise is still visible in the metadata.
			raw, _ := details["protocols_raw"].([]string)
			if len(raw) != len(tt.policy.SslProtocols) {
				t.Errorf("protocols_raw = %v, want %v", raw, tt.policy.SslProtocols)
			}
		})
	}
}

// TestSSLPolicyDetails_WeakPolicyIsReportedWeak is the security assertion, kept
// separate so it reads as what it is: the legacy policy must produce a
// protocol_version that isWeakProtocol/hasWeakTLSVersion will flag.
func TestSSLPolicyDetails_WeakPolicyIsReportedWeak(t *testing.T) {
	details := sslPolicyDetailsFromPolicy(sslPolicy(
		"ELBSecurityPolicy-TLS-1-0-2015-04",
		[]string{"TLSv1", "TLSv1.1", "TLSv1.2"},
		"ECDHE-ECDSA-AES128-GCM-SHA256"))

	protocols := details["protocols"].([]string)
	weakest := weakestTLSVersion(protocols)
	if weakest != "TLS 1.0" {
		t.Fatalf("weakest permitted version = %q, want %q — a TLS 1.0 listener "+
			"reported as anything stronger cannot be scored as weak", weakest, "TLS 1.0")
	}

	sawWeak := false
	for _, p := range protocols {
		if p == "TLS 1.0" || p == "TLS 1.1" {
			sawWeak = true
		}
	}
	if !sawWeak {
		t.Fatal("tls_versions for a TLS-1.0 policy contains no weak version; " +
			"inventory-service hasWeakTLSVersion would never flag it")
	}
}

func TestNormalizeTLSVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// ELBv2 SslPolicy.SslProtocols
		{"TLSv1", "TLS 1.0"},
		{"TLSv1.1", "TLS 1.1"},
		{"TLSv1.2", "TLS 1.2"},
		{"TLSv1.3", "TLS 1.3"},
		// CloudFront MinimumProtocolVersion (policy vintage suffix stripped)
		{"SSLv3", "SSL 3.0"},
		{"TLSv1_2016", "TLS 1.0"},
		{"TLSv1.1_2016", "TLS 1.1"},
		{"TLSv1.2_2018", "TLS 1.2"},
		{"TLSv1.2_2019", "TLS 1.2"},
		{"TLSv1.2_2021", "TLS 1.2"},
		{"TLSv1.2_2025", "TLS 1.2"},
		{"TLSv1.3_2025", "TLS 1.3"},
		// API Gateway v2 SecurityPolicy — underscore form, no year suffix
		{"TLS_1_0", "TLS 1.0"},
		{"TLS_1_2", "TLS 1.2"},
		// Already-canonical input is idempotent
		{"TLS 1.2", "TLS 1.2"},
		// Unrecognised => "" (NOT DETERMINED), never a default
		{"", ""},
		{"   ", ""},
		{"QUIC", ""},
		{"TLSv9", ""},
	}
	for _, tt := range tests {
		if got := normalizeTLSVersion(tt.in); got != tt.want {
			t.Errorf("normalizeTLSVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeTLSVersion_MatchesHandshakeSpelling(t *testing.T) {
	// TLSHandshakeService writes exactly these strings into protocol_version.
	// If this drifts, the same endpoint gets two different spellings depending
	// on which path discovered it.
	for _, want := range []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
		if got := normalizeTLSVersion(want); got != want {
			t.Errorf("normalizeTLSVersion(%q) = %q; canonical pipeline spelling must round-trip", want, got)
		}
	}
}

func TestWeakestTLSVersion(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"weakest of a mixed set", []string{"TLS 1.2", "TLS 1.0", "TLS 1.3"}, "TLS 1.0"},
		{"single", []string{"TLS 1.3"}, "TLS 1.3"},
		{"ssl beats tls", []string{"TLS 1.2", "SSL 3.0"}, "SSL 3.0"},
		{"none recognised", []string{"QUIC", ""}, ""},
		{"empty", nil, ""},
		{"unrecognised entries ignored", []string{"QUIC", "TLS 1.1"}, "TLS 1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := weakestTLSVersion(tt.in); got != tt.want {
				t.Errorf("weakestTLSVersion(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDedupeSortTLSVersions(t *testing.T) {
	got := dedupeSortTLSVersions([]string{"TLS 1.2", "TLS 1.0", "TLS 1.2", "QUIC", "TLS 1.1"})
	want := []string{"TLS 1.0", "TLS 1.1", "TLS 1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupeSortTLSVersions = %v, want %v", got, want)
	}
}

func TestTLSVersionsAtLeast(t *testing.T) {
	// API Gateway / CloudFront report a FLOOR. The legacy tail below the
	// modern versions is exactly what makes a "TLS_1_0" domain risky, so the
	// floor must expand to a set that still contains TLS 1.0.
	got := tlsVersionsAtLeast("TLS 1.0")
	want := []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tlsVersionsAtLeast(TLS 1.0) = %v, want %v", got, want)
	}

	got = tlsVersionsAtLeast("TLS 1.2")
	want = []string{"TLS 1.2", "TLS 1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tlsVersionsAtLeast(TLS 1.2) = %v, want %v", got, want)
	}

	if got := tlsVersionsAtLeast("nonsense"); got != nil {
		t.Fatalf("tlsVersionsAtLeast(nonsense) = %v, want nil", got)
	}
}
