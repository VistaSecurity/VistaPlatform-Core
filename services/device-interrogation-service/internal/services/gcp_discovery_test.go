package services

import (
	"testing"

	gcp "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

func TestBuildGCPTLSConfig(t *testing.T) {
	tests := []struct {
		name           string
		policy         *gcp.SSLPolicy
		wantProtocol   string
		wantVersion    string
		wantHasCiphers bool
	}{
		{
			name: "MODERN profile with TLS 1.2",
			policy: &gcp.SSLPolicy{
				Name:          "modern-policy",
				Profile:       "MODERN",
				MinTLSVersion: "TLS_1_2",
				EnabledFeatures: []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				},
			},
			wantProtocol:   "HTTPS",
			wantVersion:    "TLS 1.2",
			wantHasCiphers: true,
		},
		{
			name: "RESTRICTED profile",
			policy: &gcp.SSLPolicy{
				Name:          "restricted-policy",
				Profile:       "RESTRICTED",
				MinTLSVersion: "TLS_1_2",
				EnabledFeatures: []string{
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				},
			},
			wantProtocol:   "HTTPS",
			wantVersion:    "TLS 1.2",
			wantHasCiphers: true,
		},
		{
			name: "CUSTOM profile with custom features",
			policy: &gcp.SSLPolicy{
				Name:          "custom-policy",
				Profile:       "CUSTOM",
				MinTLSVersion: "TLS_1_2",
				CustomFeatures: []string{
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				},
			},
			wantProtocol:   "HTTPS",
			wantVersion:    "TLS 1.2",
			wantHasCiphers: true,
		},
		{
			name: "COMPATIBLE profile with TLS 1.0",
			policy: &gcp.SSLPolicy{
				Name:          "compatible-policy",
				Profile:       "COMPATIBLE",
				MinTLSVersion: "TLS_1_0",
			},
			wantProtocol:   "HTTPS",
			wantVersion:    "TLS 1.0",
			wantHasCiphers: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGCPTLSConfig(tt.policy, tt.wantProtocol)

			if result["protocol"] != tt.wantProtocol {
				t.Errorf("protocol = %v, want %v", result["protocol"], tt.wantProtocol)
			}
			if result["protocol_version"] != tt.wantVersion {
				t.Errorf("protocol_version = %v, want %v", result["protocol_version"], tt.wantVersion)
			}
			if result["port"] != 443 {
				t.Errorf("port = %v, want 443", result["port"])
			}

			_, hasCiphers := result["cipher_suites"]
			if hasCiphers != tt.wantHasCiphers {
				t.Errorf("has cipher_suites = %v, want %v", hasCiphers, tt.wantHasCiphers)
			}

			meta, ok := result["metadata"].(map[string]interface{})
			if !ok {
				t.Fatal("metadata is not a map")
			}
			if meta["ssl_policy"] != tt.policy.Name {
				t.Errorf("metadata.ssl_policy = %v, want %v", meta["ssl_policy"], tt.policy.Name)
			}
			if meta["ssl_policy_profile"] != tt.policy.Profile {
				t.Errorf("metadata.ssl_policy_profile = %v, want %v", meta["ssl_policy_profile"], tt.policy.Profile)
			}
		})
	}
}
