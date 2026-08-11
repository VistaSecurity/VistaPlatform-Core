package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClassifyRisk_TLSv12_NotMisclassifiedAsTLS11(t *testing.T) {
	s := &CryptoRisksService{}
	vers := []string{"TLSv1.2", "TLSV1.2", "TLS 1.2"}
	for _, v := range vers {
		t.Run(v, func(t *testing.T) {
			r := &CryptoRisk{ID: uuid.New()}
			cipher := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
			hash := "SHA384"
			ks := 4096
			s.classifyRisk(r, &v, &cipher, &hash, nil, &ks, nil)
			if r.IssueType == "deprecated_protocol" {
				t.Fatalf("protocol %q misclassified as deprecated TLS 1.1: %+v", v, r)
			}
		})
	}
}

func TestClassifyRisk_TLSv13_NotMisclassifiedAsTLS11(t *testing.T) {
	s := &CryptoRisksService{}
	v := "TLSv1.3"
	r := &CryptoRisk{ID: uuid.New()}
	cipher := "TLS_AES_256_GCM_SHA384"
	hash := "SHA384"
	ks := 4096
	s.classifyRisk(r, &v, &cipher, &hash, nil, &ks, nil)
	if r.IssueType == "deprecated_protocol" {
		t.Fatalf("TLSv1.3 misclassified as deprecated TLS 1.1: %+v", r)
	}
}

func TestClassifyRisk_TLSv11_StillDeprecatedProtocol(t *testing.T) {
	s := &CryptoRisksService{}
	v := "TLSv1.1"
	r := &CryptoRisk{ID: uuid.New()}
	cipher := "TLS_RSA_WITH_AES_128_CBC_SHA"
	hash := "SHA1"
	ks := 2048
	s.classifyRisk(r, &v, &cipher, &hash, nil, &ks, nil)
	if r.Severity != "high" || r.IssueType != "deprecated_protocol" {
		t.Fatalf("expected high deprecated_protocol for TLSv1.1, got %+v", r)
	}
}

func TestClassifyRisk_3DES_HighNotWeakCipherCritical(t *testing.T) {
	s := &CryptoRisksService{}
	v := "TLSv1.2"
	cipher := "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	hash := "SHA1"
	ks := 2048
	r := &CryptoRisk{ID: uuid.New()}
	s.classifyRisk(r, &v, &cipher, &hash, nil, &ks, nil)
	if r.IssueType != "deprecated_cipher" || r.Severity != "high" {
		t.Fatalf("expected high deprecated_cipher for 3DES, got %+v", r)
	}
}

func TestClassifyRisk_ExpiringCert_Medium(t *testing.T) {
	s := &CryptoRisksService{}
	v := "TLSv1.3"
	cipher := "TLS_AES_256_GCM_SHA384"
	hash := "SHA384"
	ks := 4096
	exp := time.Now().Add(10 * 24 * time.Hour)
	r := &CryptoRisk{ID: uuid.New()}
	s.classifyRisk(r, &v, &cipher, &hash, nil, &ks, &exp)
	if r.Severity != "medium" || r.IssueType != "expiring_certificate" {
		t.Fatalf("expected medium expiring_certificate, got %+v", r)
	}
}
