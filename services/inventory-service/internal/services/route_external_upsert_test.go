package services

import (
	"encoding/json"
	"errors"
	"testing"
)

// The one external-connections writer carries the full certificate-quality
// set ( WP3, F16). discovery-processor's own writer used to carry it and
// this one did not; with the processor's writer gone, a flag dropped here is
// dropped everywhere. external_connections persists most of these through
// weak_reasons / cert_hygiene_flags, so the integration test asserts the
// stored effect and this one asserts every field of the upsert itself —
// cert_is_ev included, which has no column to read back.

// routeThirdPartyFinding is a third-party TLS finding as the import handler
// decodes it: raw_data round-tripped through JSON, so numbers and bools have
// the wire shapes.
func routeThirdPartyFinding(t *testing.T, raw map[string]interface{}) IngestFinding {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	host, ip, port, version, suite := "api.vendor.example", "203.0.113.80", 443, "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	return IngestFinding{Hostname: &host, IPAddress: &ip, Port: &port, Protocol: "TLS",
		ProtocolVersion: &version, CipherSuite: &suite, RawData: decoded}
}

func routeQualityRawData() map[string]interface{} {
	return map[string]interface{}{
		"source_ip":                 "10.1.2.3",
		"dest_hostname_source_kind": "inferred",
		"certificates": []interface{}{
			map[string]interface{}{"chain_order": 1, "subject_dn": "CN=Intermediate", "issuer_dn": "CN=Root", "fingerprint_sha256": "bb", "serial_number": "2"},
			map[string]interface{}{"chain_order": 0, "subject_dn": "CN=api.vendor.example", "issuer_dn": "CN=Intermediate", "fingerprint_sha256": "aa", "serial_number": "1"},
		},
		"cert_validation_status": "expired",
		"cert_has_sct":           false,
		"cert_sct_source":        "none",
		"cert_known_bad_ca":      "Superfish",
		"cert_no_common_name":    true,
		"cert_is_ev":             true,
		"cert_large_san_count":   120,
		"ocsp_status":            "revoked",
	}
}

func TestRouteExternalUpsert_CarriesEveryQualityFlag(t *testing.T) {
	s := &AssetService{}
	u, err := s.externalConnectionUpsert(routeThirdPartyFinding(t, routeQualityRawData()))
	if err != nil {
		t.Fatalf("externalConnectionUpsert: %v", err)
	}
	if u.SourceIP != "10.1.2.3" {
		t.Errorf("SourceIP = %q, want the measured source", u.SourceIP)
	}
	if u.CertHasSCT == nil || *u.CertHasSCT {
		t.Errorf("CertHasSCT = %v, want an explicit false — false is an answer", u.CertHasSCT)
	}
	if u.CertSCTSource == nil || *u.CertSCTSource != "none" {
		t.Errorf("CertSCTSource = %v", u.CertSCTSource)
	}
	if u.CertKnownBadCA == nil || *u.CertKnownBadCA != "Superfish" {
		t.Errorf("CertKnownBadCA = %v", u.CertKnownBadCA)
	}
	if !u.CertIsEV {
		t.Error("CertIsEV lost")
	}
	if !u.CertNoCommonName {
		t.Error("CertNoCommonName lost")
	}
	if u.CertLargeSANCount == nil || *u.CertLargeSANCount != 120 {
		t.Errorf("CertLargeSANCount = %v", u.CertLargeSANCount)
	}
	if u.OCSPStatus == nil || *u.OCSPStatus != "revoked" {
		t.Errorf("OCSPStatus = %v", u.OCSPStatus)
	}
	if u.CertValidationStatus == nil || *u.CertValidationStatus != "expired" {
		t.Errorf("CertValidationStatus = %v", u.CertValidationStatus)
	}
	if u.CertFingerprintSHA256 == nil || *u.CertFingerprintSHA256 != "aa" {
		t.Errorf("leaf fingerprint = %v, want the chain_order 0 certificate's", u.CertFingerprintSHA256)
	}
	if u.DestHostname == nil || *u.DestHostname != "api.vendor.example" ||
		u.DestHostnameSourceKind == nil || *u.DestHostnameSourceKind != "inferred" {
		t.Errorf("dest hostname/provenance = %v/%v", u.DestHostname, u.DestHostnameSourceKind)
	}
}

// The other polarity: a discovery that measured nothing states nothing. A
// writer that defaulted the flags would pass the test above.
func TestRouteExternalUpsert_UnmeasuredFlagsStayAbsent(t *testing.T) {
	s := &AssetService{}
	u, err := s.externalConnectionUpsert(routeThirdPartyFinding(t, map[string]interface{}{"source_ip": "10.1.2.3"}))
	if err != nil {
		t.Fatalf("externalConnectionUpsert: %v", err)
	}
	if u.CertHasSCT != nil || u.CertKnownBadCA != nil || u.OCSPStatus != nil || u.CertValidationStatus != nil || u.CertIsEV {
		t.Fatalf("flags invented for a discovery that carried none: %+v", u)
	}
}

// D2: no source, no connection — and never the 0.0.0.0 that used to fill the
// upsert key.
func TestRouteExternalUpsert_NoSourceAddressIsRefused(t *testing.T) {
	s := &AssetService{}
	for name, raw := range map[string]map[string]interface{}{
		"absent": {},
		"empty":  {"source_ip": ""},
		"blank":  {"source_ip": "  "},
	} {
		t.Run(name, func(t *testing.T) {
			u, err := s.externalConnectionUpsert(routeThirdPartyFinding(t, raw))
			if !errors.Is(err, errThirdPartyNoSourceIP) {
				t.Fatalf("err = %v (source %q), want errThirdPartyNoSourceIP", err, u.SourceIP)
			}
		})
	}
}

// A passive capture's suite label under key_exchange_algorithm still reaches
// the connection when the finding names no measured exchange — what the
// processor's deleted writer stored; a measured exchange on the finding wins.
func TestRouteExternalUpsert_KeyExchangeLabelFallback(t *testing.T) {
	s := &AssetService{}
	f := routeThirdPartyFinding(t, map[string]interface{}{"source_ip": "10.1.2.3", "key_exchange_algorithm": "DHE_RSA"})
	u, err := s.externalConnectionUpsert(f)
	if err != nil {
		t.Fatal(err)
	}
	if u.KeyExchangeAlgorithm == nil || *u.KeyExchangeAlgorithm != "DHE_RSA" {
		t.Fatalf("KeyExchangeAlgorithm = %v, want the passive label DHE_RSA", u.KeyExchangeAlgorithm)
	}
	measured := "X25519"
	f.KeyExchangeAlgorithm = &measured
	if u, _ = s.externalConnectionUpsert(f); u.KeyExchangeAlgorithm == nil || *u.KeyExchangeAlgorithm != "X25519" {
		t.Fatalf("KeyExchangeAlgorithm = %v, want the finding's measured X25519", u.KeyExchangeAlgorithm)
	}
}
