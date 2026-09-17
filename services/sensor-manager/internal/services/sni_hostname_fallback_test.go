package services

// sniHostnameFromRawMetadata backs StoreDiscoveries' hostname fallback: when
// the sensor sent no hostname (neither the wire's `hostname` field nor
// raw_metadata["hostname"]), the TLS SNI captured off the ClientHello is the
// next-best measured fact — often the ONLY name a third-party endpoint with
// no PTR record will ever get. See CLAUDE.md "The discovery metadata
// envelope: empty never wins" for why this fallback chain matters and
// docsv4 root CLAUDE.md's SNI defect writeup for the reported symptom
// (bare IP:port rows in the 3rd Party lens for connections whose SNI the
// sensor did capture).

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

func TestSniHostnameFromRawMetadata(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{
			name: "sni is the first-class key",
			raw:  map[string]interface{}{"sni": "settings-win.data.microsoft.com"},
			want: "settings-win.data.microsoft.com",
		},
		{
			name: "sni_server_name is checked when sni is absent (STARTTLS sessions only emit this spelling)",
			raw:  map[string]interface{}{"sni_server_name": "smtp.example.com"},
			want: "smtp.example.com",
		},
		{
			name: "sni wins over sni_server_name when both are present",
			raw: map[string]interface{}{
				"sni":             "canonical.example.com",
				"sni_server_name": "canonical.example.com",
			},
			want: "canonical.example.com",
		},
		{
			name: "mixed case is lower-cased",
			raw:  map[string]interface{}{"sni": "API.Example.COM"},
			want: "api.example.com",
		},
		{
			name: "surrounding whitespace is trimmed",
			raw:  map[string]interface{}{"sni": "  padded.example.com  "},
			want: "padded.example.com",
		},
		{
			name: "an IPv4 literal in the SNI field is not a hostname",
			raw:  map[string]interface{}{"sni": "203.0.113.40"},
			want: "",
		},
		{
			name: "an IPv6 literal in the SNI field is not a hostname",
			raw:  map[string]interface{}{"sni": "2001:db8::1"},
			want: "",
		},
		{
			name: "empty sni falls through to sni_server_name",
			raw: map[string]interface{}{
				"sni":             "",
				"sni_server_name": "fallback.example.com",
			},
			want: "fallback.example.com",
		},
		{
			name: "no sni keys at all",
			raw:  map[string]interface{}{"cipher_suite": "TLS_AES_128_GCM_SHA256"},
			want: "",
		},
		{
			name: "nil metadata",
			raw:  nil,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sniHostnameFromRawMetadata(tc.raw); got != tc.want {
				t.Errorf("sniHostnameFromRawMetadata(%v) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestStoreDiscoveries_HostnameColumn_FallsBackToSNI is the producer-side
// pin: a discovery with no sensor-reported hostname but a captured SNI must
// land in sensor_discoveries.hostname with the SNI value — not NULL.
func TestStoreDiscoveries_HostnameColumn_FallsBackToSNI(t *testing.T) {
	tenantID := uuid.New()
	sensorID := uuid.New()
	svc, mock, captured := newStoreMock(t, tenantID, sensorID)

	batch := &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   uuid.New(),
		Timestamp: time.Now(),
		Discoveries: []models.SensorDiscoveryInput{{
			Protocol:        "TLS",
			SourceIP:        "192.0.2.5",
			DestIP:          "203.0.113.40",
			Port:            443,
			Version:         "TLS 1.3",
			CipherSuite:     "TLS_AES_128_GCM_SHA256",
			DiscoveryMethod: "passive",
			// Hostname deliberately unset — a passive TLS 1.3 capture has no
			// separate hostname field, only what the ClientHello's SNI extension
			// carried.
			RawMetadata: map[string]interface{}{"sni": "settings-win.data.microsoft.com"},
		}},
	}

	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	args := (*captured)[0]
	if got := args[12]; got != "settings-win.data.microsoft.com" {
		t.Errorf("hostname = %v, want the SNI captured in raw_metadata", got)
	}
}

// TestStoreDiscoveries_HostnameColumn_IgnoresIPLiteralSNI pins that an SNI
// carrying an IP literal (not a valid identity per RFC 6066, but not
// impossible from a malformed or hostile ClientHello) never lands in the
// hostname column — the column NULL means "no name known" is preferable to a
// bare address duplicating dest_ip.
func TestStoreDiscoveries_HostnameColumn_IgnoresIPLiteralSNI(t *testing.T) {
	tenantID := uuid.New()
	sensorID := uuid.New()
	svc, mock, captured := newStoreMock(t, tenantID, sensorID)

	batch := &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   uuid.New(),
		Timestamp: time.Now(),
		Discoveries: []models.SensorDiscoveryInput{{
			Protocol:        "TLS",
			SourceIP:        "192.0.2.5",
			DestIP:          "203.0.113.41",
			Port:            443,
			DiscoveryMethod: "passive",
			RawMetadata:     map[string]interface{}{"sni": "203.0.113.41"},
		}},
	}

	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	args := (*captured)[0]
	if got := args[12]; got != nil {
		t.Errorf("hostname = %v, want NULL — an IP literal is not a hostname", got)
	}
}

// TestStoreDiscoveries_HostnameColumn_ExplicitHostnameBeatsSNI pins that the
// SNI fallback never overrides a hostname the sensor actually reported.
func TestStoreDiscoveries_HostnameColumn_ExplicitHostnameBeatsSNI(t *testing.T) {
	tenantID := uuid.New()
	sensorID := uuid.New()
	svc, mock, captured := newStoreMock(t, tenantID, sensorID)

	batch := &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   uuid.New(),
		Timestamp: time.Now(),
		Discoveries: []models.SensorDiscoveryInput{{
			Protocol:        "TLS",
			SourceIP:        "192.0.2.5",
			DestIP:          "203.0.113.42",
			Port:            443,
			Hostname:        "reported.example.com",
			DiscoveryMethod: "passive",
			RawMetadata:     map[string]interface{}{"sni": "sni-name.example.com"},
		}},
	}

	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	args := (*captured)[0]
	if got := args[12]; got != "reported.example.com" {
		t.Errorf("hostname = %v, want the sensor-reported name, not the SNI fallback", got)
	}
}
