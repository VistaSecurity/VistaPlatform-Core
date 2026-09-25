package services

// A real cloud collector path — discoverCloudFrontDistributions against a stub
// CloudFront API, recording into a real database — carries the handshake's
// key-exchange measurement into the device's crypto config. The six collector
// sites are held to the same wiring by TestCloudHandshakeSitesApplyKeyExchange.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// stubCloudFront answers ListDistributions with one HTTPS distribution and
// every other call (the per-distribution config interrogation) with
// NoSuchDistribution, which the collector logs and carries on past.
func stubCloudFront(t *testing.T, distID, domain string) *awsclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/distribution") {
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>1</Quantity>
  <Items><DistributionSummary>
    <Id>` + distID + `</Id>
    <ARN>arn:aws:cloudfront::123456789012:distribution/` + distID + `</ARN>
    <Status>Deployed</Status>
    <DomainName>` + domain + `</DomainName>
    <Enabled>true</Enabled>
    <Aliases><Quantity>0</Quantity></Aliases>
    <DefaultCacheBehavior><TargetOriginId>origin</TargetOriginId><ViewerProtocolPolicy>redirect-to-https</ViewerProtocolPolicy></DefaultCacheBehavior>
  </DistributionSummary></Items>
</DistributionList>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchDistribution</Code><Message>not found</Message></Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)
	cfg := awssdk.Config{
		Region:           "us-east-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIAEXAMPLEEXAMPLE00", "not-a-real-secret", ""),
		BaseEndpoint:     awssdk.String(srv.URL),
		RetryMaxAttempts: 1,
		HTTPClient:       srv.Client(),
	}
	return awsclient.NewClientFromConfig(cfg, "123456789012", "us-east-1")
}

func TestIntegration_CloudFrontCollector_CarriesTLSKeyExchange(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)

	c := tlskextest.Cases[0] // X25519MLKEM768 only
	fixture := tlskextest.Start(t, c.Groups, c.MaxVersion)
	distID := "E2EXAMPLE" + strings.ToUpper(uuid.New().String()[:6])
	domain := "d111111abcdef8.cloudfront.net"

	// Point the collector's handshake at the loopback fixture, keeping the
	// distribution's name as SNI — the same shape as production, minus DNS.
	var gotHost string
	var gotPort int
	prev := cloudTLSHandshake
	cloudTLSHandshake = func(ctx context.Context, host string, port int) (*TLSHandshakeResult, error) {
		gotHost, gotPort = host, port
		return NewTLSHandshakeService(3*time.Second).handshakeTo(ctx, host, fixture.Addr)
	}
	t.Cleanup(func() { cloudTLSHandshake = prev })

	devices, err := svc.discoverCloudFrontDistributions(context.Background(), tenantID, stubCloudFront(t, distID, domain))
	if err != nil {
		t.Fatalf("discoverCloudFrontDistributions: %v", err)
	}
	if gotHost != domain || gotPort != 443 {
		t.Errorf("handshake target = %s:%d, want %s:443", gotHost, gotPort, domain)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	configs := extractCryptoConfigs(devices[0].Metadata)
	var handshake map[string]interface{}
	for _, cfg := range configs {
		if cfg["handshake_verified"] == true {
			handshake = cfg
		}
	}
	if handshake == nil {
		t.Fatalf("no handshake crypto config in %v", configs)
	}
	if handshake["key_exchange_algorithm"] != c.WantGroup {
		t.Errorf("key_exchange_algorithm = %v, want %q", handshake["key_exchange_algorithm"], c.WantGroup)
	}
	if handshake["tls_supports_pqc_hybrid_kex"] != true || handshake["tls_supports_classical_kex"] != false {
		t.Errorf("support flags = %v / %v, want classical=false hybrid=true",
			handshake["tls_supports_classical_kex"], handshake["tls_supports_pqc_hybrid_kex"])
	}
	tlskextest.CheckConnections(t, c, fixture)
}
