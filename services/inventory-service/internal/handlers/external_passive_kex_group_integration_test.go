package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Every passively observed ECDHE connection used to stay unrated: the rating
// is withheld while an elliptic-curve or finite-field exchange has no measured
// size, and nothing on the passive path supplied one. The sensor now reports
// the group the server selected and its size, and these bodies are what
// discovery-processor posts for such an observation. They go through the real
// HTTP ingest and catalogue, so a rating here is one the catalogue produced.
//
// The other half matters as much: with no group and no size the connection
// must STAY unrated. An unknown size is not a strong one.
func TestIntegration_ExternalStrength_PassiveKeyExchangeGroupCompletesRating(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := services.NewExternalConnectionsService(db, services.NewAlgorithmService(db))
	h := NewExternalConnectionsHandler(svc)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	r.POST(extConnBase, h.UpsertExternalConnection)

	post := func(t *testing.T, body string) models.ExternalConnection {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, extConnBase, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		r.ServeHTTP(res, req)
		if res.Code != 200 {
			t.Fatalf("POST %d %s", res.Code, res.Body.String())
		}
		var conn models.ExternalConnection
		if e := json.Unmarshal(res.Body.Bytes(), &conn); e != nil {
			t.Fatal(e)
		}
		return conn
	}

	const leaf = `"cert_subject":"CN=example.com","cert_fingerprint_sha256":"leaf","cert_public_key_algorithm":"RSA","cert_public_key_size":2048,"cert_signature_algorithm":"SHA256-RSA"`
	testdb.WithSchemaShareLock(t, raw, func() {
		for _, c := range []struct {
			name, body string
			rated      bool
		}{
			{"TLS 1.3 with the key_share group", `{"source_ip":"192.0.2.31","dest_ip":"198.51.100.31","dest_port":443,"protocol":"TLS","protocol_version":"TLS 1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","key_exchange_algorithm":"X25519","key_size":256}`, true},
			{"TLS 1.2 ECDHE with the ServerKeyExchange curve", `{"source_ip":"192.0.2.31","dest_ip":"198.51.100.32","dest_port":443,"protocol":"TLS","protocol_version":"TLS 1.2","cipher_suite":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","key_exchange_algorithm":"DH-ECP-256","key_size":256,` + leaf + `}`, true},
			{"TLS 1.3, no group seen", `{"source_ip":"192.0.2.31","dest_ip":"198.51.100.33","dest_port":443,"protocol":"TLS","protocol_version":"TLS 1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}`, false},
			{"TLS 1.2 ECDHE, group named but no size", `{"source_ip":"192.0.2.31","dest_ip":"198.51.100.35","dest_port":443,"protocol":"TLS","protocol_version":"TLS 1.2","cipher_suite":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","key_exchange_algorithm":"DH-ECP-256",` + leaf + `}`, false},
			{"TLS 1.2 ECDHE, suite label only", `{"source_ip":"192.0.2.31","dest_ip":"198.51.100.34","dest_port":443,"protocol":"TLS","protocol_version":"TLS 1.2","cipher_suite":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","key_exchange_algorithm":"ECDHE_RSA",` + leaf + `}`, false},
		} {
			t.Run(c.name, func(t *testing.T) {
				conn := post(t, c.body)
				switch {
				case c.rated && (conn.Strength == nil || *conn.Strength == "" || *conn.Strength == "weak"):
					t.Fatalf("strength = %v (reasons %v), want a non-weak catalogue rating", conn.Strength, conn.WeakReasons)
				case !c.rated && conn.Strength != nil:
					t.Fatalf("strength = %q with no exchange size, want unrated", *conn.Strength)
				}
			})
		}
	})
}
