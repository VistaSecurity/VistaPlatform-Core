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

func TestIntegration_ExternalStrength_HTTPIngestAndFilters(t *testing.T) {
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
	r.GET(extConnBase, h.ListExternalConnections)
	testdb.WithSchemaShareLock(t, raw, func() {
		for _, body := range []string{
			`{"source_ip":"192.0.2.16","dest_ip":"198.51.100.16","dest_port":443,"protocol":"TLS","cipher_suite":"TLS_AES_256_GCM_SHA384","cert_public_key_algorithm":"RSA","cert_public_key_size":1024}`,
			`{"source_ip":"192.0.2.16","dest_ip":"198.51.100.16","dest_port":443,"protocol":"TLS","cipher_suite":"TLS_AES_256_GCM_SHA384"}`,
		} {
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
			if conn.Strength == nil || *conn.Strength != "weak" {
				t.Fatalf("HTTP partial ingest lost weakness: %s", res.Body.String())
			}
			if bytes.Contains(res.Body.Bytes(), []byte(`"crypto_strength"`)) {
				t.Fatal("legacy wire field escaped")
			}
		}
		for _, query := range []string{"strength=weak", "strength=acceptable", "strength=strong", "strength=recommended", "strength=unassessed"} {
			res := httptest.NewRecorder()
			r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, extConnBase+"?"+query, nil))
			if res.Code != 200 {
				t.Fatalf("canonical filter %s: %d %s", query, res.Code, res.Body.String())
			}
		}
		for _, query := range []string{"strength=good", "strength=unknown", "crypto_strength=weak", "crypto_strength=", "sort_by=crypto_strength"} {
			res := httptest.NewRecorder()
			r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, extConnBase+"?"+query, nil))
			if res.Code != 400 {
				t.Fatalf("legacy/invalid filter %s accepted: %d", query, res.Code)
			}
		}
	})
}
