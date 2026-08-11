package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestAgentAuth_InvalidUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, db, false))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/not-a-uuid/jobs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestAgentAuth_FailClosed_NoClientCert is the core regression test: with
// mTLS enforcement on, a request that presents no client cert must be rejected
// 401 BEFORE any DB lookup — it must not fall through to "allow".
func TestAgentAuth_FailClosed_NoClientCert(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, db, true)) // require mTLS
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	// httptest request has no TLS peer cert.
	req := httptest.NewRequest(http.MethodGet, "/agents/"+uuid.New().String()+"/jobs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (fail closed), got %d", w.Code)
	}
	// No DB query should have been issued — the cert check precedes the lookup.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentAuth_FailClosed_CNMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	agentID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: uuid.NewString()},
		}},
	}

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, db, true))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentAuth_AgentNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	agentID := uuid.New()
	mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnError(sql.ErrNoRows)

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, db, false))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentAuth_ServiceMeshPeerCertIgnoredWhenAgentMTLSOff(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, db, false))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: "api-gateway"},
		}},
	}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentAuth_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, db, false))
	g.GET("/:id/jobs", func(c *gin.Context) {
		tid, exists := c.Get("tenantID")
		if !exists {
			t.Fatal("expected tenantID in context")
		}
		if tid != tenantID {
			t.Fatalf("tenantID mismatch: %v vs %v", tid, tenantID)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentAuth_RequiredMTLSAcceptsActiveCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bypassDB.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	caPEM, leaf, leafPEM := makeAgentCertFixture(t, agentID, big.NewInt(1001))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New(), tenantID, caPEM, "encrypted", int64(1), time.Now(), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()
	bypassMock.ExpectQuery(`SELECT id, agent_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM agent_certificates\s+WHERE agent_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "agent_id", "tenant_id", "certificate_pem", "serial_number", "issued_at", "expires_at", "revoked_at", "revocation_reason", "created_at",
		}).AddRow(uuid.New(), agentID, tenantID, leafPEM, leaf.SerialNumber.String(), time.Now(), leaf.NotAfter, nil, nil, time.Now()))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, bypassDB, true))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestAgentAuth_RequiredMTLSBackfillsLegacyCertificateWithoutHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bypassDB.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	caPEM, leaf, _ := makeAgentCertFixture(t, agentID, big.NewInt(1001))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New(), tenantID, caPEM, "encrypted", int64(1), time.Now(), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()
	bypassMock.ExpectQuery(`SELECT id, agent_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM agent_certificates\s+WHERE agent_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(agentID).
		WillReturnError(sql.ErrNoRows)
	bypassMock.ExpectQuery(`SELECT EXISTS \(\s+SELECT 1\s+FROM agent_certificates\s+WHERE agent_id = \$1\s+\)`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectExec(`INSERT INTO agent_certificates`).
		WithArgs(agentID, tenantID, sqlmock.AnyArg(), leaf.SerialNumber.String(), leaf.NotBefore, leaf.NotAfter).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectExec(`UPDATE agent_certificates\s+SET revoked_at = NOW\(\),\s+revocation_reason = 'superseded',\s+updated_at = NOW\(\)\s+WHERE agent_id = \$1\s+AND tenant_id = \$2\s+AND revoked_at IS NULL\s+AND serial_number <> \$3`).
		WithArgs(agentID, tenantID, leaf.SerialNumber.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	dbMock.ExpectCommit()

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, bypassDB, true))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestAgentAuth_RequiredMTLSRejectsMissingActiveCertificateWithHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bypassDB.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	caPEM, leaf, _ := makeAgentCertFixture(t, agentID, big.NewInt(1001))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New(), tenantID, caPEM, "encrypted", int64(1), time.Now(), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()
	bypassMock.ExpectQuery(`SELECT id, agent_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM agent_certificates\s+WHERE agent_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(agentID).
		WillReturnError(sql.ErrNoRows)
	bypassMock.ExpectQuery(`SELECT EXISTS \(\s+SELECT 1\s+FROM agent_certificates\s+WHERE agent_id = \$1\s+\)`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, bypassDB, true))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body=%s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestAgentAuth_RequiredMTLSRejectsSupersededCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bypassDB.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	caPEM, leaf, leafPEM := makeAgentCertFixture(t, agentID, big.NewInt(1001))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New(), tenantID, caPEM, "encrypted", int64(1), time.Now(), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()
	bypassMock.ExpectQuery(`SELECT id, agent_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM agent_certificates\s+WHERE agent_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "agent_id", "tenant_id", "certificate_pem", "serial_number", "issued_at", "expires_at", "revoked_at", "revocation_reason", "created_at",
		}).AddRow(uuid.New(), agentID, tenantID, leafPEM, "1002", time.Now(), leaf.NotAfter, nil, nil, time.Now()))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(AgentAuth(db, bypassDB, true))
	g.GET("/:id/jobs", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body=%s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func makeAgentCertFixture(t *testing.T, agentID uuid.UUID, leafSerial *big.Int) (string, *x509.Certificate, string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName: agentID.String(),
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	return string(caPEM), leaf, string(leafPEM)
}
