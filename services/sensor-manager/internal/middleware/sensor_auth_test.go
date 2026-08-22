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
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/lib/pq"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TestSensorAuth_FailClosed_NoClientCert is the core regression test for
// sensors: with mTLS enforcement on, a request that presents no client cert
// must be rejected 401 before any sensor work — it must not fall through to
// "allow". A non-nil DB handle (never connected) is supplied so the
// misconfiguration guard passes; the 401 is returned before any query runs.
func TestSensorAuth_FailClosed_NoClientCert(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// sql.Open does not establish a connection; the fail-closed no-cert path
	// returns before the handle is ever used.
	db, err := sql.Open("postgres", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	r := gin.New()
	g := r.Group("/sensors")
	g.Use(SensorAuth(db, db, "test-key", true)) // require mTLS
	g.GET("/:sensor_id/heartbeat", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	// httptest request has no TLS peer cert.
	req := httptest.NewRequest(http.MethodGet, "/sensors/"+uuid.New().String()+"/heartbeat", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (fail closed), got %d", w.Code)
	}
}

// TestSensorAuth_Legacy_NoCertAllowed confirms the opt-out path: with mTLS
// enforcement off, a request with no client cert is still allowed (preserving
// dev/compose behavior). Uses an invalid sensor_id so the handler is reached
// only if auth passes; here we assert the 400 for bad UUID is independent, so
// we use a valid UUID and a nil DB (legacy path tolerates it).
func TestSensorAuth_Legacy_NoCertAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	g := r.Group("/sensors")
	g.Use(SensorAuth(nil, nil, "", false)) // mTLS NOT enforced, no DB
	g.GET("/:sensor_id/heartbeat", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sensors/"+uuid.New().String()+"/heartbeat", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (legacy allow), got %d", w.Code)
	}
}

func TestSensorAuth_AcceptsCurrentClientCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	tenantID := uuid.New()
	sensorID := uuid.New()
	caPEM, leaf := testSensorClientCert(t, sensorID.String(), big.NewInt(333))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID.String()))

	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New().String(), tenantID.String(), caPEM, "encrypted", int64(1), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()

	bypassMock.ExpectQuery(`SELECT id, sensor_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM sensor_certificates\s+WHERE sensor_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "sensor_id", "tenant_id", "certificate_pem", "serial_number", "issued_at", "expires_at", "revoked_at", "revocation_reason", "created_at",
		}).AddRow(uuid.New().String(), sensorID.String(), tenantID.String(), "active-cert", leaf.SerialNumber.String(), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil, nil, time.Now()))

	r := gin.New()
	g := r.Group("/sensors")
	g.Use(SensorAuth(db, bypassDB, "test-key", true))
	g.GET("/:sensor_id/heartbeat", func(c *gin.Context) {
		gotTenantID, ok := c.Get("tenantID")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "tenantID missing"})
			return
		}
		if gotTenantID != tenantID {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "tenantID mismatch"})
			return
		}
		c.Status(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sensors/"+sensorID.String()+"/heartbeat", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for current client certificate, got %d: %s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestSensorAuth_RejectsMissingActiveCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	tenantID := uuid.New()
	sensorID := uuid.New()
	caPEM, leaf := testSensorClientCert(t, sensorID.String(), big.NewInt(444))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID.String()))

	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New().String(), tenantID.String(), caPEM, "encrypted", int64(1), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()

	bypassMock.ExpectQuery(`SELECT id, sensor_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM sensor_certificates\s+WHERE sensor_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(sensorID).
		WillReturnError(sql.ErrNoRows)

	r := gin.New()
	g := r.Group("/sensors")
	g.Use(SensorAuth(db, bypassDB, "test-key", true))
	g.GET("/:sensor_id/heartbeat", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sensors/"+sensorID.String()+"/heartbeat", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing active certificate, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not active") {
		t.Fatalf("response = %s, want not-active error", w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestSensorAuth_RejectsStaleClientCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, dbMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	tenantID := uuid.New()
	sensorID := uuid.New()
	caPEM, leaf := testSensorClientCert(t, sensorID.String(), big.NewInt(111))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID.String()))

	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New().String(), tenantID.String(), caPEM, "encrypted", int64(1), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true))
	dbMock.ExpectCommit()

	bypassMock.ExpectQuery(`SELECT id, sensor_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM sensor_certificates\s+WHERE sensor_id = \$1 AND revoked_at IS NULL\s+ORDER BY issued_at DESC\s+LIMIT 1`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "sensor_id", "tenant_id", "certificate_pem", "serial_number", "issued_at", "expires_at", "revoked_at", "revocation_reason", "created_at",
		}).AddRow(uuid.New().String(), sensorID.String(), tenantID.String(), "active-cert", "222", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil, nil, time.Now()))

	r := gin.New()
	g := r.Group("/sensors")
	g.Use(SensorAuth(db, bypassDB, "test-key", true))
	g.GET("/:sensor_id/heartbeat", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sensors/"+sensorID.String()+"/heartbeat", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale client certificate, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not the active certificate") {
		t.Fatalf("response = %s, want active-certificate error", w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func testSensorClientCert(t *testing.T, commonName string, serial *big.Int) (string, *x509.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tenant sensor CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return string(caPEM), leaf
}
