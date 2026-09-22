package handlers

// H4 regression tests: certificate rotation must require proof that the caller
// already holds the sensor's CURRENT identity, not merely a path UUID.
//
// These drive the REAL middleware chain (middleware.SensorAuth) in front of the
// REAL handler, in both AGENT_MTLS_REQUIRED modes, because the bug was that the
// route inherited SensorAuth's fail-open posture. Testing the proof helper in
// isolation would stay green if the handler stopped calling it.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/middleware"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

const rotateTestMasterKey = "test-master-key"

// newRotateEngine wires the production middleware in front of the production
// handler exactly as cmd/main.go does for the sensor outbound group.
func newRotateEngine(requireMTLS bool, h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/sensor-manager/sensors/:sensor_id")
	grp.Use(middleware.SensorAuth(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), rotateTestMasterKey, requireMTLS))
	grp.POST("/certificates/rotate", h.RotateSensorCertificate)
	return r
}

func rotateHandler(legacy *stubLegacySensorService) *Handler {
	return &Handler{
		sensorService: legacy,
		repo:          &stubSensorRepo{getSensor: sampleConfigSensor()},
		encryptionKey: rotateTestMasterKey,
		log:           logrus.New(),
	}
}

// TestRotate_RefusedWithoutClientCertificate_FailOpenMode is the core H4 test.
// With AGENT_MTLS_REQUIRED off — the shipped chart default before this change —
// SensorAuth admits a request whose only credential is the path UUID. Rotation
// must still refuse it, and must say what to do about it.
func TestRotate_RefusedWithoutClientCertificate_FailOpenMode(t *testing.T) {
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

	sensorID := uuid.New()
	// Fail-open mode: the handler resolves the owning tenant from the path id.
	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(testTenantID))

	h := rotateHandler(&stubLegacySensorService{getSensor: sampleConfigSensor(), db: db, bypassDB: bypassDB})
	eng := newRotateEngine(false, h)

	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+sensorID.String()+"/certificates/rotate",
		strings.NewReader(`{"csr":"`+testCSRPEMEscaped(t, sensorID)+`"}`))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (rotation without identity proof); body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// The failure must be actionable, not a bare 401.
	for _, want := range []string{"current client certificate", "agentMtls.enabled=true", "re-enrolled"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s does not mention %q", body, want)
		}
	}
	// No certificate was issued: every remaining expectation must be unmet only
	// because nothing else ran.
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

// TestRotate_RefusedWithForeignCertificate: holding SOME valid sensor cert must
// not let you rotate a DIFFERENT sensor's identity.
func TestRotate_RefusedWithForeignCertificate(t *testing.T) {
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock db: %v", err)
	}
	defer func() { _ = db.Close() }()
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	victimID := uuid.New()
	attackerID := uuid.New()
	_, _, _, attackerLeaf := testSensorCAWithLeaf(t, attackerID, big.NewInt(4242))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(victimID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(testTenantID))

	h := rotateHandler(&stubLegacySensorService{getSensor: sampleConfigSensor(), db: db, bypassDB: bypassDB})
	eng := newRotateEngine(false, h)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/sensor-manager/sensors/"+victimID.String()+"/certificates/rotate",
		strings.NewReader(`{"csr":"`+testCSRPEMEscaped(t, victimID)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{attackerLeaf}}
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a foreign certificate; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not this sensor's current certificate") {
		t.Fatalf("response = %s, want current-certificate error", w.Body.String())
	}
}

// TestRotate_RefusedWithSupersededCertificate: a certificate that still chains
// to the tenant CA but is no longer the active serial must not rotate.
func TestRotate_RefusedWithSupersededCertificate(t *testing.T) {
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

	sensorID := uuid.New()
	caID, caPEM, encKey, leaf := testSensorCAWithLeaf(t, sensorID, big.NewInt(111))

	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(testTenantID))
	expectActiveCA(dbMock, testTenantID, caID, caPEM, encKey)
	expectActiveSensorCert(bypassMock, sensorID, "999") // active serial != presented serial

	h := rotateHandler(&stubLegacySensorService{getSensor: sampleConfigSensor(), db: db, bypassDB: bypassDB})
	eng := newRotateEngine(false, h)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/sensor-manager/sensors/"+sensorID.String()+"/certificates/rotate",
		strings.NewReader(`{"csr":"`+testCSRPEMEscaped(t, sensorID)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a superseded certificate; body=%s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

// TestRotate_AllowedWithCurrentCertificate proves the guard is not a blanket
// deny: the genuine sensor, presenting its current certificate through the
// enforced-mTLS path, still rotates successfully.
func TestRotate_AllowedWithCurrentCertificate(t *testing.T) {
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

	sensorID := uuid.New()
	caID, caPEM, encKey, leaf := testSensorCAWithLeaf(t, sensorID, big.NewInt(777))
	serial := leaf.SerialNumber.String()

	// SensorAuth (enforced mTLS): tenant lookup, CA chain, active-cert binding.
	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(testTenantID))
	expectActiveCA(dbMock, testTenantID, caID, caPEM, encKey)
	expectActiveSensorCert(bypassMock, sensorID, serial)
	// Handler identity-proof guard: CA chain + active-cert binding again.
	expectActiveCA(dbMock, testTenantID, caID, caPEM, encKey)
	expectActiveSensorCert(bypassMock, sensorID, serial)
	// Handler: CA for the response, then IssueCertificate (CA + CA key + sensor
	// existence probe + store), then supersede older certs.
	expectActiveCA(dbMock, testTenantID, caID, caPEM, encKey)
	expectActiveCA(dbMock, testTenantID, caID, caPEM, encKey)
	bypassMock.ExpectQuery(`SELECT ca_key_pem_encrypted\s+FROM sensor_ca_certificates\s+WHERE id = \$1`).
		WithArgs(caID).
		WillReturnRows(sqlmock.NewRows([]string{"ca_key_pem_encrypted"}).AddRow(encKey))
	bypassMock.ExpectQuery(`SELECT id FROM sensors WHERE id = \$1`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(sensorID))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(testTenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectExec(`INSERT INTO sensor_certificates`).
		WithArgs(sensorID, testTenantID, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectCommit()
	bypassMock.ExpectExec(`UPDATE sensor_certificates`).
		WithArgs("rotated", sensorID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	h := rotateHandler(&stubLegacySensorService{getSensor: sampleConfigSensor(), db: db, bypassDB: bypassDB})
	eng := newRotateEngine(true, h)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/sensor-manager/sensors/"+sensorID.String()+"/certificates/rotate",
		strings.NewReader(`{"csr":"`+testCSRPEMEscaped(t, sensorID)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the genuine sensor; body=%s", w.Code, w.Body.String())
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

// --- helpers -----------------------------------------------------------------

func expectActiveSensorCert(mock sqlmock.Sqlmock, sensorID uuid.UUID, serial string) {
	mock.ExpectQuery(`SELECT id, sensor_id, tenant_id, certificate_pem, serial_number,\s+issued_at, expires_at, revoked_at, revocation_reason, created_at\s+FROM sensor_certificates`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "sensor_id", "tenant_id", "certificate_pem", "serial_number",
			"issued_at", "expires_at", "revoked_at", "revocation_reason", "created_at",
		}).AddRow(uuid.New(), sensorID, testTenantID, "cert-pem", serial,
			time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil, nil, time.Now()))
}

// testSensorCAWithLeaf builds a tenant sensor CA (with its encrypted key, so
// IssueCertificate can sign with it) plus a client leaf for commonName.
func testSensorCAWithLeaf(t *testing.T, sensorID uuid.UUID, serial *big.Int) (uuid.UUID, string, string, *x509.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test tenant sensor CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	encService, err := encryption.NewService(rotateTestMasterKey)
	if err != nil {
		t.Fatalf("encryption service: %v", err)
	}
	encryptedKey, err := encService.Encrypt(string(keyPEM))
	if err != nil {
		t.Fatalf("encrypt CA key: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sensorID.String()},
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

	return uuid.New(), string(caPEM), encryptedKey, leaf
}

// testCSRPEMEscaped returns a valid CSR for sensorID, JSON-string escaped.
func testCSRPEMEscaped(t *testing.T, sensorID uuid.UUID) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: sensorID.String()},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return strings.ReplaceAll(string(csrPEM), "\n", "\\n")
}
