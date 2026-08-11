package handlers

// Contract test for the sensor certificate-management surface (Sensor detail →
// certificates). Extends the sensor-manager spec-first contract (ADR-0001) and
// reuses the shared harness (loadSpec / assertConforms / do / aUUID /
// testTenantID) + the legacy-service stub (stubLegacySensorService) from
// sensor_config_contract_test.go.
//
// RegenerateSensorCertificates is fully covered — it uses the legacy service
// (GetSensor/UpdateSensor) plus in-process x509/rsa cert generation, no DB. The
// other three (revoke / rotate / get-certificate) construct a DB-backed
// CertificateService inline from sensorService.GetDB(), so their CA-dependent
// success paths are integration territory; here we contract-test the
// request-validation paths that return before the cert service is built.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

func newSensorCertEngine(legacy *stubLegacySensorService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// The tenant-ownership guard resolves the sensor via h.repo before
	// any cert op. Mirror the legacy stub's intent into the repo: a not-found
	// signal becomes a tenant-scoped miss (404); otherwise the guard sees a
	// present sensor so the handler runs.
	repoSensor := legacy.getSensor
	if repoSensor == nil && legacy.getSensorErr == nil {
		repoSensor = sampleConfigSensor()
	}
	h := &Handler{
		sensorService: legacy,
		repo:          &stubSensorRepo{getSensor: repoSensor, forTenantErr: legacy.getSensorErr},
		encryptionKey: "test-master-key",
		log:           logrus.New(),
	}
	grp := r.Group("/api/v1/sensor-manager")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.POST("/sensors/:sensor_id/regenerate-certificates", h.RegenerateSensorCertificates)
	grp.POST("/sensors/:sensor_id/certificates/revoke", h.RevokeSensorCertificate)
	grp.POST("/sensors/:sensor_id/certificates/rotate", h.RotateSensorCertificate)
	grp.GET("/sensors/:sensor_id/certificate", h.GetSensorCertificate)
	return r
}

// --- POST /sensors/{id}/regenerate-certificates (fully covered) --------------

func TestContract_RegenerateSensorCertificates_200(t *testing.T) {
	sv := loadSpec(t)
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

	sensor := sampleConfigSensor()
	caID, caPEM, encryptedCAKey := testEncryptedSensorCA(t, testTenantID, "test-master-key")

	expectActiveCA(dbMock, testTenantID, caID, caPEM, encryptedCAKey)
	expectActiveCA(dbMock, testTenantID, caID, caPEM, encryptedCAKey)
	bypassMock.ExpectQuery(`SELECT ca_key_pem_encrypted\s+FROM sensor_ca_certificates\s+WHERE id = \$1`).
		WithArgs(caID).
		WillReturnRows(sqlmock.NewRows([]string{"ca_key_pem_encrypted"}).AddRow(encryptedCAKey))
	bypassMock.ExpectQuery(`SELECT id FROM sensors WHERE id = \$1`).
		WithArgs(sensor.ID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(sensor.ID))
	dbMock.ExpectBegin()
	dbMock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(testTenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectExec(`INSERT INTO sensor_certificates`).
		WithArgs(sensor.ID, testTenantID, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	dbMock.ExpectCommit()
	bypassMock.ExpectExec(`UPDATE sensor_certificates\s+SET revoked_at = NOW\(\), revocation_reason = \$1\s+WHERE sensor_id = \$2\s+AND serial_number <> \$3\s+AND revoked_at IS NULL`).
		WithArgs("manual", sensor.ID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	eng := newSensorCertEngine(&stubLegacySensorService{
		getSensor: sensor,
		db:        db,
		bypassDB:  bypassDB,
	})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+aUUID+"/regenerate-certificates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RegenerateCertificatesResponse", w.Body.Bytes())

	var resp RegenerateCertificatesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	verifyCertSignedByCA(t, resp.ClientCert, caPEM)
	if resp.ClientKey == "" {
		t.Fatal("client key is empty")
	}
	if err := dbMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("db expectations: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestContract_RegenerateSensorCertificates_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/not-a-uuid/regenerate-certificates", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RegenerateSensorCertificates_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{getSensorErr: sql.ErrNoRows})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+aUUID+"/regenerate-certificates", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RegenerateSensorCertificates_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{getSensor: sampleConfigSensor(), updateErr: sql.ErrConnDone})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+aUUID+"/regenerate-certificates", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /sensors/{id}/certificates/revoke (validation paths) ---------------

func TestContract_RevokeSensorCertificate_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/not-a-uuid/certificates/revoke", strings.NewReader(`{"reason":"manual"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RevokeSensorCertificate_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+aUUID+"/certificates/revoke", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RevokeSensorCertificate_400_invalidReason(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+aUUID+"/certificates/revoke", strings.NewReader(`{"reason":"whatever"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /sensors/{id}/certificates/rotate (validation paths) ---------------

func TestContract_RotateSensorCertificate_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/not-a-uuid/certificates/rotate", strings.NewReader(`{"csr":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RotateSensorCertificate_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodPost, "/api/v1/sensor-manager/sensors/"+aUUID+"/certificates/rotate", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Note: rotate's "sensor not found -> 404" path moved to integration coverage
// (TestIntegration_RequireSensorOutboundAccess). Since, rotation is the
// sensor's own autonomous renewal under SensorAuth — it resolves the owning
// tenant from the sensor row on the bypass DB (fail-open) or the cert-derived
// context tenant (mTLS), not from the tenant-JWT repo guard — so the not-found
// path is DB-backed and can't be exercised with the stub harness here.

// --- GET /sensors/{id}/certificate (validation path) ------------------------

func TestContract_GetSensorCertificate_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorCertEngine(&stubLegacySensorService{})
	w := do(eng, http.MethodGet, "/api/v1/sensor-manager/sensors/not-a-uuid/certificate", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func expectActiveCA(mock sqlmock.Sqlmock, tenantID, caID uuid.UUID, caPEM, encryptedKey string) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,\s+created_at, expires_at, is_active\s+FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(caID, tenantID, caPEM, encryptedKey, int64(1), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true))
	mock.ExpectCommit()
}

func testEncryptedSensorCA(t *testing.T, tenantID uuid.UUID, masterKey string) (uuid.UUID, string, string) {
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
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		t.Fatalf("encryption service: %v", err)
	}
	encryptedKey, err := encService.Encrypt(string(keyPEM))
	if err != nil {
		t.Fatalf("encrypt CA key: %v", err)
	}

	return uuid.New(), string(caPEM), encryptedKey
}

func verifyCertSignedByCA(t *testing.T, certPEM, caPEM string) {
	t.Helper()

	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		t.Fatal("failed to decode client certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse client certificate: %v", err)
	}
	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		t.Fatal("failed to decode CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client certificate does not verify against tenant CA: %v", err)
	}
}
