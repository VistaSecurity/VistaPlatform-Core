package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/middleware"
)

// H4 regression tests for the device-agent rotation endpoint: rotation must
// require proof that the caller already holds the agent's CURRENT identity, not
// merely a path UUID (or an X-Agent-ID header). Driven through the REAL
// AgentAuth middleware in fail-open mode — the mode the shipped chart selected
// by default — because the bug was that the route inherited that posture.

func rotateRequest(t *testing.T, agentID uuid.UUID) string {
	t.Helper()
	body, err := json.Marshal(rotateAgentCertificateRequest{CSR: generateAgentCSR(t, agentID)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

func TestRotateAgentCertificate_RefusedWithoutClientCertificate(t *testing.T) {
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
	g.Use(middleware.AgentAuth(db, db, false)) // fail-open, as the chart default shipped
	g.POST("/:id/certificates/rotate", rotateAgentCertificateHandler(db, db))

	req := httptest.NewRequest(http.MethodPost, "/agents/"+agentID.String()+"/certificates/rotate",
		strings.NewReader(rotateRequest(t, agentID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for rotation without identity proof, got %d (body=%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"current client certificate", "agentMtls.enabled=true", "re-enrolled"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s does not mention %q", body, want)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAgentCertificate_RefusedWithForeignCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	victimID := uuid.New()
	attackerID := uuid.New()
	tenantID := uuid.New()
	_, attackerLeaf := testAgentCAWithLeaf(t, attackerID, big.NewInt(4242))

	mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(victimID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(middleware.AgentAuth(db, db, false))
	g.POST("/:id/certificates/rotate", rotateAgentCertificateHandler(db, db))

	req := httptest.NewRequest(http.MethodPost, "/agents/"+victimID.String()+"/certificates/rotate",
		strings.NewReader(rotateRequest(t, victimID)))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{attackerLeaf}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a foreign certificate, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not this agent's current certificate") {
		t.Fatalf("response = %s, want current-certificate error", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAgentCertificate_RefusedWithSupersededCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	agentID := uuid.New()
	tenantID := uuid.New()
	caPEM, leaf := testAgentCAWithLeaf(t, agentID, big.NewInt(111))

	mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	// Guard: tenant CA lookup (RLS tx), then the active-certificate binding.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM sensor_ca_certificates`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "ca_cert_pem", "ca_key_pem_encrypted", "serial_number", "created_at", "expires_at", "is_active",
		}).AddRow(uuid.New(), tenantID, caPEM, "enc", int64(1), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true))
	mock.ExpectCommit()
	mock.ExpectQuery(`FROM agent_certificates`).
		WithArgs(agentID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "agent_id", "tenant_id", "certificate_pem", "serial_number",
			"issued_at", "expires_at", "revoked_at", "revocation_reason", "created_at",
		}).AddRow(uuid.New(), agentID, tenantID, "cert-pem", "999",
			time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil, nil, time.Now()))

	r := gin.New()
	g := r.Group("/agents")
	g.Use(middleware.AgentAuth(db, db, false))
	g.POST("/:id/certificates/rotate", rotateAgentCertificateHandler(db, db))

	req := httptest.NewRequest(http.MethodPost, "/agents/"+agentID.String()+"/certificates/rotate",
		strings.NewReader(rotateRequest(t, agentID)))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a superseded certificate, got %d (body=%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// testAgentCAWithLeaf returns (CA cert PEM, client leaf for agentID).
func testAgentCAWithLeaf(t *testing.T, agentID uuid.UUID, serial *big.Int) (string, *x509.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test tenant agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID.String()},
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), leaf
}
