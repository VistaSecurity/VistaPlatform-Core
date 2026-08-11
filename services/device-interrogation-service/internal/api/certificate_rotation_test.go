package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestRotateAgentCertificate_InvalidID: a malformed agent id is rejected 400 by
// the handler's own resolver before any DB access — mounted without AgentAuth so
// this exercises resolveAgentOutboundTenant directly.
func TestRotateAgentCertificate_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	r := gin.New()
	r.POST("/agents/:id/certificates/rotate", rotateAgentCertificateHandler(db, db))

	req := httptest.NewRequest(http.MethodPost, "/agents/not-a-uuid/certificates/rotate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestRotateAgentCertificate_UnknownAgent: in fail-open mode (no AgentAuth
// context tenant) the handler resolves the owning tenant from the agent row; an
// unknown agent id must be 404, not a 500 or a cross-tenant issue.
func TestRotateAgentCertificate_UnknownAgent(t *testing.T) {
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
	r.POST("/agents/:id/certificates/rotate", rotateAgentCertificateHandler(db, db))

	req := httptest.NewRequest(http.MethodPost, "/agents/"+agentID.String()+"/certificates/rotate", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d (body=%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// generateAgentCSR builds an RSA keypair + CSR with CN == agentID, as the
// device-agent does during renewal.
func generateAgentCSR(t *testing.T, agentID uuid.UUID) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID.String()}}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestIntegration_RotateAgentCertificate_IssuesAndSupersedes drives the real
// rotation endpoint (with AgentAuth in front, fail-open) against Postgres: it
// issues a client cert bound to the agent, and a second rotation supersedes the
// first so exactly one active row remains. This is the fix — before it the
// route 404'd and the agent's enrollment cert could expire with no path to renew.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_RotateAgentCertificate_IssuesAndSupersedes(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-encryption-master-key-32byte")
	db := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, db)

	agentID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status)
		 VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active')`,
		agentID, tenantID, "regkey-"+agentID.String(),
	); err != nil {
		t.Fatalf("insert device_agent: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/agents")
	g.Use(middleware.AgentAuth(db, db, false)) // fail-open: resolves tenant from the agent row
	g.POST("/:id/certificates/rotate", rotateAgentCertificateHandler(db, db))

	rotate := func() rotateAgentCertificateResponse {
		body, _ := json.Marshal(rotateAgentCertificateRequest{CSR: generateAgentCSR(t, agentID)})
		req := httptest.NewRequest(http.MethodPost, "/agents/"+agentID.String()+"/certificates/rotate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("rotate: expected 200, got %d (body=%s)", w.Code, w.Body.String())
		}
		var resp rotateAgentCertificateResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	first := rotate()
	if first.ClientCert == "" {
		t.Fatal("first rotation returned empty client_cert")
	}
	// The issued cert must be a real cert whose CN is the agent id.
	block, _ := pem.Decode([]byte(first.ClientCert))
	if block == nil {
		t.Fatal("client_cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if cert.Subject.CommonName != agentID.String() {
		t.Errorf("issued cert CN = %q, want %q", cert.Subject.CommonName, agentID.String())
	}
	if !first.CertificateExpiresAt.After(time.Now()) {
		t.Errorf("certificate_expires_at %v is not in the future", first.CertificateExpiresAt)
	}

	// Second rotation must supersede the first: exactly one unrevoked row.
	_ = rotate()
	var active int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM agent_certificates WHERE agent_id = $1 AND revoked_at IS NULL`,
		agentID,
	).Scan(&active); err != nil {
		t.Fatalf("count active certs: %v", err)
	}
	if active != 1 {
		t.Errorf("expected exactly 1 active cert after two rotations, got %d", active)
	}
}
