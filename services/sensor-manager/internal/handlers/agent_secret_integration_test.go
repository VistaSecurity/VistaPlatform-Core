package handlers

//: a sensor is issued a per-sensor secret at enrolment and a fresh one at
// each certificate rotation, so it no longer has to keep its single-use
// registration key. These drive the REAL registration handler against Postgres
// and the REAL rotation handler behind SensorAuth, so deleting the issue call in
// either — or the response field — fails here.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/middleware"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/agentsecret"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const sensorSecretMasterKey = "sensor-secret-test-master-key-0123456789"

func sensorSecretCipher(t *testing.T) *credentials.Cipher {
	t.Helper()
	c, err := credentials.NewCipher("test", sensorSecretMasterKey, credentials.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sensorCSR(t *testing.T, sensorID uuid.UUID) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: sensorID.String()}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type sensorSecretEnv struct {
	db     *sql.DB
	tenant uuid.UUID
	router *gin.Engine
}

func newSensorSecretEnv(t *testing.T) *sensorSecretEnv {
	t.Helper()
	db := testdb.Connect(t)
	gin.SetMode(gin.TestMode)
	h := NewHandler(services.NewSensorService(db, db))
	h.SetEncryptionKey(sensorSecretMasterKey)
	r := gin.New()
	r.POST("/api/v1/sensor-manager/sensors/register", h.RegisterSensor)
	g := r.Group("/api/v1/sensor-manager/sensors/:sensor_id")
	g.Use(middleware.SensorAuth(db, db, sensorSecretMasterKey, false))
	g.POST("/certificates/rotate", h.RotateSensorCertificate)
	tenant := testdb.NewTenant(t, db)
	// Enrolment is gated on the tenant's sensor cap; a tier-less tenant has none.
	if _, err := db.Exec(`UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'enterprise') WHERE id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	return &sensorSecretEnv{db: db, tenant: tenant, router: r}
}

type sensorEnrolResult struct {
	SensorID           string `json:"sensor_id"`
	ClientCert         string `json:"client_cert"`
	AgentSecret        string `json:"agent_secret"`
	AgentSecretVersion int    `json:"agent_secret_version"`
}

func (e *sensorSecretEnv) enrol(t *testing.T, supports bool) sensorEnrolResult {
	t.Helper()
	key := "REG-" + uuid.NewString()
	if _, err := e.db.Exec(`
		INSERT INTO pending_sensor_registrations
		       (tenant_id, registration_key, name, ip_address, profile, status, expires_at)
		VALUES ($1,$2,'secret-sensor','192.0.2.41','datacenter_host','pending',$3)`,
		e.tenant, key, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sensorID := uuid.New()
	body, _ := json.Marshal(map[string]any{
		"registration_key":      key,
		"name":                  "secret-sensor",
		"platform":              "linux",
		"version":               "test",
		"profile":               "datacenter_host",
		"network_interfaces":    []string{"eth0"},
		"sensor_id":             sensorID.String(),
		"csr":                   sensorCSR(t, sensorID),
		"supports_agent_secret": supports,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor-manager/sensors/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var res sensorEnrolResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = e.db.Exec(`DELETE FROM sensor_certificates WHERE sensor_id = $1`, res.SensorID)
		_, _ = e.db.Exec(`DELETE FROM sensors WHERE id = $1`, res.SensorID)
		_, _ = e.db.Exec(`DELETE FROM pending_sensor_registrations WHERE registration_key = $1`, key)
	})
	return res
}

func (e *sensorSecretEnv) stored(t *testing.T, sensorID string) (sql.NullString, int) {
	t.Helper()
	var enc sql.NullString
	var v int
	if err := e.db.QueryRow(`SELECT agent_secret_enc, agent_secret_version FROM sensors WHERE id = $1`, sensorID).Scan(&enc, &v); err != nil {
		t.Fatal(err)
	}
	return enc, v
}

func (e *sensorSecretEnv) rotate(t *testing.T, res sensorEnrolResult, supports bool) sensorEnrolResult {
	t.Helper()
	id := uuid.MustParse(res.SensorID)
	block, _ := pem.Decode([]byte(res.ClientCert))
	peer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(RotateCertificateRequest{CSR: sensorCSR(t, id), SupportsAgentSecret: supports})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensor-manager/sensors/"+res.SensorID+"/certificates/rotate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	var out sensorEnrolResult
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	out.SensorID = res.SensorID
	return out
}

func TestIntegration_SensorAgentSecret_IssuedAtEnrolmentStoredWrapped(t *testing.T) {
	e := newSensorSecretEnv(t)
	res := e.enrol(t, true)

	raw, err := base64.StdEncoding.DecodeString(res.AgentSecret)
	if err != nil || len(raw) != agentcreds.SecretBytes {
		t.Fatalf("agent_secret = %q (err %v), want %d base64 bytes", res.AgentSecret, err, agentcreds.SecretBytes)
	}
	if res.AgentSecretVersion != 1 {
		t.Fatalf("agent_secret_version = %d, want 1", res.AgentSecretVersion)
	}
	enc, v := e.stored(t, res.SensorID)
	if v != 1 || !enc.Valid || strings.Contains(enc.String, res.AgentSecret) {
		t.Fatalf("stored = %+v v%d, want a wrapped (not plaintext) secret at v1", enc, v)
	}
	// The platform can recover exactly what the sensor was given.
	got, err := agentsecret.Unwrap(sensorSecretCipher(t), enc.String)
	if err != nil || got != res.AgentSecret {
		t.Fatalf("Unwrap = %q, %v; want the issued secret", got, err)
	}
}

func TestIntegration_SensorAgentSecret_OldSensorIsIssuedNothing(t *testing.T) {
	e := newSensorSecretEnv(t)
	res := e.enrol(t, false)
	if res.AgentSecret != "" || res.AgentSecretVersion != 0 {
		t.Fatalf("a sensor that did not ask received %+v", res)
	}
	if enc, v := e.stored(t, res.SensorID); v != 0 || enc.Valid {
		t.Fatalf("stored = %+v v%d, want none", enc, v)
	}
}

func TestIntegration_SensorAgentSecret_RotationIssuesANewOneAndMigratesOldSensors(t *testing.T) {
	e := newSensorSecretEnv(t)

	// A sensor enrolled before secrets existed receives its first at rotation.
	old := e.enrol(t, false)
	first := e.rotate(t, old, true)
	if first.AgentSecret == "" || first.AgentSecretVersion != 1 {
		t.Fatalf("migration rotation = %+v, want a v1 secret", first)
	}

	// And every later rotation replaces it.
	second := e.rotate(t, first, true)
	if second.AgentSecret == "" || second.AgentSecret == first.AgentSecret || second.AgentSecretVersion != 2 {
		t.Fatalf("second rotation = %+v, want a new secret at v2", second)
	}
	enc, v := e.stored(t, old.SensorID)
	if got, err := agentsecret.Unwrap(sensorSecretCipher(t), enc.String); v != 2 || err != nil || got != second.AgentSecret {
		t.Fatalf("stored v%d unwraps to %q (%v), want the second secret", v, got, err)
	}

	// A rotation that does not ask leaves the secret alone.
	third := e.rotate(t, second, false)
	if third.AgentSecret != "" {
		t.Fatalf("rotation without supports_agent_secret returned a secret")
	}
	if _, v := e.stored(t, old.SensorID); v != 2 {
		t.Fatalf("version = %d after a rotation that asked for nothing, want 2", v)
	}
}
