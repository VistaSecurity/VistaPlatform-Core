package api

//: a device agent's credential key is rooted in a per-agent secret the
// platform issues at enrolment and at each certificate rotation, not in the
// single-use registration key. These tests drive the REAL handlers — the public
// registration route, the job-poll route and the rotation route, with AgentAuth
// in front of the last — so deleting the wiring in any of them (the response
// field, the seal-time lookup, the rotation issue) fails here.
//
// Skip without TEST_DATABASE_URL and a reachable Redis (make test-integration-db).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/certificates"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const agentSecretTestMasterKey = "agent-secret-test-master-key-0123456789"

type agentSecretEnv struct {
	owner  *sql.DB
	tenant uuid.UUID
	router *gin.Engine
	rdb    *redis.Client
}

func newAgentSecretEnv(t *testing.T) *agentSecretEnv {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	addr := os.Getenv("REDIS_URL")
	if addr == "" {
		addr = "localhost:6379"
	}
	opts, err := redis.ParseURL(addr)
	if err != nil {
		opts = &redis.Options{Addr: addr}
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis unreachable at %s: %v", addr, err)
	}
	t.Setenv("ENCRYPTION_MASTER_KEY", agentSecretTestMasterKey)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/agents/register", registerAgentPublicHandler(app, owner, nil))
	r.GET("/agents/:id/jobs", getAgentJobsHandler(app, owner, rdb))
	g := r.Group("/agents")
	g.Use(middleware.AgentAuth(owner, owner, false))
	g.POST("/:id/certificates/rotate", rotateAgentCertificateHandler(owner, owner))

	return &agentSecretEnv{owner: owner, tenant: testdb.NewTenant(t, owner), router: r, rdb: rdb}
}

type enrolResult struct {
	AgentID            uuid.UUID `json:"agent_id"`
	ClientCert         string    `json:"client_cert"`
	AgentSecret        string    `json:"agent_secret"`
	AgentSecretVersion int       `json:"agent_secret_version"`
}

func (e *agentSecretEnv) enrol(t *testing.T, supports bool) (enrolResult, string) {
	t.Helper()
	key := "REG-" + uuid.NewString()
	if _, err := e.owner.Exec(`
		INSERT INTO pending_sensor_registrations
		       (tenant_id, registration_key, name, ip_address, profile, status, expires_at)
		VALUES ($1,$2,'secret-agent','192.0.2.31','device_interrogation','pending',$3)`,
		e.tenant, key, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.New()
	body, _ := json.Marshal(map[string]any{
		"registration_key":      key,
		"platform":              "linux",
		"version":               "test",
		"agent_id":              agentID.String(),
		"csr":                   generateAgentCSR(t, agentID),
		"supports_agent_secret": supports,
	})
	req := httptest.NewRequest(http.MethodPost, "/agents/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var res enrolResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = e.owner.Exec(`DELETE FROM device_jobs WHERE agent_id = $1`, res.AgentID)
		_, _ = e.owner.Exec(`DELETE FROM device_agents WHERE id = $1`, res.AgentID)
		_, _ = e.owner.Exec(`DELETE FROM pending_sensor_registrations WHERE registration_key = $1`, key)
		_ = e.rdb.Del(context.Background(), "device_agent:capabilities:"+res.AgentID.String()).Err()
	})
	return res, key
}

// jobEnvelope queues a job with plaintext stored credentials for the agent, polls
// it through the real route and returns the credentials exactly as the agent
// receives them, with the job id.
func (e *agentSecretEnv) jobEnvelope(t *testing.T, agentID uuid.UUID, password string) (map[string]interface{}, string) {
	t.Helper()
	jobID := uuid.New()
	if _, err := e.owner.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, status, parameters, credentials, expires_at)
		VALUES ($1, $2, 'device_discovery', $3, 'pending', '{"device_type":"fortinet","management_url":"https://192.0.2.10"}', $4::jsonb, $5)`,
		jobID, e.tenant, agentID, `{"username":"readonly","password":"`+password+`","device_type":"fortinet"}`, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil)
	req.Header.Set("X-Agent-Capabilities", "device_discovery")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		ID          uuid.UUID              `json:"id"`
		Credentials map[string]interface{} `json:"credentials"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != jobID {
		t.Fatalf("claimed job %s, want %s", got.ID, jobID)
	}
	return got.Credentials, got.ID.String()
}

func (e *agentSecretEnv) rotate(t *testing.T, res enrolResult, peer *x509.Certificate, supports bool) (enrolResult, int) {
	t.Helper()
	body, _ := json.Marshal(rotateAgentCertificateRequest{CSR: generateAgentCSR(t, res.AgentID), SupportsAgentSecret: supports})
	req := httptest.NewRequest(http.MethodPost, "/agents/"+res.AgentID.String()+"/certificates/rotate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	var out enrolResult
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out, w.Code
}

func requirePasswordWith(t *testing.T, env map[string]interface{}, jobID, secret, want string) {
	t.Helper()
	if !agentcreds.IsSealed(env) {
		t.Fatalf("credentials %v are not the canonical envelope", env)
	}
	got, err := agentcreds.Open(env, jobID, secret)
	if err != nil {
		t.Fatalf("the agent could not open the envelope: %v", err)
	}
	if got["password"] != want {
		t.Fatalf("password = %v, want %q", got["password"], want)
	}
}

func requireCannotOpen(t *testing.T, env map[string]interface{}, jobID, secret, what string) {
	t.Helper()
	if _, err := agentcreds.Open(env, jobID, secret); err == nil {
		t.Fatalf("%s opened the envelope, want failure", what)
	}
}

func (e *agentSecretEnv) storedSecret(t *testing.T, agentID uuid.UUID) (wrapped sql.NullString, version int) {
	t.Helper()
	if err := e.owner.QueryRow(`SELECT agent_secret_enc, agent_secret_version FROM device_agents WHERE id = $1`, agentID).
		Scan(&wrapped, &version); err != nil {
		t.Fatal(err)
	}
	return wrapped, version
}

// Enrolment returns the secret once, stores only its wrapped form, and the
// credentials the platform then hands the agent open with that secret and with
// nothing else — not with the (spent) registration key.
func TestIntegration_AgentSecret_EnrolmentIssuesItAndJobsSealUnderIt(t *testing.T) {
	e := newAgentSecretEnv(t)
	res, regKey := e.enrol(t, true)

	raw, err := base64.StdEncoding.DecodeString(res.AgentSecret)
	if err != nil || len(raw) != agentcreds.SecretBytes {
		t.Fatalf("agent_secret = %q (decode err %v), want %d base64 bytes", res.AgentSecret, err, agentcreds.SecretBytes)
	}
	if res.AgentSecretVersion != 1 {
		t.Fatalf("agent_secret_version = %d, want 1", res.AgentSecretVersion)
	}

	wrapped, version := e.storedSecret(t, res.AgentID)
	if version != 1 || !wrapped.Valid || wrapped.String == "" {
		t.Fatalf("stored secret = %+v v%d, want a wrapped secret at v1", wrapped, version)
	}
	if strings.Contains(wrapped.String, res.AgentSecret) {
		t.Fatal("the secret is stored in the clear")
	}

	env, jobID := e.jobEnvelope(t, res.AgentID, "s3cr3t-pw")
	requirePasswordWith(t, env, jobID, res.AgentSecret, "s3cr3t-pw")
	requireCannotOpen(t, env, jobID, regKey, "the spent registration key")
}

// An agent build that does not ask for a secret is not given one, and keeps
// opening with its registration key — the pre-change protocol, untouched.
func TestIntegration_AgentSecret_PreChangeAgentKeepsTheRegistrationKey(t *testing.T) {
	e := newAgentSecretEnv(t)
	res, regKey := e.enrol(t, false)
	if res.AgentSecret != "" || res.AgentSecretVersion != 0 {
		t.Fatalf("an agent that did not ask received a secret: %+v", res)
	}
	if wrapped, version := e.storedSecret(t, res.AgentID); version != 0 || wrapped.Valid {
		t.Fatalf("stored secret = %+v v%d, want none", wrapped, version)
	}
	env, jobID := e.jobEnvelope(t, res.AgentID, "legacy-pw")
	requirePasswordWith(t, env, jobID, regKey, "legacy-pw")
}

// Rotation issues a NEW secret; from then on the platform seals under it only.
// (The agent-side window for the replaced secret is covered in shared/agentcreds
// and the device agent.)
func TestIntegration_AgentSecret_RotationIssuesANewSecret(t *testing.T) {
	e := newAgentSecretEnv(t)
	res, _ := e.enrol(t, true)

	cs := certificates.NewCertificateService(e.owner, e.owner, agentSecretTestMasterKey)
	enrolledPEM, err := cs.IssueCertificate(e.tenant, res.AgentID, generateAgentCSR(t, res.AgentID))
	if err != nil {
		t.Fatal(err)
	}

	rot, _ := e.rotate(t, res, parseCertPEM(t, enrolledPEM), true)
	if rot.AgentSecret == "" || rot.AgentSecret == res.AgentSecret {
		t.Fatalf("rotation returned secret %q, want a new one (was %q)", rot.AgentSecret, res.AgentSecret)
	}
	if rot.AgentSecretVersion != 2 {
		t.Fatalf("agent_secret_version = %d, want 2", rot.AgentSecretVersion)
	}

	env, jobID := e.jobEnvelope(t, res.AgentID, "after-rotation")
	requirePasswordWith(t, env, jobID, rot.AgentSecret, "after-rotation")
	requireCannotOpen(t, env, jobID, res.AgentSecret, "the replaced secret")

	// A rotation from an agent that does not ask changes nothing about the secret.
	again, _ := e.rotate(t, res, parseCertPEM(t, rot.ClientCert), false)
	if again.AgentSecret != "" {
		t.Fatalf("rotation without supports_agent_secret returned a secret: %+v", again)
	}
	if _, version := e.storedSecret(t, res.AgentID); version != 2 {
		t.Fatalf("stored version = %d after a rotation that asked for nothing, want 2", version)
	}
}

// The migration: an agent enrolled before secrets existed rotates its
// certificate, receives its first secret, and the platform switches from the
// registration key to it for that agent.
func TestIntegration_AgentSecret_MigrationAtFirstRotation(t *testing.T) {
	e := newAgentSecretEnv(t)
	res, regKey := e.enrol(t, false)

	before, beforeJob := e.jobEnvelope(t, res.AgentID, "before")
	requirePasswordWith(t, before, beforeJob, regKey, "before")

	cs := certificates.NewCertificateService(e.owner, e.owner, agentSecretTestMasterKey)
	enrolledPEM, err := cs.IssueCertificate(e.tenant, res.AgentID, generateAgentCSR(t, res.AgentID))
	if err != nil {
		t.Fatal(err)
	}
	rot, _ := e.rotate(t, res, parseCertPEM(t, enrolledPEM), true)
	if rot.AgentSecret == "" || rot.AgentSecretVersion != 1 {
		t.Fatalf("migration rotation = %+v, want a v1 secret", rot)
	}

	after, afterJob := e.jobEnvelope(t, res.AgentID, "after")
	requirePasswordWith(t, after, afterJob, rot.AgentSecret, "after")
	requireCannotOpen(t, after, afterJob, regKey, "the registration key, once the agent has migrated")
}
