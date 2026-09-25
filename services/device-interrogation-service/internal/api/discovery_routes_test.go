package api

// Add device and Test connection through the REAL SetupRouter ( slice A,
// W1.8), over a sqlmock database.
//
// Two things are pinned here that no handler test can see:
//
//   - The gates. test-connection now opens an authenticated connection with a
//     device's stored credentials, so it moved from discovery.read to
// discovery.manage ( addendum C). Both polarities are asserted:
//     refused without the permission, admitted with it. Deleting or loosening
//     the RequireTenantPermission line in router.go fails these.
//   - The failed probe, per vendor. A fake appliance that refuses the
//     credentials yields a typed 4xx and NO device: sqlmock carries exactly one
//     expectation (the permission check), so any INSERT the handler attempted
//     would be an unexpected query and the request would 500 instead.

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

const discoveryRoutesSecret = "device-discovery-route-test-secret"

const devicesPrefix = "/api/v1/device-interrogation-service/devices"

func mintTenantToken(t *testing.T, userID, tenantID uuid.UUID) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id":   userID.String(),
		"tenant_id": tenantID.String(),
		"email":     "member@example.test",
		"role":      "viewer",
		"type":      "access",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(discoveryRoutesSecret))
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return signed
}

func discoveryRouter(t *testing.T, db *sql.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-discovery-routes")
	t.Setenv("NATS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	// Tenant state is not under test; with DATABASE_URL set (the nightly) the
	// shared JWT middleware would look these random tenants up and refuse them
	// before the permission gate.
	t.Setenv("DATABASE_URL", "")
	return SetupRouter(&config.Config{JWTSecret: discoveryRoutesSecret}, db, db, nil)
}

// routeRequest sends one request through the real router with a sqlmock DB
// whose only expectation is the permission check.
func routeRequest(t *testing.T, method, path, body, permission string, granted bool) (*httptest.ResponseRecorder, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.MatchExpectationsInOrder(false)
	userID, tenantID := uuid.New(), uuid.New()
	mock.ExpectQuery(`user_has_permission`).
		WithArgs(userID, tenantID, permission).
		WillReturnRows(sqlmock.NewRows([]string{"user_has_permission"}).AddRow(granted))

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mintTenantToken(t, userID, tenantID))
	w := httptest.NewRecorder()
	discoveryRouter(t, db).ServeHTTP(w, req)
	return w, mock
}

func TestDeviceProbeRoutes_PermissionGates(t *testing.T) {
	id := uuid.NewString()
	for _, r := range []struct {
		method, path, body, permission string
	}{
		{http.MethodPost, devicesPrefix + "/" + id + "/test-connection", `{}`, rbac.PermissionDiscoveryManage},
		{http.MethodPost, devicesPrefix + "/discover-and-create", `{`, rbac.PermissionDiscoveryCreate},
	} {
		t.Run("refused "+r.path, func(t *testing.T) {
			w, mock := routeRequest(t, r.method, r.path, r.body, r.permission, false)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), r.permission) {
				t.Fatalf("403 does not name %s: %s", r.permission, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the %s check did not run — is the gate wired? %v", r.permission, err)
			}
		})
		t.Run("admitted "+r.path, func(t *testing.T) {
			w, mock := routeRequest(t, r.method, r.path, r.body, r.permission, true)
			if w.Code == http.StatusForbidden {
				t.Fatalf("%s was HELD and the route still 403'd: %s", r.permission, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the %s check did not run — is the gate wired? %v", r.permission, err)
			}
		})
	}
}

// discovery.read alone must not drive a test connection. The mock grants ONLY
// discovery.read; the gate asks about discovery.manage, so the grant is never
// consulted and the handler (whose device lookup would answer 404 here) is
// never reached. Re-gating the route on discovery.read consumes the grant and
// reaches the handler, and both assertions fail.
func TestTestConnection_ReadPermissionIsNotEnough(t *testing.T) {
	w, mock := routeRequest(t, http.MethodPost, devicesPrefix+"/"+uuid.NewString()+"/test-connection", `{}`,
		rbac.PermissionDiscoveryRead, true)
	if w.Code == http.StatusNotFound || w.Code < 400 {
		t.Fatalf("a discovery.read grant reached the handler: %d %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Fatal("the gate consulted a discovery.read grant; test-connection must require discovery.manage")
	}
}

// startRefusingSSHServer is a Cisco-shaped SSH server that refuses every
// password.
func startRefusingSSHServer(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, ssh.ErrNoAuth
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _, _, _ = ssh.NewServerConn(conn, cfg)
			}()
		}
	}()
	return ln.Addr().String()
}

// Add device, per vendor, against a device that refuses the credentials: a
// typed 422 authentication_failed, and nothing created.
func TestDiscoverAndCreate_RefusedCredentialsCreateNothing_EveryVendor(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no known_hosts from the machine running the suite
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer refusing.Close()
	sshAddr := startRefusingSSHServer(t)

	for _, tc := range []struct{ deviceType, url, listener string }{
		{"fortinet", refusing.URL, refusing.Listener.Addr().String()},
		{"palo_alto", refusing.URL, refusing.Listener.Addr().String()},
		{"f5", refusing.URL, refusing.Listener.Addr().String()},
		{"unifi", refusing.URL, refusing.Listener.Addr().String()},
		{"cisco", "ssh://" + sshAddr, sshAddr},
	} {
		t.Run(tc.deviceType, func(t *testing.T) {
			devicetest.AllowListener(t, tc.listener)
			body, _ := json.Marshal(map[string]any{
				"device_type": tc.deviceType, "management_url": tc.url,
				"username": "admin", "password": "wrong-password",
			})
			w, mock := routeRequest(t, http.MethodPost, devicesPrefix+"/discover-and-create", string(body),
				rbac.PermissionDiscoveryCreate, true)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
			}
			var got struct{ Error, Message string }
			_ = json.Unmarshal(w.Body.Bytes(), &got)
			if got.Error != "authentication_failed" || got.Message == "" {
				t.Fatalf("body = %s, want a typed authentication_failed", w.Body.String())
			}
			// The permission check is the ONLY expected query; a device write
			// would have been unexpected and turned this into a 500 above.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unexpected database traffic: %v", err)
			}
		})
	}
}
