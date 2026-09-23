package api

// Staff-account takeover through identity-provider configuration, driven
// through the REAL admin-service router against a real Postgres.
//
// The path this pins shut: a platform user who could write an admin_login
// identity provider (then gated by platform.settings, which a stock
// platform_admin holds) could point its token/userinfo endpoints at a server
// they control, have it assert a super administrator's email, and receive a
// full super-admin session from the public staff SSO callback. Three layers now
// stand in the way, and each has its own subtest here:
//
//   - provider writes need platform.security.manage (seeded to super_admin only);
//   - the callback requires the IdP to assert email_verified;
//   - a super administrator signs in only through a provider whose last writer
//     is, at sign-in time, an active super administrator;
//   - anyone else signs in only if that last writer currently holds every
//     permission of their role.
//
// It also pins the settings half: the keys that decide where staff reset and
// invitation links point and how staff authenticate need
// platform.security.manage too.
//
// Needs TEST_DATABASE_URL (skips otherwise); `make test-integration-db` runs it.
// Every row it writes is its own (random emails, a throwaway role, providers
// it created) and is removed at cleanup; the global platform_settings rows it
// touches are restored exactly.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const ssoTakeoverJWTSecret = "sso-takeover-integration-secret-not-a-real-key"

// A client secret distinctive enough that finding it in any response or audit
// body is unambiguous.
const ssoTakeoverClientSecret = "sso-takeover-client-secret-6f1d0c"

type ssoTakeoverFixture struct {
	t      *testing.T
	db     *sql.DB
	srv    *Server
	suffix string

	audits   chan map[string]interface{}
	idp      *httptest.Server
	idpMu    sync.Mutex
	userinfo string // JSON the fake IdP's userinfo endpoint returns

	secMgrRole    uuid.UUID
	outrankerRole uuid.UUID // holds one permission the security manager lacks
	outrankerPerm string

	platformAdmin uuid.UUID // stock platform_admin: platform.settings, NOT platform.security.manage
	outranker     uuid.UUID // custom role: a permission secMgr does not hold
	secMgr        uuid.UUID // platform_admin's permissions + platform.security.manage, not super_admin
	superA        uuid.UUID // super_admin who configures the provider
	superVictim   uuid.UUID // super_admin whose account the attack targets
}

func newSSOTakeoverFixture(t *testing.T) *ssoTakeoverFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	f := &ssoTakeoverFixture{t: t, db: db}
	f.suffix = strings.ReplaceAll(uuid.NewString(), "-", "")[:12]

	// Premises: the seed shape the attack and the fix are about.
	if !f.roleHas("platform_admin", "platform.settings") {
		t.Fatal("premise: seeded platform_admin must hold platform.settings (the gate the attack used)")
	}
	if f.roleHas("platform_admin", "platform.security.manage") {
		t.Fatal("seed: platform_admin must NOT hold platform.security.manage (scripts/database/seed.sql)")
	}
	if !f.roleHas("super_admin", "platform.security.manage") {
		t.Fatal("seed: super_admin must hold platform.security.manage")
	}

	// This test owns the (google, admin_login) provider slot while it runs.
	var existing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_sso_providers WHERE provider_type = 'google' AND purpose = 'admin_login'`).Scan(&existing); err != nil {
		t.Fatalf("count providers: %v", err)
	}
	if existing != 0 {
		t.Fatalf("the integration database already has a (google, admin_login) identity provider; this test needs the slot")
	}

	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'Security manager (test)', 'sso-takeover integration fixture', false)
		RETURNING id`, "test_secmgr_"+f.suffix).Scan(&f.secMgrRole); err != nil {
		t.Fatalf("create fixture role: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, prp.permission_id FROM platform_role_permissions prp
		JOIN platform_roles pr ON pr.id = prp.role_id WHERE pr.name = 'platform_admin'
		UNION
		SELECT $1::uuid, id FROM platform_permissions WHERE name = 'platform.security.manage'`,
		f.secMgrRole); err != nil {
		t.Fatalf("grant fixture role: %v", err)
	}

	// A custom role holding one permission the security manager does not —
	// the "non-super staff member with more power than the provider's writer"
	// the generalised trust rule protects.
	if err := db.QueryRow(`
		SELECT name FROM platform_permissions
		WHERE id NOT IN (SELECT permission_id FROM platform_role_permissions WHERE role_id = $1)
		ORDER BY name LIMIT 1`, f.secMgrRole).Scan(&f.outrankerPerm); err != nil {
		t.Fatalf("pick a permission the security manager lacks: %v", err)
	}
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'Outranker (test)', 'sso-takeover integration fixture', false)
		RETURNING id`, "test_outranker_"+f.suffix).Scan(&f.outrankerRole); err != nil {
		t.Fatalf("create outranker role: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, id FROM platform_permissions WHERE name = $2`,
		f.outrankerRole, f.outrankerPerm); err != nil {
		t.Fatalf("grant outranker role: %v", err)
	}

	f.platformAdmin = f.user("pa", "platform_admin", uuid.Nil)
	f.outranker = f.user("outranker", "", f.outrankerRole)
	f.secMgr = f.user("secmgr", "", f.secMgrRole)
	f.superA = f.user("supera", "super_admin", uuid.Nil)
	f.superVictim = f.user("victim", "super_admin", uuid.Nil)

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_sso_providers WHERE provider_type = 'google' AND purpose = 'admin_login'`)
		_, _ = db.Exec(`DELETE FROM platform_users WHERE email LIKE $1`, "%-"+f.suffix+"@sso-takeover.example.test")
		_, _ = db.Exec(`DELETE FROM platform_role_permissions WHERE role_id IN ($1, $2)`, f.secMgrRole, f.outrankerRole)
		_, _ = db.Exec(`DELETE FROM platform_roles WHERE id IN ($1, $2)`, f.secMgrRole, f.outrankerRole)
	})

	// The IdP a hostile operator would stand up: it issues any token and
	// asserts whatever identity the test sets.
	f.idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"fake-idp-access-token"}`))
		case "/userinfo":
			f.idpMu.Lock()
			body := f.userinfo
			f.idpMu.Unlock()
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.idp.Close)

	// Capture platform audit events. Wired from the environment when the
	// server is built, so set before NewServerWithConnections.
	f.audits = make(chan map[string]interface{}, 64)
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		select {
		case f.audits <- body:
		default:
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	t.Cleanup(auditSrv.Close)
	t.Setenv("AUDIT_SERVICE_URL", auditSrv.URL)
	t.Setenv("AUDIT_LOGGING_ENABLED", "true")
	t.Setenv("ENCRYPTION_MASTER_KEY", "")

	f.srv = NewServerWithConnections(
		&config.Config{Environment: "test", JWTSecret: ssoTakeoverJWTSecret},
		db, db, EditionHooks{},
	)
	return f
}

func (f *ssoTakeoverFixture) email(label string) string {
	return label + "-" + f.suffix + "@sso-takeover.example.test"
}

// user creates an active platform user holding the seeded role roleName, or
// roleID when roleName is empty.
func (f *ssoTakeoverFixture) user(label, roleName string, roleID uuid.UUID) uuid.UUID {
	f.t.Helper()
	if roleName != "" {
		if err := f.db.QueryRow(`SELECT id FROM platform_roles WHERE name = $1`, roleName).Scan(&roleID); err != nil {
			f.t.Fatalf("seeded role %s: %v", roleName, err)
		}
	}
	var id uuid.UUID
	if err := f.db.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		VALUES ($1, 'not-a-real-hash', 'Sso', 'Takeover', $2, true)
		RETURNING id`, f.email(label), roleID).Scan(&id); err != nil {
		f.t.Fatalf("create %s user: %v", label, err)
	}
	return id
}

func (f *ssoTakeoverFixture) roleHas(role, perm string) bool {
	f.t.Helper()
	var has bool
	if err := f.db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM platform_role_permissions prp
			JOIN platform_permissions pp ON pp.id = prp.permission_id
			JOIN platform_roles pr ON pr.id = prp.role_id
			WHERE pr.name = $1 AND pp.name = $2)`, role, perm).Scan(&has); err != nil {
		f.t.Fatalf("roleHas: %v", err)
	}
	return has
}

func (f *ssoTakeoverFixture) token(user uuid.UUID) string {
	f.t.Helper()
	claims := models.JWTClaims{
		UserID: user,
		Email:  "operator@example.test",
		// Deliberately a lie: authorization must come from the database, not
		// from the role name the token carries.
		Role: "super_admin",
		Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ssoTakeoverJWTSecret))
	if err != nil {
		f.t.Fatalf("sign token: %v", err)
	}
	return signed
}

// admin sends a request to /api/v1/admin-service/admin<path> as caller.
func (f *ssoTakeoverFixture) admin(caller uuid.UUID, method, path, body string) (int, string) {
	f.t.Helper()
	req := httptest.NewRequest(method, "/api/v1/admin-service/admin"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.token(caller))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.srv.Router().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// providerBody is an admin_login provider whose endpoints are the fake IdP.
func (f *ssoTakeoverFixture) providerBody() string {
	return `{"provider_type":"google","purpose":"admin_login","client_id":"hostile-client",` +
		`"client_secret":"` + ssoTakeoverClientSecret + `",` +
		`"auth_url":"` + f.idp.URL + `/authorize","token_url":"` + f.idp.URL + `/token",` +
		`"userinfo_url":"` + f.idp.URL + `/userinfo","is_enabled":true}`
}

func (f *ssoTakeoverFixture) providerCount() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM platform_sso_providers WHERE provider_type = 'google' AND purpose = 'admin_login'`).Scan(&n); err != nil {
		f.t.Fatalf("providerCount: %v", err)
	}
	return n
}

func (f *ssoTakeoverFixture) providerID() string {
	f.t.Helper()
	var id string
	if err := f.db.QueryRow(`SELECT id FROM platform_sso_providers WHERE provider_type = 'google' AND purpose = 'admin_login'`).Scan(&id); err != nil {
		f.t.Fatalf("providerID: %v", err)
	}
	return id
}

func (f *ssoTakeoverFixture) providerAuthor() uuid.NullUUID {
	f.t.Helper()
	var by uuid.NullUUID
	if err := f.db.QueryRow(`SELECT updated_by FROM platform_sso_providers WHERE provider_type = 'google' AND purpose = 'admin_login'`).Scan(&by); err != nil {
		f.t.Fatalf("providerAuthor: %v", err)
	}
	return by
}

// callback runs the public staff SSO callback with the fake IdP asserting
// userinfo, and returns the redirect Location and whether a platform session
// cookie was issued.
func (f *ssoTakeoverFixture) callback(userinfo string) (string, bool) {
	f.t.Helper()
	f.idpMu.Lock()
	f.userinfo = userinfo
	f.idpMu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin-service/admin/sso/google/callback?state=st&code=cd", nil)
	req.AddCookie(&http.Cookie{Name: "admin_sso_state", Value: "st"})
	w := httptest.NewRecorder()
	f.srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		f.t.Fatalf("callback status = %d, want 302; body=%s", w.Code, w.Body.String())
	}
	session := false
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "platform_access_token" && ck.Value != "" {
			session = true
		}
	}
	return w.Header().Get("Location"), session
}

// waitAudit returns the next captured audit event of eventType, failing the
// test if none arrives. Events of other types are discarded.
func (f *ssoTakeoverFixture) waitAudit(eventType string) map[string]interface{} {
	f.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-f.audits:
			if ev["event_type"] == eventType {
				return ev
			}
		case <-deadline:
			f.t.Fatalf("no %q audit event within 5s", eventType)
			return nil
		}
	}
}

func (f *ssoTakeoverFixture) drainAudits() {
	for {
		select {
		case <-f.audits:
		case <-time.After(300 * time.Millisecond):
			return
		}
	}
}

func verifiedUserinfo(email string) string {
	return `{"email":"` + email + `","email_verified":true}`
}

func ssoTakeoverExpect(t *testing.T, what string, got int, body string, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status = %d, want %d; body=%s", what, got, want, body)
	}
}

func assertNoSecret(t *testing.T, what, body string) {
	t.Helper()
	if strings.Contains(body, ssoTakeoverClientSecret) {
		t.Fatalf("%s carries the client secret: %s", what, body)
	}
}

func TestIntegration_StaffSSOTakeover_RealRouter(t *testing.T) {
	f := newSSOTakeoverFixture(t)

	// ---- A. provider writes need platform.security.manage -------------------

	t.Run("stock platform_admin cannot create a staff-login provider", func(t *testing.T) {
		code, body := f.admin(f.platformAdmin, http.MethodPost, "/identity-providers", f.providerBody())
		ssoTakeoverExpect(t, "platform_admin create", code, body, http.StatusForbidden)
		if !strings.Contains(body, "platform.security.manage") {
			t.Fatalf("403 should name the missing permission: %s", body)
		}
		if f.providerCount() != 0 {
			t.Fatal("the refused create still wrote a provider row")
		}
	})

	t.Run("stock platform_admin cannot create a sign-up provider either", func(t *testing.T) {
		body := strings.Replace(f.providerBody(), `"purpose":"admin_login"`, `"purpose":"signup"`, 1)
		code, resp := f.admin(f.platformAdmin, http.MethodPost, "/identity-providers", body)
		ssoTakeoverExpect(t, "platform_admin create signup", code, resp, http.StatusForbidden)
	})

	t.Run("super_admin creates the provider and is recorded as its author", func(t *testing.T) {
		f.drainAudits()
		code, body := f.admin(f.superA, http.MethodPost, "/identity-providers", f.providerBody())
		ssoTakeoverExpect(t, "super_admin create", code, body, http.StatusCreated)
		if by := f.providerAuthor(); !by.Valid || by.UUID != f.superA {
			t.Fatalf("updated_by = %v, want the creating super_admin %s", by, f.superA)
		}
		ev := f.waitAudit("platform_identity_provider.created")
		raw, _ := json.Marshal(ev)
		assertNoSecret(t, "the create audit event", string(raw))
		if ev["user_id"] != f.superA.String() {
			t.Fatalf("audit actor = %v, want %s", ev["user_id"], f.superA)
		}
		if fields, _ := ev["changed_fields"].([]interface{}); len(fields) == 0 {
			t.Fatalf("create audit event names no changed fields: %s", raw)
		}
	})

	t.Run("reads stay on platform.settings and never return the secret", func(t *testing.T) {
		code, body := f.admin(f.platformAdmin, http.MethodGet, "/identity-providers", "")
		ssoTakeoverExpect(t, "platform_admin list", code, body, http.StatusOK)
		assertNoSecret(t, "the provider list", body)
		if !strings.Contains(body, `"has_secret":true`) {
			t.Fatalf("list should flag the stored secret: %s", body)
		}
	})

	t.Run("stock platform_admin cannot re-point, disable or delete the provider", func(t *testing.T) {
		id := f.providerID()
		code, body := f.admin(f.platformAdmin, http.MethodPut, "/identity-providers/"+id,
			`{"userinfo_url":"https://elsewhere.example.test/userinfo","is_enabled":true}`)
		ssoTakeoverExpect(t, "platform_admin update", code, body, http.StatusForbidden)
		code, body = f.admin(f.platformAdmin, http.MethodPut, "/identity-providers/"+id,
			`{"userinfo_url":"`+f.idp.URL+`/userinfo","is_enabled":false}`)
		ssoTakeoverExpect(t, "platform_admin disable", code, body, http.StatusForbidden)
		code, body = f.admin(f.platformAdmin, http.MethodDelete, "/identity-providers/"+id, "")
		ssoTakeoverExpect(t, "platform_admin delete", code, body, http.StatusForbidden)
		if by := f.providerAuthor(); !by.Valid || by.UUID != f.superA {
			t.Fatalf("a refused write changed updated_by to %v", by)
		}
	})

	// ---- B. the IdP must assert email_verified ------------------------------

	for name, ui := range map[string]string{
		"missing":      `{"email":"` + f.email("victim") + `"}`,
		"false":        `{"email":"` + f.email("victim") + `","email_verified":false}`,
		"string false": `{"email":"` + f.email("victim") + `","email_verified":"false"}`,
	} {
		t.Run("callback refuses an unverified email ("+name+")", func(t *testing.T) {
			f.drainAudits()
			loc, session := f.callback(ui)
			if loc != "/login?error=sso_email_unverified" || session {
				t.Fatalf("Location = %q, session = %v; want the unverified-email refusal and no session", loc, session)
			}
			ev := f.waitAudit("auth.sso_login")
			if ev["success"] != false || ev["error_code"] != "email_not_verified" {
				t.Fatalf("refusal audit = %v, want success=false error_code=email_not_verified", ev)
			}
			if ev["user_email"] != f.email("victim") {
				t.Fatalf("refusal audit actor email = %v, want the asserted email", ev["user_email"])
			}
		})
	}

	// ---- C. super_admin only through a super_admin-authored provider --------

	t.Run("a super_admin-authored provider signs a super_admin in, and the sign-in is audited", func(t *testing.T) {
		f.drainAudits()
		loc, session := f.callback(verifiedUserinfo(f.email("victim")))
		if loc != "/" || !session {
			t.Fatalf("Location = %q, session = %v; want a super-admin session", loc, session)
		}
		ev := f.waitAudit("auth.sso_login")
		if ev["success"] != true || ev["user_id"] != f.superVictim.String() || ev["resource_id"] != f.providerID() {
			t.Fatalf("sign-in audit = %v, want success=true for the victim through this provider", ev)
		}
	})

	t.Run("a super_admin-authored provider signs in staff with a custom role", func(t *testing.T) {
		loc, session := f.callback(verifiedUserinfo(f.email("outranker")))
		if loc != "/" || !session {
			t.Fatalf("Location = %q, session = %v; want a session for the custom-role user", loc, session)
		}
	})

	t.Run("after a non-super security manager edits it, the provider cannot sign in a super_admin", func(t *testing.T) {
		id := f.providerID()
		code, body := f.admin(f.secMgr, http.MethodPut, "/identity-providers/"+id,
			`{"userinfo_url":"`+f.idp.URL+`/userinfo","is_enabled":true}`)
		ssoTakeoverExpect(t, "security manager update", code, body, http.StatusOK)
		if by := f.providerAuthor(); !by.Valid || by.UUID != f.secMgr {
			t.Fatalf("updated_by = %v, want the security manager %s", by, f.secMgr)
		}

		f.drainAudits()
		loc, session := f.callback(verifiedUserinfo(f.email("victim")))
		if loc != "/login?error=sso_super_admin_untrusted_provider" || session {
			t.Fatalf("Location = %q, session = %v; want the super-admin refusal and no session", loc, session)
		}
		ev := f.waitAudit("auth.sso_login")
		if ev["success"] != false || ev["error_code"] != "super_admin_provider_untrusted" || ev["user_id"] != f.superVictim.String() {
			t.Fatalf("refusal audit = %v, want success=false error_code=super_admin_provider_untrusted for the victim", ev)
		}
	})

	t.Run("the same provider still signs in staff its writer outranks", func(t *testing.T) {
		loc, session := f.callback(verifiedUserinfo(f.email("pa")))
		if loc != "/" || !session {
			t.Fatalf("Location = %q, session = %v; want a platform_admin session", loc, session)
		}
	})

	t.Run("but not staff holding a permission its writer lacks", func(t *testing.T) {
		f.drainAudits()
		loc, session := f.callback(verifiedUserinfo(f.email("outranker")))
		if loc != "/login?error=sso_untrusted_provider" || session {
			t.Fatalf("Location = %q, session = %v; want the untrusted-provider refusal for a user holding %s", loc, session, f.outrankerPerm)
		}
		ev := f.waitAudit("auth.sso_login")
		if ev["success"] != false || ev["error_code"] != "provider_author_outranked" || ev["user_id"] != f.outranker.String() {
			t.Fatalf("refusal audit = %v, want success=false error_code=provider_author_outranked for the outranker", ev)
		}
	})

	t.Run("a provider with no recorded writer signs in non-super staff but not a super_admin", func(t *testing.T) {
		if _, err := f.db.Exec(`UPDATE platform_sso_providers SET updated_by = NULL WHERE provider_type = 'google' AND purpose = 'admin_login'`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = f.db.Exec(`UPDATE platform_sso_providers SET updated_by = $1 WHERE provider_type = 'google' AND purpose = 'admin_login'`, f.secMgr)
		}()
		if loc, session := f.callback(verifiedUserinfo(f.email("outranker"))); loc != "/" || !session {
			t.Fatalf("legacy provider, custom-role user: Location = %q, session = %v; want a session (upgrade must not lock non-super staff out)", loc, session)
		}
		if loc, session := f.callback(verifiedUserinfo(f.email("victim"))); loc != "/login?error=sso_super_admin_untrusted_provider" || session {
			t.Fatalf("legacy provider, super_admin: Location = %q, session = %v; want the super-admin refusal", loc, session)
		}
	})

	t.Run("a super_admin re-saving the provider restores super-admin sign-in", func(t *testing.T) {
		id := f.providerID()
		f.drainAudits()
		code, body := f.admin(f.superA, http.MethodPut, "/identity-providers/"+id,
			`{"userinfo_url":"`+f.idp.URL+`/userinfo","is_enabled":true,"client_secret":"`+ssoTakeoverClientSecret+`-rotated"}`)
		ssoTakeoverExpect(t, "super_admin re-save", code, body, http.StatusOK)
		ev := f.waitAudit("platform_identity_provider.updated")
		raw, _ := json.Marshal(ev)
		assertNoSecret(t, "the update audit event", string(raw))
		if nv, _ := ev["new_values"].(map[string]interface{}); nv["client_secret_rotated"] != true {
			t.Fatalf("update audit should record the secret rotation as a boolean: %s", raw)
		}

		loc, session := f.callback(verifiedUserinfo(f.email("victim")))
		if loc != "/" || !session {
			t.Fatalf("Location = %q, session = %v; want a super-admin session", loc, session)
		}
	})

	t.Run("an author who is no longer an active super_admin is not trusted", func(t *testing.T) {
		if _, err := f.db.Exec(`UPDATE platform_users SET is_active = false WHERE id = $1`, f.superA); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = f.db.Exec(`UPDATE platform_users SET is_active = true WHERE id = $1`, f.superA) }()
		loc, session := f.callback(verifiedUserinfo(f.email("victim")))
		if loc != "/login?error=sso_super_admin_untrusted_provider" || session {
			t.Fatalf("Location = %q, session = %v; want the super-admin refusal", loc, session)
		}
	})

	// ---- A (settings half): link- and auth-shaping keys ---------------------

	f.snapshotSettings("admin_ui_base_url", "support_email", "email_config")

	t.Run("stock platform_admin cannot re-point admin_ui_base_url", func(t *testing.T) {
		before := f.setting("admin_ui_base_url")
		code, body := f.admin(f.platformAdmin, http.MethodPut, "/settings", `{"admin_ui_base_url":"https://elsewhere.example.test"}`)
		ssoTakeoverExpect(t, "platform_admin admin_ui_base_url", code, body, http.StatusForbidden)
		if !strings.Contains(body, "admin_ui_base_url") || !strings.Contains(body, "platform.security.manage") {
			t.Fatalf("403 should name the field and the permission: %s", body)
		}
		if after := f.setting("admin_ui_base_url"); after != before {
			t.Fatalf("admin_ui_base_url changed from %q to %q on a refused write", before, after)
		}
	})

	t.Run("stock platform_admin cannot re-point the email relay", func(t *testing.T) {
		before := f.setting("email_config")
		code, body := f.admin(f.platformAdmin, http.MethodPut, "/settings",
			`{"email_config":{"smtp_host":"relay.elsewhere.example.test","smtp_port":"587","from_email":"noreply@elsewhere.example.test"}}`)
		ssoTakeoverExpect(t, "platform_admin email_config", code, body, http.StatusForbidden)
		if !strings.Contains(body, "email_config") {
			t.Fatalf("403 should name the field: %s", body)
		}
		if after := f.setting("email_config"); after != before {
			t.Fatalf("email_config changed from %q to %q on a refused write", before, after)
		}
	})

	t.Run("stock platform_admin cannot loosen the lockout policy", func(t *testing.T) {
		code, body := f.admin(f.platformAdmin, http.MethodPut, "/settings", `{"max_login_attempts":100}`)
		ssoTakeoverExpect(t, "platform_admin max_login_attempts", code, body, http.StatusForbidden)
	})

	t.Run("stock platform_admin keeps the ungated settings", func(t *testing.T) {
		code, body := f.admin(f.platformAdmin, http.MethodPut, "/settings", `{"support_email":"support-`+f.suffix+`@example.test"}`)
		ssoTakeoverExpect(t, "platform_admin support_email", code, body, http.StatusOK)
	})

	t.Run("super_admin writes admin_ui_base_url and the write is audited", func(t *testing.T) {
		f.drainAudits()
		want := "https://admin-" + f.suffix + ".example.test"
		code, body := f.admin(f.superA, http.MethodPut, "/settings", `{"admin_ui_base_url":"`+want+`"}`)
		ssoTakeoverExpect(t, "super_admin admin_ui_base_url", code, body, http.StatusOK)
		if got := f.setting("admin_ui_base_url"); got != `"`+want+`"` {
			t.Fatalf("admin_ui_base_url = %s, want %q", got, want)
		}
		ev := f.waitAudit("platform_settings.security_updated")
		if ev["user_id"] != f.superA.String() {
			t.Fatalf("audit actor = %v, want %s", ev["user_id"], f.superA)
		}
		fields, _ := ev["changed_fields"].([]interface{})
		if len(fields) != 1 || fields[0] != "admin_ui_base_url" {
			t.Fatalf("audit changed_fields = %v, want [admin_ui_base_url]", ev["changed_fields"])
		}
	})
}

// snapshotSettings records the platform_settings rows for keys and restores
// them exactly (or removes them) at cleanup — they are global rows other
// suites read. Registered after the fixture's user cleanup, so it runs first
// (the rows' updated_by references this test's users).
func (f *ssoTakeoverFixture) snapshotSettings(keys ...string) {
	f.t.Helper()
	type row struct {
		exists bool
		value  []byte
		by     uuid.NullUUID
	}
	saved := map[string]row{}
	for _, k := range keys {
		var r row
		err := f.db.QueryRow(`SELECT setting_value, updated_by FROM platform_settings WHERE setting_key = $1`, k).Scan(&r.value, &r.by)
		switch {
		case err == sql.ErrNoRows:
		case err != nil:
			f.t.Fatalf("snapshot %s: %v", k, err)
		default:
			r.exists = true
		}
		saved[k] = r
	}
	f.t.Cleanup(func() {
		for k, r := range saved {
			if r.exists {
				_, _ = f.db.Exec(`UPDATE platform_settings SET setting_value = $2, updated_by = $3 WHERE setting_key = $1`, k, r.value, r.by)
			} else {
				_, _ = f.db.Exec(`DELETE FROM platform_settings WHERE setting_key = $1`, k)
			}
		}
	})
}

// setting returns a platform_settings value as raw JSON text ("" when absent).
func (f *ssoTakeoverFixture) setting(key string) string {
	f.t.Helper()
	var v []byte
	err := f.db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = $1`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		f.t.Fatalf("setting %s: %v", key, err)
	}
	return string(v)
}
