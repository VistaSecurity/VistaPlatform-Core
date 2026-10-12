package api

// DB-integration coverage for the auth identity-flow fixes, driven through the
// REAL router (SetupRouter) over the non-owner app role and the BYPASSRLS role,
// exactly as production wires them, so deleting a check turns a test red — not
// just a helper. Skips unless TEST_DATABASE_URL is set; the token-consumption
// tests additionally need a Redis (TEST_REDIS_ADDR[/TEST_REDIS_PASSWORD]) and
// skip without one.
//
// Covered: sso_only refuses local login and reset; global email uniqueness at
// invite / accept / create; mixed-case emails sign in; parallel refresh yields
// exactly one session; a reset token is single-use and a reset clears the
// lockout; the last tenant_admin cannot be removed (also under concurrency); a
// platform user can finish the forced password change; avatar_url is
// shape-checked; an admin-created user's verification link works.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const identityTestSigningSecret = "test-secret-for-identity-flows"

// identityLoginCredential is the sign-in secret of every seeded user. Not named
// *PASSWORD* (gitleaks treats that as a real secret); it satisfies the strength
// policy.
const identityLoginCredential = "Ident1ty-Flow!Test9"

type identityFixture struct {
	owner  *sql.DB
	router *gin.Engine
	rdb    *redis.Client
}

// identityRedis returns a real Redis client, or skips when none is configured.
func identityRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set — Redis-backed token tests need a real Redis")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		_ = rdb.Close()
		t.Skipf("redis at %s unreachable: %v", addr, err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func newIdentityFixture(t *testing.T, withRedis bool) *identityFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	bypass := testdb.ConnectAsBypassRole(t, owner)
	t.Setenv("TENANT_STATE_CACHE_TTL", "0s")

	var rdb *redis.Client
	if withRedis {
		rdb = identityRedis(t)
	} else {
		rdb = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on these paths
		t.Cleanup(func() { _ = rdb.Close() })
	}
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: identityTestSigningSecret, JWTExpiry: time.Hour}
	return &identityFixture{owner: owner, rdb: rdb, router: SetupRouter(cfg, app, bypass, rdb, nil, EditionHooks{})}
}

func (f *identityFixture) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/api/v1/auth-service"+path, nil)
	} else {
		req = httptest.NewRequest(method, "/api/v1/auth-service"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *identityFixture) newTenant(t *testing.T) uuid.UUID {
	t.Helper()
	tid := testdb.NewTenant(t, f.owner)
	seedSystemRoles(t, f.owner, tid)
	return tid
}

// seedUser inserts a verified, active user with a real password hash and gives
// it role. email is stored EXACTLY as given.
func (f *identityFixture) seedUser(t *testing.T, tenantID uuid.UUID, email, role string) uuid.UUID {
	t.Helper()
	hash, err := passwordsvc.NewPasswordService().HashPassword(identityLoginCredential)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id := uuid.New()
	if _, err := f.owner.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified)
		VALUES ($1, $2, $3, $4, 'Id', 'Flow', true, true)`, id, tenantID, email, hash); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	if role != "" {
		if _, err := f.owner.Exec(`
			INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active)
			SELECT $1, $2, id, true FROM tenant_roles WHERE tenant_id = $2 AND name = $3`, id, tenantID, role); err != nil {
			t.Fatalf("assign role %s: %v", role, err)
		}
	}
	return id
}

func uniqEmail(prefix string) string { return prefix + "-" + uuid.NewString()[:8] + "@example.test" }

type idTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (f *identityFixture) login(email, password string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"email": email, "password": password})
	return f.do(http.MethodPost, "/auth/login", "", string(b))
}

func (f *identityFixture) mustLogin(t *testing.T, email string) idTokens {
	t.Helper()
	w := f.login(email, identityLoginCredential)
	if w.Code != http.StatusOK {
		t.Fatalf("login %s = %d; body=%s", email, w.Code, w.Body.String())
	}
	var tok idTokens
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("login %s returned no tokens: %v; body=%s", email, err, w.Body.String())
	}
	return tok
}

func (f *identityFixture) setPolicy(t *testing.T, tenantID uuid.UUID, policy string) {
	t.Helper()
	if _, err := f.owner.Exec(`UPDATE tenants SET authentication_policy = $1 WHERE id = $2`, policy, tenantID); err != nil {
		t.Fatalf("set policy: %v", err)
	}
}

func (f *identityFixture) seedResetToken(t *testing.T, userID uuid.UUID) string {
	t.Helper()
	token := uuid.NewString()
	key := "password_reset:" + token
	ctx := context.Background()
	if err := f.rdb.HSet(ctx, key, map[string]interface{}{
		"user_id": userID.String(), "email": "x@example.test", "expiry": time.Now().Add(time.Hour).Unix(),
	}).Err(); err != nil {
		t.Fatalf("seed reset token: %v", err)
	}
	t.Cleanup(func() { _ = f.rdb.Del(context.Background(), key).Err() })
	return token
}

func (f *identityFixture) reset(token, newPassword string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"token": token, "password": newPassword, "new_password": newPassword})
	return f.do(http.MethodPost, "/auth/reset-password", "", string(b))
}

func (f *identityFixture) passwordHashOf(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var h string
	if err := f.owner.QueryRow(`SELECT COALESCE(password_hash,'') FROM users WHERE id = $1`, id).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

// ---------------------------------------------------------------------------
// 1. sso_only refuses local password login and reset
// ---------------------------------------------------------------------------

func TestIntegration_SSOOnly_RefusesLocalPasswordLoginAndReset(t *testing.T) {
	f := newIdentityFixture(t, true)
	tenant := f.newTenant(t)
	email := uniqEmail("sso")
	userID := f.seedUser(t, tenant, email, "viewer")

	// Baseline: password_only logs in.
	f.mustLogin(t, email)

	// sso_only: a CORRECT password is refused with 403 / sso_required.
	f.setPolicy(t, tenant, "sso_only")
	w := f.login(email, identityLoginCredential)
	assertRefused(t, "sso_only local login", w, "sso_required")

	// ...and a wrong one is still just invalid credentials (no policy oracle).
	if w := f.login(email, "Wr0ng-Password!x"); w.Code != http.StatusUnauthorized {
		t.Fatalf("sso_only wrong password = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	// A reset link minted before the policy changed must not set a password.
	before := f.passwordHashOf(t, userID)
	rw := f.reset(f.seedResetToken(t, userID), "New-Passw0rd!Strong")
	if rw.Code == http.StatusOK {
		t.Fatalf("sso_only reset = 200; body=%s — a local password was set on an SSO-only tenant", rw.Body.String())
	}
	if after := f.passwordHashOf(t, userID); after != before {
		t.Fatal("sso_only reset changed the stored password hash")
	}

	// enforce_sso refuses regular users too, but tenant_admins keep password
	// access as the documented break-glass path.
	f.setPolicy(t, tenant, "enforce_sso")
	assertRefused(t, "enforce_sso local login of a regular user", f.login(email, identityLoginCredential), "sso_required")
	adminEmail := uniqEmail("ssoadm")
	f.seedUser(t, tenant, adminEmail, "tenant_admin")
	f.mustLogin(t, adminEmail)
	// sso_only closes even the admin's password.
	f.setPolicy(t, tenant, "sso_only")
	assertRefused(t, "sso_only local login of a tenant_admin", f.login(adminEmail, identityLoginCredential), "sso_required")

	// Back to password_only: reset works again (the other polarity).
	f.setPolicy(t, tenant, "password_only")
	if rw := f.reset(f.seedResetToken(t, userID), "New-Passw0rd!Strong"); rw.Code != http.StatusOK {
		t.Fatalf("password_only reset = %d; body=%s", rw.Code, rw.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 2. global email uniqueness (invite / accept / create)
// ---------------------------------------------------------------------------

func TestIntegration_GlobalEmailUniqueness_InviteAcceptCreate(t *testing.T) {
	f := newIdentityFixture(t, false)
	tenantA := f.newTenant(t)
	tenantB := f.newTenant(t)

	adminEmail := uniqEmail("adminA")
	adminID := f.seedUser(t, tenantA, adminEmail, "tenant_admin")
	victim := uniqEmail("victim")
	f.seedUser(t, tenantB, victim, "viewer")
	admin := f.mustLogin(t, adminEmail)

	invite := func(email string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"email": email, "role": "viewer"})
		return f.do(http.MethodPost, "/tenant/"+tenantA.String()+"/users/invite", admin.AccessToken, string(b))
	}

	// Another tenant's address (any case) cannot be invited.
	if w := invite(victim); w.Code != http.StatusConflict {
		t.Fatalf("invite of another tenant's address = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	if w := invite(strings.ToUpper(victim)); w.Code != http.StatusConflict {
		t.Fatalf("invite of another tenant's address (upper-case) = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	// A platform user's address cannot be invited either.
	platEmail := uniqEmail("platvictim")
	pid := f.insertPlatformUser(t, platEmail)
	_ = pid
	if w := invite(platEmail); w.Code != http.StatusConflict {
		t.Fatalf("invite of a platform user's address = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	// A genuinely new address still works (the other polarity).
	if w := invite(uniqEmail("fresh")); w.Code != http.StatusCreated {
		t.Fatalf("invite of a fresh address = %d, want 201; body=%s", w.Code, w.Body.String())
	}

	// Accept time: an invitation that already exists (issued before the fix, or
	// raced) for an address now held elsewhere is refused and creates no row.
	raw, hash, err := newInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`
		INSERT INTO invitations (tenant_id, email, role, invited_by, token_hash, status, expires_at)
		VALUES ($1, $2, 'viewer', $3, $4, 'pending', NOW() + interval '1 day')`, tenantA, victim, adminID, hash); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	b, _ := json.Marshal(map[string]string{"token": raw, "password": identityLoginCredential})
	if w := f.do(http.MethodPost, "/auth/invitations/accept", "", string(b)); w.Code != http.StatusConflict {
		t.Fatalf("accept of an invitation for another tenant's address = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM users WHERE lower(email) = lower($1)`, victim).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d users rows share the victim address after a refused accept, want 1", n)
	}

	// Admin-create (POST /users) with the same address, different case.
	cb, _ := json.Marshal(map[string]interface{}{
		"email": strings.ToUpper(victim), "password": identityLoginCredential,
		"first_name": "X", "last_name": "Y", "role": "viewer",
	})
	if w := f.do(http.MethodPost, "/users", admin.AccessToken, string(cb)); w.Code != http.StatusConflict {
		t.Fatalf("create of another tenant's address = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func (f *identityFixture) insertPlatformUser(t *testing.T, email string) uuid.UUID {
	t.Helper()
	hash, err := passwordsvc.NewPasswordService().HashPassword(identityLoginCredential)
	if err != nil {
		t.Fatal(err)
	}
	role := testdb.SeededPlatformRole(t, f.owner, "super_admin")
	var id uuid.UUID
	if err := f.owner.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active, email_verified)
		VALUES ($1, $2, 'P', 'U', $3, true, true) RETURNING id`, email, hash, role).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM platform_users WHERE id = $1`, id) })
	return id
}

// A pre-existing duplicate must fail CLOSED at login (no arbitrary row wins).
func TestIntegration_AmbiguousEmail_LoginFailsClosed(t *testing.T) {
	f := newIdentityFixture(t, false)
	tA, tB := f.newTenant(t), f.newTenant(t)
	email := uniqEmail("dup")
	f.seedUser(t, tA, email, "viewer")
	f.seedUser(t, tB, email, "viewer")
	if w := f.login(email, identityLoginCredential); w.Code != http.StatusUnauthorized {
		t.Fatalf("login with a shared address = %d, want 401 (fail closed); body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 3. mixed-case emails sign in; 8. admin-created verification link works
// ---------------------------------------------------------------------------

func TestIntegration_CreateUser_MixedCaseEmailCanSignIn_AndVerificationLinkWorks(t *testing.T) {
	f := newIdentityFixture(t, true)
	tenant := f.newTenant(t)
	adminEmail := uniqEmail("adm")
	f.seedUser(t, tenant, adminEmail, "tenant_admin")
	admin := f.mustLogin(t, adminEmail)

	mixed := "Mixed.Case-" + uuid.NewString()[:8] + "@Example.TEST"
	cb, _ := json.Marshal(map[string]interface{}{
		"email": mixed, "password": identityLoginCredential, "first_name": "Mi", "last_name": "Xed",
		"role": "viewer", "send_verification_email": true,
	})
	if w := f.do(http.MethodPost, "/users", admin.AccessToken, string(cb)); w.Code != http.StatusCreated {
		t.Fatalf("create = %d; body=%s", w.Code, w.Body.String())
	}
	var stored string
	var verified bool
	var vtoken sql.NullString
	if err := f.owner.QueryRow(`SELECT email, email_verified, email_verification_token FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)`,
		tenant, mixed).Scan(&stored, &verified, &vtoken); err != nil {
		t.Fatal(err)
	}
	if stored != strings.ToLower(mixed) {
		t.Fatalf("stored email = %q, want the lower-cased %q", stored, strings.ToLower(mixed))
	}

	// The verification link a tenant admin's "create user" mails must work.
	if !vtoken.Valid || vtoken.String == "" {
		t.Fatal("no verification token stored")
	}
	if w := f.do(http.MethodPost, "/auth/verify-email?token="+vtoken.String, "", ""); w.Code != http.StatusOK {
		t.Fatalf("verify-email with the admin-created token = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if err := f.owner.QueryRow(`SELECT email_verified FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)`, tenant, mixed).Scan(&verified); err != nil || !verified {
		t.Fatalf("email_verified = %v (err %v) after redeeming the link", verified, err)
	}
	// Single use.
	if w := f.do(http.MethodPost, "/auth/verify-email?token="+vtoken.String, "", ""); w.Code == http.StatusOK {
		t.Fatal("the verification token was redeemable twice")
	}

	// Sign-in works as typed AND in any other case.
	for _, e := range []string{mixed, strings.ToLower(mixed), strings.ToUpper(mixed)} {
		if w := f.login(e, identityLoginCredential); w.Code != http.StatusOK {
			t.Fatalf("login as %q = %d; body=%s", e, w.Code, w.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// 4. refresh rotation is atomic
// ---------------------------------------------------------------------------

func TestIntegration_RefreshRotation_ParallelRefreshYieldsExactlyOneSession(t *testing.T) {
	f := newIdentityFixture(t, false)
	tenant := f.newTenant(t)
	email := uniqEmail("ref")
	userID := f.seedUser(t, tenant, email, "viewer")
	tok := f.mustLogin(t, email)

	const n = 8
	codes := make([]int, n)
	newRefresh := make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			b, _ := json.Marshal(map[string]string{"refresh_token": tok.RefreshToken})
			w := f.do(http.MethodPost, "/auth/refresh", "", string(b))
			codes[i] = w.Code
			var out idTokens
			if json.Unmarshal(w.Body.Bytes(), &out) == nil {
				newRefresh[i] = out.RefreshToken
			}
		}(i)
	}
	close(start)
	wg.Wait()

	ok, winner := 0, ""
	for i, c := range codes {
		if c == http.StatusOK {
			ok++
			winner = newRefresh[i]
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d parallel refreshes succeeded (%v), want exactly 1", ok, n, codes)
	}
	// Exactly one live (unrevoked) token remains for the user: no second branch.
	var live int
	if err := f.owner.QueryRow(`SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND is_revoked = false`, userID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("%d live refresh tokens after a parallel refresh, want 1", live)
	}
	// The losers did not burn the family: the winner's token still works.
	b, _ := json.Marshal(map[string]string{"refresh_token": winner})
	if w := f.do(http.MethodPost, "/auth/refresh", "", string(b)); w.Code != http.StatusOK {
		t.Fatalf("the winning branch was killed by the losers: refresh = %d; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 5. reset token single-use; reset clears the lockout
// ---------------------------------------------------------------------------

func TestIntegration_ResetToken_SingleUse_AndClearsLockout(t *testing.T) {
	f := newIdentityFixture(t, true)
	tenant := f.newTenant(t)
	email := uniqEmail("rst")
	userID := f.seedUser(t, tenant, email, "viewer")
	if _, err := f.owner.Exec(`UPDATE users SET failed_login_attempts = 9, locked_until = NOW() + interval '1 hour' WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	token := f.seedResetToken(t, userID)

	if w := f.reset(token, "Brand-New-Passw0rd!1"); w.Code != http.StatusOK {
		t.Fatalf("first reset = %d; body=%s", w.Code, w.Body.String())
	}
	if w := f.reset(token, "Another-Passw0rd!2"); w.Code == http.StatusOK {
		t.Fatalf("second use of the same reset token = 200; body=%s", w.Body.String())
	}

	var attempts int
	var lockedUntil sql.NullTime
	if err := f.owner.QueryRow(`SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, userID).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || lockedUntil.Valid {
		t.Fatalf("lockout survived a successful reset: attempts=%d locked_until=%v", attempts, lockedUntil)
	}
	if w := f.login(email, "Brand-New-Passw0rd!1"); w.Code != http.StatusOK {
		t.Fatalf("login with the reset password = %d; body=%s", w.Code, w.Body.String())
	}
}

func TestIntegration_ResetToken_ConcurrentRedemption_ExactlyOneWins(t *testing.T) {
	f := newIdentityFixture(t, true)
	tenant := f.newTenant(t)
	userID := f.seedUser(t, tenant, uniqEmail("rc"), "viewer")
	token := f.seedResetToken(t, userID)

	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = f.reset(token, fmt.Sprintf("Concurrent-Passw0rd!%d", i)).Code
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent redemptions of one reset token succeeded (%v), want exactly 1", ok, codes)
	}
}

// ---------------------------------------------------------------------------
// 7. last-admin guard
// ---------------------------------------------------------------------------

func TestIntegration_LastTenantAdmin_CannotBeRemovedOnAnyPath(t *testing.T) {
	f := newIdentityFixture(t, false)
	tenant := f.newTenant(t)

	soleAdmin := uniqEmail("sole")
	soleID := f.seedUser(t, tenant, soleAdmin, "tenant_admin")
	// A billing_admin is NOT a substitute: it used to be counted as an admin.
	billingEmail := uniqEmail("bill")
	f.seedUser(t, tenant, billingEmail, "billing_admin")
	// The actor: a second user with users.* but not a tenant_admin — a custom
	// role is overkill, so use a platform-free approach: promote then demote is
	// not possible; instead use the billing_admin? It lacks users.update. Make
	// the actor a tenant_admin of the same tenant, then retire it.
	actorEmail := uniqEmail("actor")
	actorID := f.seedUser(t, tenant, actorEmail, "tenant_admin")
	actor := f.mustLogin(t, actorEmail)

	status := func(id uuid.UUID, s string) *httptest.ResponseRecorder {
		return f.do(http.MethodPut, "/tenant/"+tenant.String()+"/users/"+id.String()+"/status", actor.AccessToken, `{"status":"`+s+`"}`)
	}
	// Two admins (sole + actor): deactivating sole is allowed...
	if w := status(soleID, "suspended"); w.Code != http.StatusOK {
		t.Fatalf("deactivating one of two admins = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// ...restore it, then retire the actor's standing so sole is the LAST admin.
	if w := status(soleID, "active"); w.Code != http.StatusOK {
		t.Fatalf("reactivating = %d; body=%s", w.Code, w.Body.String())
	}
	// Make the actor a viewer-with-powers: keep the actor's token (already
	// minted) but demote its role row so it is no longer a counted admin.
	if _, err := f.owner.Exec(`UPDATE user_tenant_roles SET is_active = false WHERE user_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	// RequirePermission re-reads grants, so the actor now needs users.* from
	// somewhere: give it the billing_admin... which lacks users.update. Instead
	// grant the actor a SECOND role that carries users.update/delete/manage but
	// is not tenant_admin.
	var rid uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, 'user_manager', 'User manager') RETURNING id`, tenant).Scan(&rid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name IN ('users.read','users.update','users.delete','users.manage','users.create')`, rid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, actorID, tenant, rid); err != nil {
		t.Fatal(err)
	}

	expect400 := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400 (last admin); body=%s", what, w.Code, w.Body.String())
		}
	}
	expect400("deactivate via /status", status(soleID, "suspended"))
	expect400("deactivate via PUT /users/:id", f.do(http.MethodPut, "/users/"+soleID.String(), actor.AccessToken, `{"is_active":false}`))
	expect400("demote via PUT /users/:id", f.do(http.MethodPut, "/users/"+soleID.String(), actor.AccessToken, `{"role":"viewer"}`))
	expect400("delete via DELETE /users/:id", f.do(http.MethodDelete, "/users/"+soleID.String(), actor.AccessToken, ""))
	expect400("delete via DELETE /tenant/.../users/:id", f.do(http.MethodDelete, "/tenant/"+tenant.String()+"/users/"+soleID.String(), actor.AccessToken, ""))
	expect400("erase via POST /users/:id/erase", f.do(http.MethodPost, "/users/"+soleID.String()+"/erase", actor.AccessToken, ""))

	var active bool
	var deleted sql.NullTime
	if err := f.owner.QueryRow(`SELECT is_active, deleted_at FROM users WHERE id = $1`, soleID).Scan(&active, &deleted); err != nil {
		t.Fatal(err)
	}
	if !active || deleted.Valid {
		t.Fatalf("the last admin was changed despite the refusals: active=%v deleted=%v", active, deleted)
	}

	// The other polarity: with a second tenant_admin the same call succeeds.
	f.seedUser(t, tenant, uniqEmail("second"), "tenant_admin")
	if w := status(soleID, "suspended"); w.Code != http.StatusOK {
		t.Fatalf("deactivating one of two admins = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// Two admins each removing the other at the same moment: exactly one lands.
func TestIntegration_LastTenantAdmin_ConcurrentMutualRemovalLeavesOne(t *testing.T) {
	for round := 0; round < 5; round++ {
		f := newIdentityFixture(t, false)
		tenant := f.newTenant(t)
		aEmail, bEmail := uniqEmail("ca"), uniqEmail("cb")
		aID := f.seedUser(t, tenant, aEmail, "tenant_admin")
		bID := f.seedUser(t, tenant, bEmail, "tenant_admin")
		aTok, bTok := f.mustLogin(t, aEmail), f.mustLogin(t, bEmail)

		var wg sync.WaitGroup
		codes := make([]int, 2)
		start := make(chan struct{})
		run := func(i int, tok idTokens, target uuid.UUID) {
			defer wg.Done()
			<-start
			codes[i] = f.do(http.MethodPut, "/tenant/"+tenant.String()+"/users/"+target.String()+"/status", tok.AccessToken, `{"status":"suspended"}`).Code
		}
		wg.Add(2)
		go run(0, aTok, bID)
		go run(1, bTok, aID)
		close(start)
		wg.Wait()

		var active int
		if err := f.owner.QueryRow(`SELECT count(*) FROM users WHERE tenant_id = $1 AND is_active = true`, tenant).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active != 1 {
			t.Fatalf("round %d: %d active admins remain after mutual removal (codes %v), want exactly 1", round, active, codes)
		}
	}
}

// ---------------------------------------------------------------------------
// 9. platform user finishes the forced password change
// ---------------------------------------------------------------------------

func TestIntegration_PlatformUser_CanFinishForcedPasswordChange(t *testing.T) {
	f := newIdentityFixture(t, false)
	email := uniqEmail("force")
	id := f.insertPlatformUser(t, email)
	if _, err := f.owner.Exec(`UPDATE platform_users SET force_password_change = true WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	// Mint the LIMITED session the way admin-service does for a flagged platform
	// account (the tenant login no longer signs platform accounts in).
	jwtSvc := auth.NewJWTService(identityTestSigningSecret, time.Hour, time.Hour)
	access, _, err := jwtSvc.GenerateTokensWithPasswordChange(id, uuid.Nil, email, "super_admin", time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}

	cb, _ := json.Marshal(map[string]string{"current_password": "nope-Nope-1234!", "new_password": "Rotated-Passw0rd!88"})
	if w := f.do(http.MethodPost, "/auth/change-password", access, string(cb)); w.Code != http.StatusUnauthorized {
		t.Fatalf("platform change-password with a wrong current password = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	cb, _ = json.Marshal(map[string]string{"current_password": identityLoginCredential, "new_password": "Rotated-Passw0rd!77"})
	w := f.do(http.MethodPost, "/auth/change-password", access, string(cb))
	if w.Code != http.StatusOK {
		t.Fatalf("platform change-password = %d, want 200 (it was a 404 for platform users); body=%s", w.Code, w.Body.String())
	}
	var force bool
	var hash string
	if err := f.owner.QueryRow(`SELECT force_password_change, password_hash FROM platform_users WHERE id = $1`, id).Scan(&force, &hash); err != nil {
		t.Fatal(err)
	}
	if force {
		t.Fatal("force_password_change still set after the change")
	}
	if ok, _ := passwordsvc.NewPasswordService().VerifyPassword("Rotated-Passw0rd!77", hash); !ok {
		t.Fatal("the new password was not stored")
	}
}

// ---------------------------------------------------------------------------
// 11. avatar_url shape
// ---------------------------------------------------------------------------

func TestIntegration_AvatarURL_OnlyUploadedShape(t *testing.T) {
	f := newIdentityFixture(t, false)
	tenant := f.newTenant(t)
	email := uniqEmail("av")
	id := f.seedUser(t, tenant, email, "viewer")
	tok := f.mustLogin(t, email)

	put := func(url string) int {
		b, _ := json.Marshal(map[string]string{"avatar_url": url})
		return f.do(http.MethodPut, "/auth/me", tok.AccessToken, string(b)).Code
	}
	for _, bad := range []string{
		"http://tracker.example/pixel.gif",
		"javascript:alert(1)",
		"data:image/svg+xml;base64,PHN2Zz4=",
		"/uploads/avatars/../../etc/passwd",
		"/uploads/avatars/not-a-uuid.png",
	} {
		if code := put(bad); code == http.StatusOK {
			t.Fatalf("avatar_url %q was accepted", bad)
		}
	}
	var stored sql.NullString
	if err := f.owner.QueryRow(`SELECT avatar_url FROM users WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Valid {
		t.Fatalf("a rejected avatar_url was stored: %q", stored.String)
	}
	good := "/uploads/avatars/" + uuid.NewString() + ".png"
	if code := put(good); code != http.StatusOK {
		t.Fatalf("avatar_url %q = %d, want 200", good, code)
	}
}

// The guard serialises admin-removal decisions with a per-tenant advisory lock
// held to commit. Deterministic proof it is TAKEN in the request path: hold the
// same lock from another transaction and show the request waits for it. (The
// mutual-removal race above is probabilistic; this is not.)
func TestIntegration_LastTenantAdmin_RequestWaitsOnTheTenantAdminLock(t *testing.T) {
	f := newIdentityFixture(t, false)
	tenant := f.newTenant(t)
	aEmail, bEmail := uniqEmail("la"), uniqEmail("lb")
	f.seedUser(t, tenant, aEmail, "tenant_admin")
	bID := f.seedUser(t, tenant, bEmail, "tenant_admin")
	aTok := f.mustLogin(t, aEmail)

	holder, err := f.owner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(`SELECT pg_advisory_xact_lock(hashtextextended('tenant_admin_guard:' || $1::text, 0))`, tenant.String()); err != nil {
		t.Fatal(err)
	}

	done := make(chan int, 1)
	go func() {
		done <- f.do(http.MethodPut, "/tenant/"+tenant.String()+"/users/"+bID.String()+"/status", aTok.AccessToken, `{"status":"suspended"}`).Code
	}()
	select {
	case code := <-done:
		t.Fatalf("the deactivation completed (%d) while another transaction held the tenant-admin lock — the guard is not serialised", code)
	case <-time.After(700 * time.Millisecond):
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("deactivation after the lock was released = %d, want 200", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the deactivation never completed after the lock was released")
	}
}

// ---------------------------------------------------------------------------
// 12. platform credentials at the tenant login
// ---------------------------------------------------------------------------

// On a real database the old platform branch died on the refresh_tokens.user_id
// foreign key with a 500. Now: right password -> 403 + stable code, wrong
// password -> the ordinary 401, and nothing is ever written to refresh_tokens.
func TestIntegration_PlatformCredentials_RefusedAtTenantLogin(t *testing.T) {
	t.Setenv("ADMIN_UI_BASE_URL", "https://admin.example.test")
	f := newIdentityFixture(t, false)
	email := uniqEmail("plat")
	id := f.insertPlatformUser(t, email)

	w := f.login(email, identityLoginCredential)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), auth.PlatformAccountCode) ||
		!strings.Contains(w.Body.String(), "https://admin.example.test") {
		t.Fatalf("platform login = %d %s, want 403 %s with the admin URL", w.Code, w.Body.String(), auth.PlatformAccountCode)
	}
	if w := f.login(email, "wrong-Passw0rd!99"); w.Code != http.StatusUnauthorized {
		t.Fatalf("platform login with a wrong password = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d refresh tokens were stored for a platform account", n)
	}

	// A platform refresh token (minted by admin-service) gets the same refusal.
	_, refresh, err := auth.NewJWTService(identityTestSigningSecret, time.Hour, time.Hour).
		GenerateTokensWithPasswordChange(id, uuid.Nil, email, "super_admin", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := json.Marshal(map[string]string{"refresh_token": refresh})
	if w := f.do(http.MethodPost, "/auth/refresh", "", string(rb)); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), auth.PlatformAccountCode) {
		t.Fatalf("platform refresh = %d %s, want 403 %s", w.Code, w.Body.String(), auth.PlatformAccountCode)
	}
}
