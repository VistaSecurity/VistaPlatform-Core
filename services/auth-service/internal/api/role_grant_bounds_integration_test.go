package api

// Wiring coverage for the legacy-role-assignment grant ceiling.
//
// The unit tests next door (users_test.go) prove ensureRoleGrantableByName and
// assignUserRole refuse a role whose permissions the actor does not hold — by
// calling those functions directly. That is necessary but NOT sufficient: it
// leaves every CALL SITE unpinned, so the ceiling can be deleted from a handler
// and the suite stays green. That is precisely how a privilege-escalation fix
// rots.
//
// These tests drive the REAL gin handlers against a REAL Postgres and assert
// the refusal reaches the client, so removing the guard from any of the four
// enforcement points fails a named test:
//
//	users.go        CreateUser           -> ensureRoleGrantableByName pre-check
//	users.go        assignUserRole       -> validateRoleGrantable (UpdateUser's only ceiling)
//	users.go        InviteTenantMember   -> ensureRoleGrantableByName pre-check
//	invitations.go  materializeInvitedUser -> ensureRoleGrantableByName re-check at ACCEPT
//
// Each site is covered in BOTH directions: an actor who lacks the target role's
// permissions is refused, and an actor who holds them still succeeds. A guard
// that refused everything would pass a refusal-only test and break the product.
//
// The acceptance test matters most: it is what stops an invitation minted before
// the fix (or by an admin who has since lost permission) from materializing an
// elevated role at redemption time. Note that the accept path's 403 alone does
// NOT pin the pre-check — assignUserRole would refuse a moment later and produce
// the same status — so it also asserts the invited user was never created and
// the invitation is still pending, which only holds if the check runs BEFORE
// materialization.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// strongPassword satisfies ValidatePasswordStrength on both the create and the
// invitation-accept paths.
const strongPassword = "Str0ng!Passw0rd#2026"

type grantBoundsEnv struct {
	owner       *sql.DB // production "db" handle
	bypass      *sql.DB // production "bypassDB" handle
	tenant      uuid.UUID
	cfg         *config.Config
	jwt         *auth.JWTService
	authService *auth.AuthService
}

// newGrantBoundsEnv stands up a throwaway tenant with the five built-in roles
// and their real permission grants (the same reconciliation production runs), on
// an unlimited-seat tier so the seat gate is never the thing under test.
func newGrantBoundsEnv(t *testing.T) *grantBoundsEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	bypass := connectAsBypassRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	// 'community' seeds max_users unlimited; without a tier every capacity cap
	// resolves to the conservative catalogue default and CreateUser/Invite would
	// 403 on the seat gate instead of the ceiling.
	if _, err := owner.Exec(`
		UPDATE tenants SET subscription_tier_id = (SELECT id FROM subscription_tiers WHERE name = 'community')
		WHERE id = $1`, tenant); err != nil {
		t.Fatalf("assign subscription tier: %v", err)
	}

	jwt := auth.NewJWTService("grant-bounds-test-secret", time.Hour, 24*time.Hour)
	authService := auth.NewAuthService(owner, bypass, nil, jwt)
	if err := authService.EnsureDefaultTenantRoles(tenant); err != nil {
		t.Fatalf("EnsureDefaultTenantRoles: %v", err)
	}

	return &grantBoundsEnv{
		owner:       owner,
		bypass:      bypass,
		tenant:      tenant,
		cfg:         &config.Config{CORSOrigins: []string{"https://tenant.example.com"}},
		jwt:         jwt,
		authService: authService,
	}
}

// newUserWithRole inserts a tenant member holding roleName and returns its id.
func (e *grantBoundsEnv) newUserWithRole(t *testing.T, emailAddr, roleName string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := e.owner.Exec(`
		INSERT INTO users (id, tenant_id, email, first_name, last_name, is_active, email_verified)
		VALUES ($1, $2, $3, 'Test', 'User', true, true)`, id, e.tenant, emailAddr); err != nil {
		t.Fatalf("seed user %s: %v", emailAddr, err)
	}
	if roleName != "" {
		if _, err := e.owner.Exec(`
			INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
			SELECT $1, $2, id, NOW(), true FROM tenant_roles WHERE tenant_id = $2 AND name = $3`,
			id, e.tenant, roleName); err != nil {
			t.Fatalf("assign role %s to %s: %v", roleName, emailAddr, err)
		}
	}
	// Guard against a silent no-op seed: the ceiling is only meaningful if the
	// actor really holds (or really lacks) the permissions we think it does.
	if roleName != "" {
		var n int
		if err := e.owner.QueryRow(`
			SELECT COUNT(*) FROM user_tenant_roles ur
			JOIN tenant_roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND r.name = $2 AND ur.is_active = true`, id, roleName).Scan(&n); err != nil {
			t.Fatalf("verify seeded role: %v", err)
		}
		if n != 1 {
			t.Fatalf("seeded role rows for %s = %d, want 1 (role %q missing?)", emailAddr, n, roleName)
		}
	}
	return id
}

// assertCeilingIsMeaningful fails the test if `grantee` is not in fact a strict
// escalation over `actorRole` — i.e. if the negative case could pass for the
// wrong reason.
func (e *grantBoundsEnv) assertCeilingIsMeaningful(t *testing.T, actorRole, granteeRole string) {
	t.Helper()
	var missing int
	if err := e.owner.QueryRow(`
		SELECT COUNT(*) FROM tenant_role_permissions grp
		JOIN tenant_roles gr ON gr.id = grp.role_id
		WHERE gr.tenant_id = $1 AND gr.name = $2
		  AND grp.permission_id NOT IN (
			SELECT arp.permission_id FROM tenant_role_permissions arp
			JOIN tenant_roles ar ON ar.id = arp.role_id
			WHERE ar.tenant_id = $1 AND ar.name = $3
		  )`, e.tenant, granteeRole, actorRole).Scan(&missing); err != nil {
		t.Fatalf("compare role grants: %v", err)
	}
	if missing == 0 {
		t.Fatalf("role %q holds every permission of %q — the negative case proves nothing", actorRole, granteeRole)
	}
}

// engine wires one handler behind an authenticated-context middleware, the way
// the other handler tests in this package do.
func (e *grantBoundsEnv) engine(actorID uuid.UUID, register func(*gin.RouterGroup)) *gin.Engine {
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", e.tenant.String())
		c.Set("userID", actorID.String())
		c.Next()
	})
	register(grp)
	return r
}

func (e *grantBoundsEnv) roleOf(t *testing.T, userID uuid.UUID) string {
	t.Helper()
	var name string
	err := e.owner.QueryRow(`
		SELECT r.name FROM user_tenant_roles ur
		JOIN tenant_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.is_active = true
		ORDER BY ur.assigned_at DESC LIMIT 1`, userID).Scan(&name)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("read assigned role: %v", err)
	}
	return name
}

func (e *grantBoundsEnv) userIDByEmail(t *testing.T, emailAddr string) (uuid.UUID, bool) {
	t.Helper()
	var id uuid.UUID
	err := e.owner.QueryRow(`SELECT id FROM users WHERE tenant_id = $1 AND lower(email) = lower($2) AND deleted_at IS NULL`,
		e.tenant, emailAddr).Scan(&id)
	if err == sql.ErrNoRows {
		return uuid.Nil, false
	}
	if err != nil {
		t.Fatalf("look up user %s: %v", emailAddr, err)
	}
	return id, true
}

// assertPermissionNotHeld checks the refusal shape the frontend keys on.
func assertPermissionNotHeld(t *testing.T, status int, body string, site string) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("%s: status = %d, want 403 — the grant ceiling is NOT enforced at this call site; body=%s", site, status, body)
	}
	var payload struct {
		Code    string   `json:"code"`
		Missing []string `json:"missing_permissions"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("%s: decode body %q: %v", site, body, err)
	}
	if payload.Code != "permission_not_held" {
		t.Fatalf("%s: code = %q, want permission_not_held (403 from a different guard does not prove the ceiling ran); body=%s", site, payload.Code, body)
	}
	if len(payload.Missing) == 0 {
		t.Fatalf("%s: missing_permissions empty, want the un-held permissions named; body=%s", site, body)
	}
}

// --- CreateUser (users.go) --------------------------------------------------

// Deleting ensureRoleGrantableByName from CreateUser makes this fail: the
// handler runs on to create the user and answers 500 from assignUserRole.
func TestIntegration_CreateUser_RefusesRoleAboveActorCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertCeilingIsMeaningful(t, "security_admin", "tenant_admin")
	actor := e.newUserWithRole(t, "sec-admin-create@example.com", "security_admin")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.POST("/users", CreateUser(e.owner, e.bypass, e.cfg))
	})
	const target = "escalated-create@example.com"
	body := fmt.Sprintf(`{"email":%q,"password":%q,"first_name":"Esc","last_name":"Alate","role":"tenant_admin"}`, target, strongPassword)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/users", strings.NewReader(body))

	assertPermissionNotHeld(t, w.Code, w.Body.String(), "CreateUser")
	if _, found := e.userIDByEmail(t, target); found {
		t.Fatal("CreateUser: the user was created despite the refusal — the ceiling must run BEFORE the INSERT")
	}
}

func TestIntegration_CreateUser_AllowsRoleWithinActorCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	actor := e.newUserWithRole(t, "sec-admin-create-ok@example.com", "security_admin")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.POST("/users", CreateUser(e.owner, e.bypass, e.cfg))
	})
	const target = "peer-create@example.com"
	body := fmt.Sprintf(`{"email":%q,"password":%q,"first_name":"Peer","last_name":"User","role":"security_admin"}`, target, strongPassword)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/users", strings.NewReader(body))

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateUser: status = %d, want 201 — an actor granting its OWN role must still succeed; body=%s", w.Code, w.Body.String())
	}
	id, found := e.userIDByEmail(t, target)
	if !found {
		t.Fatal("CreateUser: 201 but no user row")
	}
	if got := e.roleOf(t, id); got != "security_admin" {
		t.Fatalf("CreateUser: assigned role = %q, want security_admin", got)
	}
}

// --- UpdateUser (users.go -> assignUserRole's validateRoleGrantable) --------

// UpdateUser has no pre-check: its only ceiling is the one inside
// assignUserRole. Deleting that block makes this fail with 200.
func TestIntegration_UpdateUser_RefusesRoleAboveActorCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertCeilingIsMeaningful(t, "security_admin", "tenant_admin")
	actor := e.newUserWithRole(t, "sec-admin-update@example.com", "security_admin")
	target := e.newUserWithRole(t, "target-update@example.com", "viewer")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.PUT("/users/:id", UpdateUser(e.owner))
	})
	w := do(eng, http.MethodPut, "/api/v1/auth-service/users/"+target.String(), strings.NewReader(`{"role":"tenant_admin"}`))

	assertPermissionNotHeld(t, w.Code, w.Body.String(), "UpdateUser")
	if got := e.roleOf(t, target); got != "viewer" {
		t.Fatalf("UpdateUser: target role = %q, want it left at viewer — the escalated role was assigned anyway", got)
	}
}

func TestIntegration_UpdateUser_AllowsRoleWithinActorCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	actor := e.newUserWithRole(t, "sec-admin-update-ok@example.com", "security_admin")
	target := e.newUserWithRole(t, "target-update-ok@example.com", "viewer")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.PUT("/users/:id", UpdateUser(e.owner))
	})
	w := do(eng, http.MethodPut, "/api/v1/auth-service/users/"+target.String(), strings.NewReader(`{"role":"security_admin"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateUser: status = %d, want 200 — an actor granting its OWN role must still succeed; body=%s", w.Code, w.Body.String())
	}
	if got := e.roleOf(t, target); got != "security_admin" {
		t.Fatalf("UpdateUser: target role = %q, want security_admin", got)
	}
}

// --- InviteTenantMember (users.go) -----------------------------------------

// The invite-create path never reaches assignUserRole, so the pre-check is its
// ONLY ceiling. Deleting it makes this fail with 201 and a pending invitation
// carrying the escalated role.
func TestIntegration_InviteTenantMember_RefusesRoleAboveActorCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertCeilingIsMeaningful(t, "security_admin", "tenant_admin")
	actor := e.newUserWithRole(t, "sec-admin-invite@example.com", "security_admin")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.POST("/tenant/:tenantId/users/invite", InviteTenantMember(e.cfg, e.owner, e.bypass, e.authService))
	})
	const target = "escalated-invite@example.com"
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+e.tenant.String()+"/users/invite",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"role":"admin"}`, target)))

	assertPermissionNotHeld(t, w.Code, w.Body.String(), "InviteTenantMember")
	var invites int
	if err := e.owner.QueryRow(`SELECT COUNT(*) FROM public.invitations WHERE tenant_id = $1 AND lower(email) = $2`,
		e.tenant, target).Scan(&invites); err != nil {
		t.Fatalf("count invitations: %v", err)
	}
	if invites != 0 {
		t.Fatalf("InviteTenantMember: %d invitation(s) written despite the refusal — an escalating invite is still redeemable", invites)
	}
}

func TestIntegration_InviteTenantMember_AllowsRoleWithinActorCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	actor := e.newUserWithRole(t, "sec-admin-invite-ok@example.com", "security_admin")

	eng := e.engine(actor, func(g *gin.RouterGroup) {
		g.POST("/tenant/:tenantId/users/invite", InviteTenantMember(e.cfg, e.owner, e.bypass, e.authService))
	})
	const target = "peer-invite@example.com"
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+e.tenant.String()+"/users/invite",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"role":"security_admin"}`, target)))

	if w.Code != http.StatusCreated {
		t.Fatalf("InviteTenantMember: status = %d, want 201 — an actor inviting into its OWN role must still succeed; body=%s", w.Code, w.Body.String())
	}
	var role string
	if err := e.owner.QueryRow(`SELECT role FROM public.invitations WHERE tenant_id = $1 AND lower(email) = $2 AND status = 'pending'`,
		e.tenant, target).Scan(&role); err != nil {
		t.Fatalf("read created invitation: %v", err)
	}
	if role != "security_admin" {
		t.Fatalf("InviteTenantMember: invitation role = %q, want security_admin", role)
	}
}

// --- AcceptInvitation (invitations.go -> materializeInvitedUser) ------------

// The one that matters: an invitation whose inviter does NOT hold the invited
// role's permissions must not materialize that role at redemption — including
// an invitation minted before this guard existed, or by an admin who has since
// been demoted.
//
// Deleting the re-check from materializeInvitedUser still answers 403 (the
// ceiling inside assignUserRole catches it a moment later), so the status alone
// proves nothing here. The user row and the invitation status are what pin the
// call site: without the re-check the user IS created and only the role
// assignment fails, leaving a roleless account behind.
func TestIntegration_AcceptInvitation_RefusesRoleAboveInviterCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	e.assertCeilingIsMeaningful(t, "security_admin", "tenant_admin")
	inviter := e.newUserWithRole(t, "demoted-inviter@example.com", "security_admin")

	const invitee = "escalated-accept@example.com"
	invitationID, rawToken, err := createInvitation(e.owner, e.tenant, invitee, "tenant_admin", inviter)
	if err != nil {
		t.Fatalf("createInvitation: %v", err)
	}

	eng := gin.New()
	eng.POST("/auth/invitations/accept", AcceptInvitation(e.cfg, e.owner, e.bypass, e.jwt))
	w := do(eng, http.MethodPost, "/auth/invitations/accept",
		strings.NewReader(fmt.Sprintf(`{"token":%q,"password":%q}`, rawToken, strongPassword)))

	assertPermissionNotHeld(t, w.Code, w.Body.String(), "AcceptInvitation")

	if id, found := e.userIDByEmail(t, invitee); found {
		t.Fatalf("AcceptInvitation: user %s was materialized despite the refusal (role=%q) — the re-check must run BEFORE the INSERT", id, e.roleOf(t, id))
	}
	var status string
	if err := e.owner.QueryRow(`SELECT status FROM public.invitations WHERE id = $1`, invitationID).Scan(&status); err != nil {
		t.Fatalf("read invitation status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("AcceptInvitation: invitation status = %q, want it left pending", status)
	}
}

func TestIntegration_AcceptInvitation_AllowsRoleWithinInviterCeiling(t *testing.T) {
	e := newGrantBoundsEnv(t)
	inviter := e.newUserWithRole(t, "ok-inviter@example.com", "security_admin")

	const invitee = "peer-accept@example.com"
	invitationID, rawToken, err := createInvitation(e.owner, e.tenant, invitee, "security_admin", inviter)
	if err != nil {
		t.Fatalf("createInvitation: %v", err)
	}

	eng := gin.New()
	eng.POST("/auth/invitations/accept", AcceptInvitation(e.cfg, e.owner, e.bypass, e.jwt))
	w := do(eng, http.MethodPost, "/auth/invitations/accept",
		strings.NewReader(fmt.Sprintf(`{"token":%q,"password":%q}`, rawToken, strongPassword)))

	if w.Code != http.StatusOK {
		t.Fatalf("AcceptInvitation: status = %d, want 200 — an invitation within the inviter's ceiling must still be redeemable; body=%s", w.Code, w.Body.String())
	}
	id, found := e.userIDByEmail(t, invitee)
	if !found {
		t.Fatal("AcceptInvitation: 200 but no user row")
	}
	if got := e.roleOf(t, id); got != "security_admin" {
		t.Fatalf("AcceptInvitation: assigned role = %q, want security_admin", got)
	}
	var status string
	if err := e.owner.QueryRow(`SELECT status FROM public.invitations WHERE id = $1`, invitationID).Scan(&status); err != nil {
		t.Fatalf("read invitation status: %v", err)
	}
	if status != "accepted" {
		t.Fatalf("AcceptInvitation: invitation status = %q, want accepted", status)
	}
}
