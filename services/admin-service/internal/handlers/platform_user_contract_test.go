package handlers

// Contract test for the platform-user HTTP surface (admin-ui Users page):
// /admin/users CRUD + set-password, and GET /auth/me.
//
// The ListPlatformUsers/GetPlatformUser/... free-funcs previously ran SQL
// inline; this slice landed a behaviour-preserving repo extraction (queries
// moved verbatim into platformUserRepository behind the platformUserStore
// interface — see platform_user_repository.go). Password hashing is taken via
// the passwordHasher seam. The public free-funcs keep their (db *sql.DB)
// signatures (server.go is unchanged); the contract test drives the inner
// *WithStore variants over httptest with in-memory stubs — no database — and
// asserts the bodies against api/openapi/admin-service.openapi.yaml.
//
// Scope: the two email/SMTP/branding-coupled handlers (InvitePlatformUser,
// AdminSendPasswordReset) are intentionally NOT covered by this slice.
//
// The spec-loading / assertConforms / doRequest harness and apiBase const
// are shared with tenant_billing_contract_test.go (same package, same spec) and
// reused here rather than redefined.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// --- in-memory stubs --------------------------------------------------------

type stubPasswordHasher struct{ hashErr error }

func (s stubPasswordHasher) HashPassword(string) (string, error) {
	return "hashed-password", s.hashErr
}

type stubPlatformUserStore struct {
	users         []models.PlatformUser
	total         int
	listErr       error
	user          models.PlatformUser
	userFound     bool
	userErr       error
	roleExists    bool
	roleErr       error
	emailVerifReq bool
	createID      string
	createErr     error
	updateErr     error
	pwErr         error
	deleteErr     error
	// passwordMinLength stands in for platform_settings.password_min_length. The
	// zero value means "unset", which the handler clamps to the built-in floor —
	// same as the repository's fail-safe read.
	passwordMinLength int

	// Role-assignment seams (platform_role_assignment.go). Zero values PERMIT,
	// so the contract tests above describe the authorized path; the
	// escalation tests in platform_role_assignment_test.go set these to deny.
	denyAssign bool
	permErr    error
	// missingByRole maps a role id to the permissions it grants that the
	// caller lacks. Absent → the role is a subset of the caller's permissions.
	missingByRole map[string][]string
	// roleRefs maps a user id to its current role. nil map → every user
	// exists with no role; non-nil → users absent from the map are not found.
	roleRefs  map[string]platformUserRoleRef
	roleNames map[uuid.UUID]string
	// otherSuperAdmins stands in for the repository's in-transaction guard:
	// when it is 0, a write that takes a super_admin (per roleRefs) out of the
	// active set — deactivate, delete, or a role change away from super_admin —
	// returns errLastActiveSuperAdmin and writes nothing.
	otherSuperAdmins int
	// updated records the last UpdatePlatformUser write, so a test can prove a
	// denied request wrote nothing.
	updated *platformUserUpdateFields
	created bool
	// permChecks records, in order, every permission name passed to
	// HasPlatformPermission.
	permChecks []string
	// passwordSet / resetStored / deleted record the other writes, for the same
	// "a denied request wrote nothing" assertions.
	passwordSet bool
	resetStored bool
	deleted     bool

	// onRoleRead, when set, runs once — right after the handler's FIRST
	// PlatformUserRole read, i.e. between its rank check and its write. A test
	// uses it to change the target's role (roleRefs) the way a concurrent
	// operator would. The writes then behave like the repository's
	// conditional UPDATEs: when the target's current role (per roleRefs) is not
	// the expectedRole the handler passes, they return errPlatformUserChanged
	// and write nothing.
	onRoleRead func()
	// expectedRoles records the expectedRole passed to every conditional write.
	expectedRoles []*uuid.UUID
}

// staleRole mirrors "role_id IS NOT DISTINCT FROM $expected": true when the
// target no longer holds the role the handler checked.
func (s *stubPlatformUserStore) staleRole(id string, expected *uuid.UUID) bool {
	s.expectedRoles = append(s.expectedRoles, expected)
	if s.roleRefs == nil {
		return false
	}
	cur := s.roleRefs[id].RoleID
	if cur == nil || expected == nil {
		return cur != expected
	}
	return *cur != *expected
}

// removesLastSuperAdmin mirrors platformUserRepository.withLastSuperAdminGuard.
func (s *stubPlatformUserStore) removesLastSuperAdmin(id string, removes bool) bool {
	if s.roleRefs == nil || s.otherSuperAdmins > 0 || !removes {
		return false
	}
	return s.roleRefs[id].RoleName == superAdminRoleName
}

func (s *stubPlatformUserStore) ListPlatformUsers(context.Context, platformUserListFilters) ([]models.PlatformUser, int, error) {
	return s.users, s.total, s.listErr
}
func (s *stubPlatformUserStore) GetPlatformUser(context.Context, string) (models.PlatformUser, bool, error) {
	return s.user, s.userFound, s.userErr
}
func (s *stubPlatformUserStore) RoleExists(context.Context, string) (bool, error) {
	return s.roleExists, s.roleErr
}
func (s *stubPlatformUserStore) AdminEmailVerificationRequired(context.Context) bool {
	return s.emailVerifReq
}
func (s *stubPlatformUserStore) PasswordMinLength(context.Context) int {
	return s.passwordMinLength
}
func (s *stubPlatformUserStore) CreatePlatformUser(context.Context, platformUserInsert) (string, time.Time, time.Time, error) {
	s.created = true
	now := time.Now().UTC()
	return s.createID, now, now, s.createErr
}
func (s *stubPlatformUserStore) UpdatePlatformUser(_ context.Context, id string, expected *uuid.UUID, f platformUserUpdateFields) error {
	if s.staleRole(id, expected) {
		return errPlatformUserChanged
	}
	removes := (f.IsActive != nil && !*f.IsActive) ||
		(f.RoleID != nil && s.roleNames[*f.RoleID] != superAdminRoleName)
	if s.removesLastSuperAdmin(id, removes) {
		return errLastActiveSuperAdmin
	}
	s.updated = &f
	if s.updateErr == nil && f.RoleID != nil && s.roleRefs != nil {
		// Mirror the write so a read-back (the role_changed audit) sees it.
		rid := *f.RoleID
		s.roleRefs[id] = platformUserRoleRef{RoleID: &rid, RoleName: s.roleNames[rid]}
	}
	return s.updateErr
}
func (s *stubPlatformUserStore) UpdatePlatformUserPassword(_ context.Context, id string, expected *uuid.UUID, _ string, _ bool) error {
	if s.staleRole(id, expected) {
		return errPlatformUserChanged
	}
	s.passwordSet = true
	return s.pwErr
}
func (s *stubPlatformUserStore) DeletePlatformUser(_ context.Context, id string, expected *uuid.UUID) error {
	if s.staleRole(id, expected) {
		return errPlatformUserChanged
	}
	if s.removesLastSuperAdmin(id, true) {
		return errLastActiveSuperAdmin
	}
	s.deleted = true
	return s.deleteErr
}
func (s *stubPlatformUserStore) CreateInvitedPlatformUser(context.Context, platformUserInviteInsert) (string, time.Time, error) {
	s.created = true
	return s.createID, time.Now().UTC(), s.createErr
}
func (s *stubPlatformUserStore) InviterDisplayName(context.Context, string) string { return "" }
func (s *stubPlatformUserStore) EnabledAdminSsoProviderLabels(context.Context) []string {
	return nil
}
func (s *stubPlatformUserStore) ActiveUserEmail(context.Context, string) (string, bool, error) {
	return s.user.Email, s.userFound, s.userErr
}
func (s *stubPlatformUserStore) StorePasswordResetToken(_ context.Context, id string, expected *uuid.UUID, _ string, _ time.Time) error {
	if s.staleRole(id, expected) {
		return errPlatformUserChanged
	}
	s.resetStored = true
	return s.updateErr
}

// HasPlatformPermission records every permission the handler asks about, and
// denies only the literal "platform_roles.assign" when denyAssign is set — so a
// handler that checks some other permission neither passes the escalation
// tests by accident nor escapes TestRoleAssign_ChecksPlatformRolesAssign.
func (s *stubPlatformUserStore) HasPlatformPermission(_ context.Context, _ string, permission string) (bool, error) {
	s.permChecks = append(s.permChecks, permission)
	if permission == "platform_roles.assign" && s.denyAssign {
		return false, s.permErr
	}
	return true, s.permErr
}
func (s *stubPlatformUserStore) RolePermissionsNotHeldBy(_ context.Context, _ string, roleID string) ([]string, error) {
	return s.missingByRole[roleID], nil
}
func (s *stubPlatformUserStore) PlatformUserRole(_ context.Context, userID string) (platformUserRoleRef, bool, error) {
	if s.onRoleRead != nil {
		defer func() {
			hook := s.onRoleRead
			s.onRoleRead = nil
			hook()
		}()
	}
	if s.roleRefs == nil {
		return platformUserRoleRef{}, true, nil
	}
	ref, ok := s.roleRefs[userID]
	return ref, ok, nil
}

// --- engine -----------------------------------------------------------------

func platformUserEngine(store platformUserStore, hasher passwordHasher, currentUserID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase + "/admin/users")
	// The acting operator, as AuthMiddleware + StringifyUserID leave it.
	grp.Use(func(c *gin.Context) { c.Set("userID", stubCallerID); c.Next() })
	grp.GET("", listPlatformUsersWithStore(store))
	grp.POST("", createPlatformUserWithStore(store, hasher))
	grp.GET("/:id", getPlatformUserWithStore(store))
	grp.PUT("/:id", updatePlatformUserWithStore(store))
	grp.DELETE("/:id", deletePlatformUserWithStore(store))
	grp.PUT("/:id/set-password", adminSetPasswordWithStore(store, hasher))

	// /auth/me sits outside the /admin/users group and reads userID from context.
	auth := r.Group(apiBase)
	auth.GET("/auth/me", func(c *gin.Context) {
		if currentUserID != "" {
			c.Set("userID", currentUserID)
		}
		c.Next()
	}, getCurrentPlatformUserWithStore(store))
	return r
}

const platformUserBase = apiBase + "/admin/users"

// stubCallerID is the operator every /admin/users request in these tests is
// made by.
const stubCallerID = "0a000000-0000-4000-8000-00000000ca11"

func strongPassword() string { return "Str0ng!Passw0rd" }

func samplePlatformUserRole() *models.PlatformRole {
	return &models.PlatformRole{
		ID:          uuid.New(),
		Name:        "super_admin",
		DisplayName: "Super Admin",
	}
}

func samplePlatformUser() models.PlatformUser {
	now := time.Now().UTC()
	login := now.Add(-2 * time.Hour)
	changed := now.Add(-24 * time.Hour)
	accepted := now.Add(-48 * time.Hour)
	inviter := uuid.New()
	role := samplePlatformUserRole()
	return models.PlatformUser{
		ID:                   uuid.New(),
		Email:                "admin@vistaplatform.local",
		FirstName:            "Grace",
		LastName:             "Hopper",
		IsActive:             true,
		RoleID:               &role.ID,
		EmailVerified:        true,
		ForcePasswordChange:  false,
		PasswordChangedAt:    &changed,
		LastLoginAt:          &login,
		Role:                 role,
		InvitedBy:            &inviter,
		InvitationAcceptedAt: &accepted,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// minimalPlatformUser leaves role + nullable/omitempty fields unset. It is a
// roleless user: the repository maps a NULL role_id to a nil RoleID, which
// must reach the wire as "role_id": null (never the zero UUID).
func minimalPlatformUser() models.PlatformUser {
	now := time.Now().UTC()
	return models.PlatformUser{
		ID:        uuid.New(),
		Email:     "minimal@vistaplatform.local",
		FirstName: "Min",
		LastName:  "Imal",
		IsActive:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// --- list -------------------------------------------------------------------

func TestContract_ListPlatformUsers_200(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{
		users: []models.PlatformUser{samplePlatformUser(), minimalPlatformUser()}, total: 2,
	}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodGet, platformUserBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformUserListResponse", w.Body.Bytes())
}

func TestContract_ListPlatformUsers_200_null(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{users: nil, total: 0}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodGet, platformUserBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformUserListResponse", w.Body.Bytes())
}

// --- get --------------------------------------------------------------------

func TestContract_GetPlatformUser_200(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{user: samplePlatformUser(), userFound: true}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodGet, platformUserBase+"/u1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "GetPlatformUserResponse", w.Body.Bytes())
}

func TestContract_GetPlatformUser_404(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{userFound: false}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodGet, platformUserBase+"/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- current (/auth/me) -----------------------------------------------------

func TestContract_GetCurrentPlatformUser_200(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{user: samplePlatformUser(), userFound: true}, stubPasswordHasher{}, uuid.New().String())
	w := doRequest(eng, http.MethodGet, apiBase+"/auth/me", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CurrentPlatformUserResponse", w.Body.Bytes())
}

// user row missing → 401.
func TestContract_GetCurrentPlatformUser_401(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{userFound: false}, stubPasswordHasher{}, uuid.New().String())
	w := doRequest(eng, http.MethodGet, apiBase+"/auth/me", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- create -----------------------------------------------------------------

func TestContract_CreatePlatformUser_201(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{roleExists: true, createID: uuid.New().String()}, stubPasswordHasher{}, "")
	body := `{"email":"new@vistaplatform.local","password":"` + strongPassword() + `","first_name":"New","last_name":"Admin","role_id":"` + uuid.New().String() + `"}`
	w := doRequest(eng, http.MethodPost, platformUserBase, strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CreatePlatformUserResponse", w.Body.Bytes())
}

func TestContract_CreatePlatformUser_400_missingFields(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPost, platformUserBase, strings.NewReader(`{"email":"x@y.com"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// role_id not found → 400.
func TestContract_CreatePlatformUser_400_invalidRole(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{roleExists: false}, stubPasswordHasher{}, "")
	body := `{"email":"new@vistaplatform.local","password":"` + strongPassword() + `","first_name":"New","last_name":"Admin","role_id":"` + uuid.New().String() + `"}`
	w := doRequest(eng, http.MethodPost, platformUserBase, strings.NewReader(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// duplicate email → 409.
func TestContract_CreatePlatformUser_409(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{roleExists: true, createErr: errPlatformUserExists}, stubPasswordHasher{}, "")
	body := `{"email":"dup@vistaplatform.local","password":"` + strongPassword() + `","first_name":"Dup","last_name":"Admin","role_id":"` + uuid.New().String() + `"}`
	w := doRequest(eng, http.MethodPost, platformUserBase, strings.NewReader(body))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- update -----------------------------------------------------------------

func TestContract_UpdatePlatformUser_200(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{roleExists: true}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+uuid.New().String(), strings.NewReader(`{"first_name":"Renamed","is_active":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_UpdatePlatformUser_400_invalidID(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/not-a-uuid", strings.NewReader(`{"first_name":"X"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdatePlatformUser_400_noFields(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+uuid.New().String(), strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// role_id provided but not found → 400.
func TestContract_UpdatePlatformUser_400_invalidRole(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{roleExists: false}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+uuid.New().String(), strings.NewReader(`{"role_id":"`+uuid.New().String()+`"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- set-password -----------------------------------------------------------

func TestContract_AdminSetPassword_200(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+uuid.New().String()+"/set-password", strings.NewReader(`{"new_password":"`+strongPassword()+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// unknown user → 404 (from the rank check's role lookup).
func TestContract_AdminSetPassword_404(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{roleRefs: map[string]platformUserRoleRef{}}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+uuid.New().String()+"/set-password", strings.NewReader(`{"new_password":"`+strongPassword()+`"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AdminSetPassword_400_invalidID(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/not-a-uuid/set-password", strings.NewReader(`{"new_password":"`+strongPassword()+`"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- delete -----------------------------------------------------------------

func TestContract_DeletePlatformUser_200(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodDelete, platformUserBase+"/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_DeletePlatformUser_400_invalidID(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodDelete, platformUserBase+"/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guard ------------------------------------------------------------

func TestContract_PlatformUser_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/PlatformUser")
	if err != nil {
		t.Fatalf("compile PlatformUser: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted PlatformUser, but it passed — the guardrail is not actually checking")
	}
}
