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
	pwAffected    int64
	pwErr         error
	deleteErr     error
	// passwordMinLength stands in for platform_settings.password_min_length. The
	// zero value means "unset", which the handler clamps to the built-in floor —
	// same as the repository's fail-safe read.
	passwordMinLength int
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
	now := time.Now().UTC()
	return s.createID, now, now, s.createErr
}
func (s *stubPlatformUserStore) UpdatePlatformUser(context.Context, string, platformUserUpdateFields) error {
	return s.updateErr
}
func (s *stubPlatformUserStore) UpdatePlatformUserPassword(context.Context, string, string, bool) (int64, error) {
	return s.pwAffected, s.pwErr
}
func (s *stubPlatformUserStore) DeletePlatformUser(context.Context, string) error {
	return s.deleteErr
}
func (s *stubPlatformUserStore) CreateInvitedPlatformUser(context.Context, platformUserInviteInsert) (string, time.Time, error) {
	return s.createID, time.Now().UTC(), s.createErr
}
func (s *stubPlatformUserStore) InviterDisplayName(context.Context, string) string { return "" }
func (s *stubPlatformUserStore) EnabledAdminSsoProviderLabels(context.Context) []string {
	return nil
}
func (s *stubPlatformUserStore) ActiveUserEmail(context.Context, string) (string, bool, error) {
	return s.user.Email, s.userFound, s.userErr
}
func (s *stubPlatformUserStore) StorePasswordResetToken(context.Context, string, string, time.Time) error {
	return s.updateErr
}

// --- engine -----------------------------------------------------------------

func platformUserEngine(store platformUserStore, hasher passwordHasher, currentUserID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase + "/admin/users")
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
	return models.PlatformUser{
		ID:                   uuid.New(),
		Email:                "admin@vistaplatform.local",
		FirstName:            "Grace",
		LastName:             "Hopper",
		IsActive:             true,
		RoleID:               uuid.New(),
		EmailVerified:        true,
		ForcePasswordChange:  false,
		PasswordChangedAt:    &changed,
		LastLoginAt:          &login,
		Role:                 samplePlatformUserRole(),
		InvitedBy:            &inviter,
		InvitationAcceptedAt: &accepted,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// minimalPlatformUser leaves role + nullable/omitempty fields unset.
func minimalPlatformUser() models.PlatformUser {
	now := time.Now().UTC()
	return models.PlatformUser{
		ID:        uuid.New(),
		Email:     "minimal@vistaplatform.local",
		FirstName: "Min",
		LastName:  "Imal",
		IsActive:  false,
		RoleID:    uuid.New(),
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
	eng := platformUserEngine(&stubPlatformUserStore{pwAffected: 1}, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+uuid.New().String()+"/set-password", strings.NewReader(`{"new_password":"`+strongPassword()+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// no row updated → 404.
func TestContract_AdminSetPassword_404(t *testing.T) {
	sv := loadSpec(t)
	eng := platformUserEngine(&stubPlatformUserStore{pwAffected: 0}, stubPasswordHasher{}, "")
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
