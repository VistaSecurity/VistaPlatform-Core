package api

// A sign-up identity provider needs a paid licence (settings-8, admin-ui
// review decision 11), driven through the REAL admin-service router against a
// real Postgres.
//
// Social sign-up is served only by auth-service's Enterprise build, so on Core
// a sign-up row used to save, show "Enabled", and do nothing. Creating one on
// Core is now refused with 402 and writes nothing; with an Enterprise or MSP
// licence it is created as before; an admin-login provider is Core and is
// created either way; and an existing sign-up row can still be updated and
// deleted once the licence has lapsed, so an operator can clean it up.
//
// Runs on a scratch database: the licence (platform_license) is install-global
// state, and writing it on the shared database would change the edition every
// concurrently running test binary sees. Needs TEST_DATABASE_URL (skips
// otherwise).

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const signupIdPSigningValue = "signup-idp-licence-test-signing-value"

type signupIdPEnv struct {
	t      *testing.T
	db     *sql.DB
	srv    *Server
	caller uuid.UUID
}

func newSignupIdPEnv(t *testing.T) *signupIdPEnv {
	t.Helper()
	db := testdb.ScratchDatabase(t)
	e := &signupIdPEnv{t: t, db: db}

	role := testdb.NewPlatformRole(t, db, "platform.settings", "platform.security.manage")
	e.caller = testdb.NewPlatformUser(t, db, role)

	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	t.Setenv("ENCRYPTION_MASTER_KEY", "")
	e.srv = NewServerWithConnections(
		&config.Config{Environment: "test", JWTSecret: signupIdPSigningValue},
		db, db, EditionHooks{},
	)
	e.licence("")
	t.Cleanup(entitlements.FlushLicenseCache)
	return e
}

// licence replaces the install's licence; edition "" removes it (Core), and a
// negative validity writes one that has already expired.
func (e *signupIdPEnv) licence(edition string, validFor ...time.Duration) {
	e.t.Helper()
	if _, err := e.db.Exec(`DELETE FROM platform_license`); err != nil {
		e.t.Fatalf("clear licence: %v", err)
	}
	if edition != "" {
		d := 30 * 24 * time.Hour
		if len(validFor) > 0 {
			d = validFor[0]
		}
		if _, err := e.db.Exec(`
			INSERT INTO platform_license (subject, edition, expires_at, token_sha256, license_id)
			VALUES ('signup-idp-it', $1, now() + make_interval(secs => $2), 'x', $3)`,
			edition, d.Seconds(), "lic-"+uuid.NewString()); err != nil {
			e.t.Fatalf("install %s licence: %v", edition, err)
		}
	}
	entitlements.FlushLicenseCache()
}

func (e *signupIdPEnv) do(method, path, body string) (int, string) {
	e.t.Helper()
	claims := models.JWTClaims{
		UserID: e.caller,
		Email:  "operator@example.test",
		Role:   "super_admin", // ignored: authorization comes from the database
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signupIdPSigningValue))
	if err != nil {
		e.t.Fatalf("sign token: %v", err)
	}
	req := httptest.NewRequest(method, "/api/v1/admin-service/admin"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.srv.Router().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *signupIdPEnv) rows(purpose string) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM platform_sso_providers WHERE purpose = $1`, purpose).Scan(&n); err != nil {
		e.t.Fatalf("count %s providers: %v", purpose, err)
	}
	return n
}

func idpBody(providerType, purpose string) string {
	return `{"provider_type":"` + providerType + `","purpose":"` + purpose + `","client_id":"it-client",` +
		`"client_secret":"it-client-credential","auth_url":"https://idp.example.test/authorize",` +
		`"token_url":"https://idp.example.test/token","is_enabled":true}`
}

func signupIdPExpect(t *testing.T, what string, got int, body string, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status = %d, want %d; body=%s", what, got, want, body)
	}
}

func TestIntegration_SignupIdentityProvider_NeedsLicence_RealRouter(t *testing.T) {
	e := newSignupIdPEnv(t)

	t.Run("Core refuses a sign-up provider with 402 and writes nothing", func(t *testing.T) {
		e.licence("")
		code, body := e.do(http.MethodPost, "/identity-providers", idpBody("google", "signup"))
		signupIdPExpect(t, "Core signup create", code, body, http.StatusPaymentRequired)
		if !strings.Contains(body, "Enterprise or MSP licence") {
			t.Fatalf("402 should say what is needed: %s", body)
		}
		if n := e.rows("signup"); n != 0 {
			t.Fatalf("the refused create wrote %d sign-up row(s)", n)
		}
	})

	t.Run("an expired licence is Core too", func(t *testing.T) {
		e.licence("enterprise", -time.Hour)
		code, body := e.do(http.MethodPost, "/identity-providers", idpBody("google", "signup"))
		signupIdPExpect(t, "expired-licence signup create", code, body, http.StatusPaymentRequired)
		if n := e.rows("signup"); n != 0 {
			t.Fatalf("the refused create wrote %d sign-up row(s)", n)
		}
	})

	t.Run("an omitted purpose defaults to sign-up and is refused on Core too", func(t *testing.T) {
		e.licence("")
		body := strings.Replace(idpBody("google", "signup"), `"purpose":"signup",`, "", 1)
		code, resp := e.do(http.MethodPost, "/identity-providers", body)
		signupIdPExpect(t, "Core default-purpose create", code, resp, http.StatusPaymentRequired)
	})

	t.Run("Core still creates an admin-login provider", func(t *testing.T) {
		e.licence("")
		code, body := e.do(http.MethodPost, "/identity-providers", idpBody("google", "admin_login"))
		signupIdPExpect(t, "Core admin_login create", code, body, http.StatusCreated)
		if n := e.rows("admin_login"); n != 1 {
			t.Fatalf("admin_login rows = %d, want 1", n)
		}
	})

	for _, edition := range []string{"enterprise", "msp"} {
		t.Run("a "+edition+" licence creates a sign-up provider", func(t *testing.T) {
			e.licence(edition)
			if _, err := e.db.Exec(`DELETE FROM platform_sso_providers WHERE purpose = 'signup'`); err != nil {
				t.Fatal(err)
			}
			code, body := e.do(http.MethodPost, "/identity-providers", idpBody("microsoft", "signup"))
			signupIdPExpect(t, edition+" signup create", code, body, http.StatusCreated)
			if n := e.rows("signup"); n != 1 {
				t.Fatalf("signup rows = %d, want 1", n)
			}
		})
	}

	t.Run("after the licence lapses the sign-up row can still be switched off and deleted", func(t *testing.T) {
		var id string
		if err := e.db.QueryRow(`SELECT id FROM platform_sso_providers WHERE purpose = 'signup'`).Scan(&id); err != nil {
			t.Fatalf("premise: a sign-up row from the licensed create: %v", err)
		}
		e.licence("")
		off := strings.Replace(idpBody("microsoft", "signup"), `"is_enabled":true`, `"is_enabled":false`, 1)
		code, body := e.do(http.MethodPut, "/identity-providers/"+id, off)
		signupIdPExpect(t, "Core disable signup", code, body, http.StatusOK)
		var enabled bool
		if err := e.db.QueryRow(`SELECT is_enabled FROM platform_sso_providers WHERE id = $1`, id).Scan(&enabled); err != nil || enabled {
			t.Fatalf("sign-up row should now be disabled (enabled=%v, err=%v)", enabled, err)
		}
		code, body = e.do(http.MethodDelete, "/identity-providers/"+id, "")
		signupIdPExpect(t, "Core delete signup", code, body, http.StatusOK)
		if n := e.rows("signup"); n != 0 {
			t.Fatalf("signup rows after delete = %d, want 0", n)
		}
	})
}
