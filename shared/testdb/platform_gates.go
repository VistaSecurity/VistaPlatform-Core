package testdb

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Helpers for proving, through a service's REAL router and the real
// platform_user_has_permission(), that an operator route is decided by a
// permission grant and never by the role name on the token.

// GatedRoute is one operator route and the platform permission that must open it.
type GatedRoute struct {
	Method, Path, Permission string
}

func (r GatedRoute) String() string { return r.Method + " " + r.Path }

// SignPlatformToken mints an HS256 platform access token (no tenant_id) for
// userID, carrying roleClaim as its role. The role claim is deliberately free:
// the gates under test must ignore it.
func SignPlatformToken(t *testing.T, secret string, userID uuid.UUID, roleClaim string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"sub":     userID.String(),
		"email":   "platform-fixture@example.test",
		"role":    roleClaim,
		"type":    "access",
		"iss":     "crypto-inventory-auth",
		"aud":     "crypto-inventory",
		"jti":     uuid.NewString(),
		"iat":     now.Unix(),
		"nbf":     now.Add(-time.Minute).Unix(),
		"exp":     now.Add(time.Hour).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("testdb: sign platform token: %v", err)
	}
	return signed
}

// DoPlatform sends one request with a bearer token and returns the recorder.
func DoPlatform(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// RefusedByPlatformGate reports whether the response is an authentication or
// platform-permission refusal rather than the handler's own answer. It reads
// the body, not just the status, because a reached handler can itself answer
// 403/500 and a bare status check would then pass for the wrong reason.
func RefusedByPlatformGate(w *httptest.ResponseRecorder) bool {
	body := w.Body.String()
	switch w.Code {
	case http.StatusUnauthorized:
		return true
	case http.StatusForbidden:
		return strings.Contains(body, "Insufficient platform permissions") ||
			strings.Contains(body, "Platform user required") ||
			strings.Contains(body, "Permission outside token scope")
	case http.StatusInternalServerError:
		return strings.Contains(body, "Failed to check platform permission")
	case http.StatusServiceUnavailable:
		return strings.Contains(body, "RBAC unavailable")
	}
	return false
}

// AllPlatformPermissionsExcept lists every seeded platform permission but the
// named ones — the widest role that still lacks them.
func AllPlatformPermissionsExcept(t *testing.T, db *sql.DB, except ...string) []string {
	t.Helper()
	skip := map[string]bool{}
	for _, e := range except {
		skip[e] = true
	}
	rows, err := db.Query(`SELECT name FROM platform_permissions ORDER BY name`)
	if err != nil {
		t.Fatalf("testdb: list platform permissions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		if !skip[n] {
			out = append(out, n)
		}
	}
	return out
}

// CheckPlatformGates proves, for every route, both polarities of a
// permission-based gate against the real database:
//
//   - a CUSTOM role holding only the route's permission passes the gate;
//   - a custom role holding every OTHER platform permission is refused, with a
//     403 that names the route's permission;
//   - a user without the permission is refused even when the token's role
//     claim says platform_admin or super_admin.
//
// sign mints a token for the service under test (see SignPlatformToken).
func CheckPlatformGates(t *testing.T, db *sql.DB, h http.Handler, sign func(userID uuid.UUID, roleClaim string) string, routes []GatedRoute) {
	t.Helper()
	with := map[string]uuid.UUID{}
	without := map[string]uuid.UUID{}
	for _, rt := range routes {
		if _, ok := with[rt.Permission]; ok {
			continue
		}
		with[rt.Permission] = NewPlatformUser(t, db, NewPlatformRole(t, db, rt.Permission))
		without[rt.Permission] = NewPlatformUser(t, db, NewPlatformRole(t, db, AllPlatformPermissionsExcept(t, db, rt.Permission)...))
	}

	for _, rt := range routes {
		w := DoPlatform(h, rt.Method, rt.Path, sign(with[rt.Permission], "custom_operator"))
		if RefusedByPlatformGate(w) {
			t.Errorf("%s: a custom role holding %s was refused: %d %s", rt, rt.Permission, w.Code, w.Body.String())
		}

		for _, claim := range []string{"custom_operator", "platform_admin", "super_admin"} {
			w = DoPlatform(h, rt.Method, rt.Path, sign(without[rt.Permission], claim))
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Insufficient platform permissions") {
				t.Errorf("%s: a role lacking %s (role claim %q) got %d %s, want the permission gate's 403",
					rt, rt.Permission, claim, w.Code, w.Body.String())
				continue
			}
			if !strings.Contains(w.Body.String(), `"required_permission":"`+rt.Permission+`"`) {
				t.Errorf("%s: refused, but not on %s: %s", rt, rt.Permission, w.Body.String())
			}
		}
	}
}

// SeededRoleVerdicts reports, for each seeded platform role, which routes a
// member of that role gets past the gate. Tests compare it with the behaviour
// the role had before the gate became permission-based.
func SeededRoleVerdicts(t *testing.T, db *sql.DB, h http.Handler, sign func(userID uuid.UUID, roleClaim string) string, routes []GatedRoute) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, role := range []string{"super_admin", "platform_admin", "support_agent"} {
		user := NewPlatformUser(t, db, SeededPlatformRole(t, db, role))
		out[role] = map[string]bool{}
		for _, rt := range routes {
			w := DoPlatform(h, rt.Method, rt.Path, sign(user, role))
			out[role][rt.String()] = !RefusedByPlatformGate(w)
		}
	}
	return out
}
