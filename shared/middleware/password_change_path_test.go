package middleware

import "testing"

// The limited (pwd_change_required) session's reachable-route allowlist.
//
// This gate is what makes shipping a published default admin password safe: the
// seeded platform admins carry force_password_change, so their login yields a
// token that may reach ONLY these routes. If the matcher widens, that password
// starts buying a real session.
//
// The allowlist was a strings.HasSuffix test, which accepts any path ending in
// "/auth/me" at any depth. The deep-path cases below are the ones that
// regression pins — they must NOT match.
func TestIsPasswordChangeAllowedPath(t *testing.T) {
	allowed := []string{
		// Un-prefixed: a service called directly rather than through the gateway.
		"/auth/me",
		"/auth/logout",
		"/auth/change-password",
		// admin-service's un-prefixed shape (one extra segment).
		"/admin/auth/me",
		"/admin/auth/change-password",
		// Gateway-prefixed, both real shapes.
		"/api/v1/auth-service/auth/me",
		"/api/v1/auth-service/auth/logout",
		"/api/v1/auth-service/auth/change-password",
		"/api/v1/admin-service/admin/auth/me",
		"/api/v1/admin-service/admin/auth/change-password",
		"/api/v2/auth-service/auth/me",
	}
	for _, p := range allowed {
		if !IsPasswordChangeAllowedPath(p) {
			t.Errorf("IsPasswordChangeAllowedPath(%q) = false, want true — a real forced-password-change route is now unreachable, which locks admins out entirely", p)
		}
	}

	denied := []string{
		// Everything a limited session must not reach.
		"/api/v1/inventory-service/assets",
		"/api/v1/admin-service/admin/tenants",
		"/auth/register",
		"/auth/mexico",    // must not match the "/auth/me" prefix
		"/auth/me/detail", // suffix must be the END of the path
		"",
		"/",
		// The HasSuffix hole: arbitrarily deep paths that merely END in an
		// allowed suffix. None of these routes exist today; the point is that
		// adding one must not silently open the gate.
		"/api/v1/inventory-service/assets/deep/auth/me",
		"/api/v1/x/y/z/auth/change-password",
		"/anything/at/all/auth/logout",
		// Query strings are not part of URL.Path, but a caller passing a raw
		// URL must not sneak through either.
		"/api/v1/auth-service/auth/me?x=1",
	}
	for _, p := range denied {
		if IsPasswordChangeAllowedPath(p) {
			t.Errorf("IsPasswordChangeAllowedPath(%q) = true, want false — a limited session can reach a route it must not", p)
		}
	}
}
