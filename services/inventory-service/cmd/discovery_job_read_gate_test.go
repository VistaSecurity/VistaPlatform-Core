package main

// Discovery job READ gates.
//
// `GET /discovery/jobs/:id` and `.../results` return what a scan found — the
// hosts it touched and the crypto it observed on them. They carried NO
// permission at all until: authentication only, so any authenticated
// member of a tenant could read every scan result in it regardless of role.
//
// The LIST beside them was gated the whole time, which is what made this easy
// to miss: `GET /discovery/jobs` asks for settings.read, so the surface looked
// governed. Fetching a specific job by id did not.
//
// Six registrations were ungated, not two — the routes exist three times over
// (the /inventory-service/* block, the legacy unprefixed block kept for
// backward compatibility, and the /api/v2 block). Gating the first pair and
// stopping would have left four open paths to the same handlers. This test
// therefore asserts on EVERY registration via registrationsOf rather than
// scanRoutesWithArgs, which collapses copies into the weaker one.
//
// Both polarities are pinned:
//   - DETAIL and RESULTS require discovery.read — the discovered data itself.
//   - The LIST requires settings.read, NOT discovery.read. It mirrors
//     inventory-service's Active Scanning settings summary, and
//     cluster-sensor-service proxies it forwarding the caller's JWT, so the two
//     hops must name the same permission or the second 403s. Raising the list
//     to discovery.read would silently drop billing_admin, which is the owner's
// call to make and was made the other way on.

import "testing"

const (
	discoveryReadPerm  = "rbac.PermissionDiscoveryRead"
	discoverySettsPerm = "rbac.PermissionSettingsRead"
)

// discoveryJobReadRoutes are every job-read path and the permission each
// registration of it must carry.
var discoveryJobReadRoutes = []struct {
	path string
	perm string
	// want is how many registrations main.go is expected to have. Stated so a
	// route that loses a copy (or gains an ungated one) fails here rather than
	// passing because the survivors happen to be correct.
	want int
}{
	{"/inventory-service/discovery/jobs/:id", discoveryReadPerm, 2},
	{"/inventory-service/discovery/jobs/:id/results", discoveryReadPerm, 2},
	{"/discovery/jobs/:id", discoveryReadPerm, 1},
	{"/discovery/jobs/:id/results", discoveryReadPerm, 1},
	{"/inventory-service/discovery/jobs", discoverySettsPerm, 2},
	{"/discovery/jobs", discoverySettsPerm, 1},
}

func TestDiscoveryJobReads_EveryRegistrationCarriesItsPermission(t *testing.T) {
	for _, r := range discoveryJobReadRoutes {
		regs := registrationsOf(t, "GET", r.path)
		if len(regs) != r.want {
			t.Fatalf("GET %s: found %d registration(s), expected %d — a copy was added or removed and this table is now wrong",
				r.path, len(regs), r.want)
		}
		for i, args := range regs {
			if !contains(args, "RequireTenantPermission") {
				t.Errorf("GET %s registration %d is UNGATED: %s", r.path, i, args)
				continue
			}
			if !contains(args, r.perm) {
				t.Errorf("GET %s registration %d does not require %s: %s", r.path, i, r.perm, args)
			}
		}
	}
}

// TestDiscoveryJobDetail_IsNotGatedOnSettingsRead is the reverse polarity of
// the split above. settings.read is deliberately weaker than discovery.read
// here — it exists so a billing role can see THAT scans ran. If a future change
// "simplifies" the detail routes onto it, the scan results become readable by a
// role that was only ever meant to see the activity list.
func TestDiscoveryJobDetail_IsNotGatedOnSettingsRead(t *testing.T) {
	for _, path := range []string{
		"/inventory-service/discovery/jobs/:id",
		"/inventory-service/discovery/jobs/:id/results",
		"/discovery/jobs/:id",
		"/discovery/jobs/:id/results",
	} {
		for i, args := range registrationsOf(t, "GET", path) {
			if contains(args, discoverySettsPerm) {
				t.Errorf("GET %s registration %d is gated on %s; job detail and results must require %s",
					path, i, discoverySettsPerm, discoveryReadPerm)
			}
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
