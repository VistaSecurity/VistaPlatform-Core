package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// main.go must mount the region, site group, site and location routes through
// registerSiteRoutes, which carries the permission gates (DCIM row 2.1).
func TestSiteRoutesAreMountedThroughTheGatedRegistration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "registerSiteRoutes(apiv2, rawDB, siteHandler)") {
		t.Error("main.go does not call registerSiteRoutes(apiv2, rawDB, siteHandler)")
	}
	for _, p := range []string{"/dcim/regions", "/dcim/site-groups", "/dcim/sites", "/dcim/locations", "/inventory-service/locations"} {
		if strings.Contains(src, p) {
			t.Errorf("main.go registers %s itself, bypassing registerSiteRoutes", p)
		}
	}
}

func TestSiteRoutesCarryTheirPermissions(t *testing.T) {
	raw, err := os.ReadFile("site_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	routes := 0
	for _, line := range strings.Split(src, "\n") {
		switch {
		case strings.Contains(line, "g.GET("):
			routes++
			if !strings.Contains(line, ", read,") {
				t.Errorf("read route without the dcim.read gate: %s", line)
			}
		case strings.Contains(line, "g.POST(") || strings.Contains(line, "g.PUT(") || strings.Contains(line, "g.DELETE("):
			routes++
			if !strings.Contains(line, ", write,") {
				t.Errorf("write route without the dcim.manage gate: %s", line)
			}
		}
	}
	if routes != 20 {
		t.Errorf("site_routes.go mounts %d routes, want 20 (5 per object)", routes)
	}
	if !strings.Contains(src, "rbac.PermissionDcimManage") || !strings.Contains(src, "rbac.PermissionDcimRead") {
		t.Error("the gates are not dcim.read / dcim.manage")
	}
}
