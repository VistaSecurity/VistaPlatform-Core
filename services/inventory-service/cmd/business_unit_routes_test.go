package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// main.go must mount the Business Unit routes through registerBusinessUnitRoutes,
// which carries the permission gates. A bare registration would compile, pass
// every handler test and let any tenant user rewrite the organisation tree.
func TestBusinessUnitRoutesAreMountedThroughTheGatedRegistration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "registerBusinessUnitRoutes(apiv2, rawDB, businessUnitHandler)") {
		t.Error("main.go does not call registerBusinessUnitRoutes(apiv2, rawDB, businessUnitHandler)")
	}
	if strings.Contains(string(raw), "/dcim/business-units") {
		t.Error("main.go registers a business-units path itself, bypassing registerBusinessUnitRoutes")
	}
}

func TestBusinessUnitRoutesCarryTheirPermissions(t *testing.T) {
	raw, err := os.ReadFile("business_unit_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, line := range strings.Split(src, "\n") {
		switch {
		case strings.Contains(line, "g.GET("):
			if !strings.Contains(line, ", read,") {
				t.Errorf("read route without the dcim.read gate: %s", line)
			}
		case strings.Contains(line, "g.POST(") || strings.Contains(line, "g.PUT(") || strings.Contains(line, "g.DELETE("):
			if !strings.Contains(line, ", write,") {
				t.Errorf("write route without the business_units.manage gate: %s", line)
			}
		}
	}
	if !strings.Contains(src, "rbac.PermissionBusinessUnitsManage") || !strings.Contains(src, "rbac.PermissionDcimRead") {
		t.Error("the gates are not dcim.read / business_units.manage")
	}
}
