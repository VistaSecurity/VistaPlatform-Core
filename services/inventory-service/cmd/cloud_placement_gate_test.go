package main

// The cloud placement read (asset-inventory ADR-0009 D7, DCIM row 4.6) is
// gated on assets.read — the cloud read permission the row names. Every other
// infrastructure-asset GET is JWT-scoped only; this one says what it reads.
//
// MUTATION-VERIFIED: drop the RequireTenantPermission from the registration in
// main.go and this goes red.

import "testing"

func TestCloudPlacement_IsGatedOnAssetsRead(t *testing.T) {
	regs := registrationsOf(t, "GET", "/inventory-service/infrastructure-assets/:id/cloud-placement")
	if len(regs) != 1 {
		t.Fatalf("found %d registration(s) of the cloud placement route, want 1", len(regs))
	}
	if !contains(regs[0], "RequireTenantPermission") || !contains(regs[0], "rbac.PermissionAssetsRead") {
		t.Errorf("cloud placement is not gated on assets.read: %s", regs[0])
	}
}
