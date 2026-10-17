package identifiersql

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestScopeDefaultAgrees(t *testing.T) {
	if scopeTenantDefault != identity.ScopeTenantDefault {
		t.Fatalf("scopeTenantDefault = %q, identity.ScopeTenantDefault = %q", scopeTenantDefault, identity.ScopeTenantDefault)
	}
	if !strings.Contains(Addresses, "'"+identity.ScopeTenantDefault+"'") {
		t.Fatal("Addresses does not report the tenant-default scope for an unscoped address row")
	}
}
