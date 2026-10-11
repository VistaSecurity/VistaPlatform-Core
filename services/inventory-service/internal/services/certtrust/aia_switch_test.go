package certtrust

import (
	"testing"

	"github.com/google/uuid"
)

// CERT_TRUST_AIA_ENABLED=false must stop every caIssuers fetch before the
// per-URL and per-tenant bookkeeping, so an air-gapped cluster (or a test run
// ingesting real certificates) makes no egress at all. Default is on.
func TestAIAPolicy_KillSwitchRefusesEveryFetch(t *testing.T) {
	p := newAIAPolicy(nil)
	tenant := uuid.New()

	t.Setenv("CERT_TRUST_AIA_ENABLED", "false")
	if p.allow(tenant, "http://ca.example.test/issuer.cer") {
		t.Fatal("allow() permitted a fetch with CERT_TRUST_AIA_ENABLED=false")
	}
	if AIAFetchEnabled() {
		t.Fatal("AIAFetchEnabled() should be false")
	}

	t.Setenv("CERT_TRUST_AIA_ENABLED", "")
	if !p.allow(tenant, "http://ca.example.test/issuer.cer") {
		t.Fatal("allow() refused a first fetch with the switch unset (default on)")
	}
}
