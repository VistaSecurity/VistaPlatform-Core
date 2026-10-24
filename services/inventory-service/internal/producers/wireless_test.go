package producers

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// The crypto pass must not sweep the wireless pass's kind: it does not assert
// it, so it would resolve the finding and the wireless pass would resurface it
// on every run. Every other crypto kind stays swept.
//
// Mutation: delete `&& !sweptByAnotherPass[k.Key]` from cryptoKinds -> red.
func TestCryptoKinds_ExcludesTheWirelessKindAndKeepsTheRest(t *testing.T) {
	has := map[string]bool{}
	for _, k := range cryptoKinds {
		has[k] = true
	}
	if has[findings.KindWeakWirelessAuth] {
		t.Fatal("the crypto pass sweeps weak_wireless_auth: it would resolve what the wireless pass raised")
	}
	if has[findings.KindUnencryptedAtRest] {
		t.Fatal("the crypto pass sweeps unencrypted_at_rest: it would resolve what the at-rest pass raised, every night")
	}
	for _, k := range []string{findings.KindWeakConfiguration, findings.KindWeakCertificate, findings.KindPQCVulnerable} {
		if !has[k] {
			t.Errorf("the crypto pass no longer sweeps %s", k)
		}
	}
}
