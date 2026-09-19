package services

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// A receipt cannot be acknowledged when catalogue linking failed. An unknown
// algorithm is different: its evidence is valid even without a catalogue entry.
func TestIntegration_CryptoMaterializationPropagatesCatalogueLinkFailures(t *testing.T) {
	f := newLeafLinkFixture(t)
	impl := uuid.New()
	suffix := "materialization_" + fmt.Sprintf("%x", impl[:])
	// Junctions reference partitioned implementations without a foreign key, so
	// inject a real write failure instead of relying on a missing target row.
	_, err := f.db.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN IF NEW.crypto_implementation_id = '%s'::uuid THEN RAISE EXCEPTION 'injected link failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER %s BEFORE INSERT ON crypto_implementation_algorithms FOR EACH ROW EXECUTE FUNCTION %s()`, suffix, impl, suffix, suffix))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON crypto_implementation_algorithms; DROP FUNCTION IF EXISTS %s()", suffix, suffix))
	})
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"TLS", func() error {
			return f.svc.classifyAndLinkAlgorithms(impl, IngestFinding{ProtocolVersion: strPtr("TLS 1.2")})
		}},
		{"SSH", func() error {
			return f.svc.classifyAndLinkSSH(impl, sshObservation{Present: true, ProtocolVersion: "SSH 2.0", HostKeyType: "ssh-rsa"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatal("failed algorithm link was acknowledged")
			}
		})
	}
	if err := f.svc.classifyAndLinkAlgorithms(impl, IngestFinding{CipherSuite: strPtr("unknown-future-suite")}); err != nil {
		t.Fatalf("unrecognized evidence should remain retainable: %v", err)
	}
}
