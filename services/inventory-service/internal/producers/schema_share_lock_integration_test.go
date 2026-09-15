package producers

// Every pass helper in this package takes the schema share lock before it
// touches a table — proven, not assumed.
//
// `go test ./...` runs this package's binary beside internal/services', whose
// tests re-apply schema.sql dozens of times; each apply takes ACCESS EXCLUSIVE
// locks across the schema in file order, while a pass here locks the tables it
// reads in query order. Postgres breaks the cycle by killing one side, and the
// side it kills is a test with nothing wrong with it: `pq: deadlock detected`
// from the hygiene producer's post-pass rollup, green alone and green under a
// serial runner, red whenever the two binaries lined up.
//
// testdb.WithSchemaShareLock makes the overlap impossible rather than retrying
// past it, but only where a helper uses it. This test holds the schema lock the
// way an applier does and drives each helper against it: a guarded helper waits
// (holding nothing); an unguarded one runs straight through, which is the
// window the deadlock lives in. Deterministic — nothing here depends on the two
// binaries lining up.
//
// One case per helper. Add a helper, add a case: a helper that is not listed
// here is one nobody has proven. The tests that EXPECT a pass to fail call Run
// directly rather than through a helper, so they are not (and must not be)
// wrapped.

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Producers_PassHelpersTakeTheSchemaShareLock(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		setup func(t *testing.T) func()
	}{
		{"hygiene run", func(t *testing.T) func() {
			f := newHygieneFixture(t)
			return func() { f.run(t, ctx) }
		}},
		{"hygiene risk recompute", func(t *testing.T) func() {
			f := newHygieneFixture(t)
			return func() { f.recomputeRisk(t) }
		}},
		{"configuration run", func(t *testing.T) func() {
			f := newConfigFixture(t)
			return func() { f.run(t, ctx) }
		}},
		{"vulnerability run", func(t *testing.T) func() {
			f := newVulnFixture(t)
			return func() { f.run(t, ctx) }
		}},
		{"eol run", func(t *testing.T) func() {
			f := newEOLFixture(t)
			return func() { f.run(t, ctx) }
		}},
		{"crypto run", func(t *testing.T) func() {
			f := newCryptoFixture(t)
			return func() { f.mustRun(t, ctx) }
		}},
		{"drift run", func(t *testing.T) func() {
			f := newDriftFixture(t)
			return func() { f.run(t, ctx) }
		}},
		{"drift risk recompute", func(t *testing.T) func() {
			f := newDriftFixture(t)
			return func() { f.recomputeRisk(t) }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testdb.RequireSchemaShareLock(t, c.setup)
		})
	}
}
