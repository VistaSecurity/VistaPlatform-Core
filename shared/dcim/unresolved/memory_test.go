package unresolved_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/dcim/dcimtest"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// The in-memory repository is the reference the phase-1 SQL repository is held
// to by the same suite.
func TestMemoryRepository_ResolverContract(t *testing.T) {
	dcimtest.RunResolverContract(t, func() unresolved.Repository { return unresolved.NewMemoryRepository() })
}
