// Package catalogstest is an in-memory [catalogs.LookupStore] for tests.
//
// The matching rules in shared/catalogs are the substance of the lookup, and
// they are testable without a database — which is the point of the LookupStore
// interface. This is the double every caller outside shared/catalogs uses: the
// gap pass in admin-service, and the `eol` producer's unit tests in
// inventory-service.
//
// shared/catalogs' OWN tests keep a private double instead, because a test file
// in `package catalogs` cannot import a package that imports `catalogs` — the
// cycle is a compile error, not a style preference.
package catalogstest

import (
	"context"

	"github.com/vistasecurity/vistaplatform/shared/catalogs"
)

// Store is a scripted LookupStore. Set the answers; read back what was asked.
type Store struct {
	// Rows is what LookupEOL returns, for every question. Selecting among them
	// is the code under test's job, not the double's — a double that filtered
	// would be testing itself.
	Rows    []catalogs.EOLRow
	RowsErr error

	// CPE / CPECVE are what LookupCPE returns.
	CPE     string
	CPECVE  string
	CPEErr  error
	MissErr error

	// Asked records what the caller looked up, in order.
	Asked    []catalogs.EOLLookup
	CPEAsked []string
	Misses   []catalogs.MissSubject
}

var _ catalogs.LookupStore = (*Store)(nil)

// LookupEOL returns the scripted rows and records the question.
func (s *Store) LookupEOL(_ context.Context, q catalogs.EOLLookup) ([]catalogs.EOLRow, error) {
	s.Asked = append(s.Asked, q)
	return s.Rows, s.RowsErr
}

// LookupCPE returns the scripted CPE and records the question.
func (s *Store) LookupCPE(_ context.Context, vendor, product string) (string, string, error) {
	s.CPEAsked = append(s.CPEAsked, vendor+":"+product)
	return s.CPE, s.CPECVE, s.CPEErr
}

// RecordMiss records the gap, or fails if MissErr is set.
func (s *Store) RecordMiss(_ context.Context, m catalogs.MissSubject) error {
	if s.MissErr != nil {
		return s.MissErr
	}
	s.Misses = append(s.Misses, m)
	return nil
}

// LastLookup is the most recent question put to LookupEOL.
func (s *Store) LastLookup() catalogs.EOLLookup {
	if len(s.Asked) == 0 {
		return catalogs.EOLLookup{}
	}
	return s.Asked[len(s.Asked)-1]
}
