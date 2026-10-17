// Package dcimtest holds the behavioural contracts and fakes for the DCIM
// object substrate (shared/dcim/...).
//
// It is an ordinary (non-_test) package for the reason shared/identity's
// identitytest is: the phase-1 SQL implementation of unresolved.Repository
// lives in another package (and module) and must run exactly the assertions
// the in-memory one does. Two implementations of a storage contract held to
// two different test suites drift, invisibly, until production.
package dcimtest

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// FakeMatcher matches from fixed tables keyed by identity value. A key absent
// from its table does not match. Calls are counted so a test can prove the
// resolver asked.
type FakeMatcher struct {
	mu        sync.Mutex
	ByMAC     map[string]unresolved.Match
	ByChassis map[string]unresolved.Match
	ByCloud   map[string]unresolved.Match
	// BySync is keyed by "<key>=<value>", e.g. "sync:netbox:interface=77".
	BySync map[string]unresolved.Match
	// Err, when set, is returned from every call (a matcher whose database
	// is down).
	Err   error
	Calls int
}

func (f *FakeMatcher) look(tbl map[string]unresolved.Match, k string) (unresolved.Match, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls++
	if f.Err != nil {
		return unresolved.Match{}, false, f.Err
	}
	m, ok := tbl[k]
	return m, ok, nil
}

func (f *FakeMatcher) MatchInterfaceByMAC(_ context.Context, _ uuid.UUID, mac string) (unresolved.Match, bool, error) {
	return f.look(f.ByMAC, mac)
}
func (f *FakeMatcher) MatchAssetByChassisID(_ context.Context, _ uuid.UUID, id string) (unresolved.Match, bool, error) {
	return f.look(f.ByChassis, id)
}
func (f *FakeMatcher) MatchAssetByCloudResourceID(_ context.Context, _ uuid.UUID, id string) (unresolved.Match, bool, error) {
	return f.look(f.ByCloud, id)
}
func (f *FakeMatcher) MatchBySyncKey(_ context.Context, _ uuid.UUID, key, value string) (unresolved.Match, bool, error) {
	return f.look(f.BySync, key+"="+value)
}

// Applied is one call a RecordingApplier received.
type Applied struct {
	Method           string // "cable", "relationship", "assignment"
	RelationshipType string
	Tenant           uuid.UUID
	Parked           unresolved.Parked
	Far              unresolved.Match
}

// RecordingApplier records every Apply call. Err, when set, is returned from
// every call (and the call is still recorded).
type RecordingApplier struct {
	mu    sync.Mutex
	Calls []Applied
	Err   error
}

func (a *RecordingApplier) rec(c Applied) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Calls = append(a.Calls, c)
	return a.Err
}

func (a *RecordingApplier) ApplyCable(_ context.Context, tenant uuid.UUID, p unresolved.Parked, far unresolved.Match) error {
	return a.rec(Applied{Method: "cable", Tenant: tenant, Parked: p, Far: far})
}
func (a *RecordingApplier) ApplyRelationship(_ context.Context, tenant uuid.UUID, p unresolved.Parked, rt string, far unresolved.Match) error {
	return a.rec(Applied{Method: "relationship", RelationshipType: rt, Tenant: tenant, Parked: p, Far: far})
}
func (a *RecordingApplier) ApplyAssignment(_ context.Context, tenant uuid.UUID, p unresolved.Parked, far unresolved.Match) error {
	return a.rec(Applied{Method: "assignment", Tenant: tenant, Parked: p, Far: far})
}

// MemoryRecorder is a changes.Recorder that keeps the prepared rows in memory.
// It applies exactly the rules the Postgres recorder does (changes.Prepare).
type MemoryRecorder struct {
	mu   sync.Mutex
	Rows []changes.Row
}

// Record implements changes.Recorder.
func (r *MemoryRecorder) Record(ctx context.Context, c changes.Change) error {
	row, skip, err := changes.Prepare(ctx, c)
	if err != nil || skip {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Rows = append(r.Rows, row)
	return nil
}
