package updates

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
)

type fakeTags struct {
	mu    sync.Mutex
	tags  []string
	err   error
	calls int
}

func (f *fakeTags) ListTags(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.tags, f.err
}

func (f *fakeTags) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type memStore struct {
	mu  sync.Mutex
	row Status
}

func (m *memStore) Get(context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.row, nil
}
func (m *memStore) SaveSuccess(_ context.Context, s Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.row = s
	return nil
}
func (m *memStore) SaveFailure(_ context.Context, at time.Time, source, current, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.row.CheckedAt, m.row.Source, m.row.CurrentVersion, m.row.Error = &at, &source, &current, &msg
	return nil
}

type fakeLocker struct {
	mu   sync.Mutex
	held bool
}

func (f *fakeLocker) TryLock(context.Context) (func(), bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held {
		return func() {}, false, nil
	}
	f.held = true
	return func() { f.mu.Lock(); f.held = false; f.mu.Unlock() }, true, nil
}

func newUpdatesTestChecker(tags *fakeTags, st Store, lk Locker) *Checker {
	log, _ := test.NewNullLogger()
	return &Checker{
		Tags: tags, Store: st, Locker: lk, Log: log,
		Now: func() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) },
		Config: Config{
			Source:         Source{Registry: "ghcr.io", Repository: "vistasecurity/vistaplatform"},
			RunningVersion: "4.5.0",
		},
	}
}

func TestChecker_RecordsLatestAndNotes(t *testing.T) {
	st := &memStore{}
	c := newUpdatesTestChecker(&fakeTags{tags: []string{"4.5.0", "4.6.0", "4.7.0-rc.1", "x"}}, st, &fakeLocker{})
	got, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.LatestVersion == nil || *got.LatestVersion != "4.6.0" {
		t.Fatalf("latest = %v", got.LatestVersion)
	}
	if *got.NotesURL != "https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v4.6.0" {
		t.Fatalf("notes = %s", *got.NotesURL)
	}
	if *got.Source != "oci://ghcr.io/vistasecurity/vistaplatform" || *got.CurrentVersion != "4.5.0" || got.Error != nil {
		t.Fatalf("row = %+v", got)
	}
	if len(got.PrereleasesSeen) != 1 || got.PrereleasesSeen[0] != "4.7.0-rc.1" {
		t.Fatalf("prereleases = %v", got.PrereleasesSeen)
	}
	if got.CheckedAt == nil || !got.CheckedAt.Equal(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("checked_at = %v", got.CheckedAt)
	}
}

func TestChecker_UpToDateClearsLatest(t *testing.T) {
	st := &memStore{}
	c := newUpdatesTestChecker(&fakeTags{tags: []string{"4.4.0", "4.5.0"}}, st, &fakeLocker{})
	got, err := c.Run(context.Background())
	if err != nil || got.LatestVersion != nil || got.NotesURL != nil || got.Error != nil {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestChecker_FailureIsRecordedKeepingLastGoodVersion_ThenSuccessClearsIt(t *testing.T) {
	st := &memStore{}
	tags := &fakeTags{tags: []string{"4.5.0", "4.6.0"}}
	c := newUpdatesTestChecker(tags, st, &fakeLocker{})
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	tags.mu.Lock()
	tags.err = &RegistryError{URL: "https://ghcr.io/v2/x/tags/list", Status: 503}
	tags.mu.Unlock()
	got, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("a registry failure is the check's outcome, not a Run error: %v", err)
	}
	if got.Error == nil || *got.Error == "" {
		t.Fatalf("error not recorded: %+v", got)
	}
	if got.LatestVersion == nil || *got.LatestVersion != "4.6.0" {
		t.Fatalf("a registry outage erased the announced release: %+v", got)
	}

	tags.mu.Lock()
	tags.err = nil
	tags.mu.Unlock()
	got, _ = c.Run(context.Background())
	if got.Error != nil {
		t.Fatalf("error not cleared on success: %q", *got.Error)
	}
}

func TestChecker_OnlyOneRunAtATime(t *testing.T) {
	lk := &fakeLocker{held: true}
	tags := &fakeTags{tags: []string{"4.6.0"}}
	c := newUpdatesTestChecker(tags, &memStore{}, lk)
	if _, err := c.Run(context.Background()); !errors.Is(err, ErrInProgress) {
		t.Fatalf("err = %v, want ErrInProgress", err)
	}
	if tags.count() != 0 {
		t.Fatal("the registry was queried without holding the lock")
	}
	lk.held = false
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lk.held {
		t.Fatal("lock not released after Run")
	}
}

func TestChecker_Start_RunsAfterDelayAndOnInterval(t *testing.T) {
	tags := &fakeTags{tags: []string{"4.6.0"}}
	c := newUpdatesTestChecker(tags, &memStore{}, &fakeLocker{})
	c.Config.StartDelay = 10 * time.Millisecond
	c.Config.Interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for {
		calls := tags.count()
		if calls >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d scheduled checks ran", calls)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
}

func TestService_UpdateAvailableIsComputedAtReadTime(t *testing.T) {
	st := &memStore{}
	c := newUpdatesTestChecker(&fakeTags{tags: []string{"4.6.0"}}, st, &fakeLocker{})
	svc := &Service{Checker: c, Store: st, Enabled: true, RunningVersion: "4.5.0"}
	v, err := svc.Check(context.Background())
	if err != nil || !v.UpdateAvailable || !v.CheckEnabled {
		t.Fatalf("%+v %v", v, err)
	}
	// The pod now runs 4.6.0 (the update landed): no new check needed.
	svc.RunningVersion = "4.6.0"
	v, _ = svc.Read(context.Background())
	if v.UpdateAvailable {
		t.Fatal("banner would persist after the update")
	}
}

func TestService_DisabledRefusesManualCheckButStillReads(t *testing.T) {
	tags := &fakeTags{tags: []string{"4.6.0"}}
	st := &memStore{}
	svc := &Service{Checker: newUpdatesTestChecker(tags, st, &fakeLocker{}), Store: st, Enabled: false, RunningVersion: "4.5.0"}
	if _, err := svc.Check(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v", err)
	}
	if tags.count() != 0 {
		t.Fatal("a disabled check dialled the registry")
	}
	v, err := svc.Read(context.Background())
	if err != nil || v.CheckEnabled || v.UpdateAvailable || v.PrereleasesSeen == nil {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestSettingsFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }

	s := SettingsFromEnv(get)
	if !s.Enabled || s.Interval != 24*time.Hour || s.IncludePrereleases || len(s.Warnings) != 0 {
		t.Fatalf("defaults: %+v", s)
	}
	env[EnvEnabled], env[EnvInterval], env[EnvPrereleases], env[EnvPullSecret] = "false", "6h", "true", "regcred"
	s = SettingsFromEnv(get)
	if s.Enabled || s.Interval != 6*time.Hour || !s.IncludePrereleases || s.PullSecretName != "regcred" {
		t.Fatalf("set: %+v", s)
	}
	for _, bad := range []string{"daily", "10s", "-1h"} {
		env[EnvInterval] = bad
		s = SettingsFromEnv(get)
		if s.Interval != 24*time.Hour || len(s.Warnings) != 1 {
			t.Fatalf("interval %q: %+v", bad, s)
		}
	}
}

func TestNewService_UnusableSourceIsRecordedNotFatal(t *testing.T) {
	st := &memStore{}
	log, _ := test.NewNullLogger()
	svc := NewService(EnvSettings{Enabled: true, ChartSource: "ghcr.io/not-oci"}, "4.5.0", st, &fakeLocker{}, nil, log)
	v, err := svc.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Error == nil || *v.Source != "ghcr.io/not-oci" {
		t.Fatalf("%+v", v)
	}
}
