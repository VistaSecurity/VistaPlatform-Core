package handlers

// Contract tests for the update-check routes: the real handlers, a real
// updates.Service over in-memory fakes, bodies validated against
// api/openapi/maintenance-service.openapi.yaml.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
)

type updatesFakeTags struct {
	tags []string
	err  error
}

func (f updatesFakeTags) ListTags(context.Context) ([]string, error) { return f.tags, f.err }

type updatesFakeStore struct {
	mu  sync.Mutex
	row updates.Status
}

func (m *updatesFakeStore) Get(context.Context) (updates.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.row, nil
}

func (m *updatesFakeStore) SaveSuccess(_ context.Context, s updates.Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.row = s
	return nil
}

func (m *updatesFakeStore) SaveFailure(_ context.Context, at time.Time, source, current, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.row.CheckedAt, m.row.Source, m.row.CurrentVersion, m.row.Error = &at, &source, &current, &msg
	return nil
}

type updatesFakeLocker struct{ held bool }

func (l *updatesFakeLocker) TryLock(context.Context) (func(), bool, error) {
	if l.held {
		return func() {}, false, nil
	}
	return func() {}, true, nil
}

func updatesTestService(tags updatesFakeTags, lk *updatesFakeLocker, enabled bool) (*updates.Service, *updatesFakeStore) {
	st := &updatesFakeStore{}
	c := &updates.Checker{
		Tags: tags, Store: st, Locker: lk,
		Config: updates.Config{
			Source:         updates.Source{Registry: "docker.io", Repository: "vistasecurity/vistaplatform"},
			RunningVersion: "4.5.0",
		},
	}
	return &updates.Service{Checker: c, Store: st, Enabled: enabled, RunningVersion: "4.5.0"}, st
}

func updatesTestRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/updates", h.UpdateStatus)
	r.POST("/updates/check", h.CheckForUpdates)
	return r
}

func updatesHandlers(svc UpdatesService) *Handlers {
	h := New(nil, nil, nil, nil, Config{}, nil)
	h.SetUpdates(svc)
	return h
}

func decodeUpdateView(t *testing.T, b []byte) updates.View {
	t.Helper()
	var v updates.View
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return v
}

func TestContract_UpdateStatus_BeforeFirstCheck(t *testing.T) {
	sv := loadSpec(t)
	svc, _ := updatesTestService(updatesFakeTags{}, &updatesFakeLocker{}, true)
	w := get(updatesTestRouter(updatesHandlers(svc)), http.MethodGet, "/updates")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateStatus", w.Body.Bytes())
	v := decodeUpdateView(t, w.Body.Bytes())
	if v.UpdateAvailable || v.CheckedAt != nil || !v.CheckEnabled {
		t.Fatalf("never-checked view = %+v", v)
	}
}

func TestContract_CheckForUpdates_Available(t *testing.T) {
	sv := loadSpec(t)
	svc, _ := updatesTestService(updatesFakeTags{tags: []string{"4.5.0", "4.6.0", "junk", "4.7.0-rc.1"}}, &updatesFakeLocker{}, true)
	r := updatesTestRouter(updatesHandlers(svc))

	w := get(r, http.MethodPost, "/updates/check")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateStatus", w.Body.Bytes())
	v := decodeUpdateView(t, w.Body.Bytes())
	if !v.UpdateAvailable || v.LatestVersion == nil || *v.LatestVersion != "4.6.0" {
		t.Fatalf("view = %+v", v)
	}
	if v.NotesURL == nil || *v.NotesURL != "https://vistasecurity.io/docs/releases/4.6.0/" {
		t.Fatalf("notes = %v", v.NotesURL)
	}

	// The same row is then what GET returns.
	w = get(r, http.MethodGet, "/updates")
	sv.assertConforms(t, "UpdateStatus", w.Body.Bytes())
	if got := decodeUpdateView(t, w.Body.Bytes()); !got.UpdateAvailable || *got.LatestVersion != "4.6.0" {
		t.Fatalf("GET after check = %+v", got)
	}
}

// A registry that cannot be reached is the check's outcome, not an HTTP error.
func TestContract_CheckForUpdates_RegistryDown(t *testing.T) {
	sv := loadSpec(t)
	svc, _ := updatesTestService(updatesFakeTags{err: &updates.RegistryError{URL: "https://registry-1.docker.io/v2/x/tags/list", Status: 503}}, &updatesFakeLocker{}, true)
	w := get(updatesTestRouter(updatesHandlers(svc)), http.MethodPost, "/updates/check")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateStatus", w.Body.Bytes())
	v := decodeUpdateView(t, w.Body.Bytes())
	if v.Error == nil || v.UpdateAvailable {
		t.Fatalf("view = %+v", v)
	}
}

func TestContract_CheckForUpdates_Conflicts(t *testing.T) {
	sv := loadSpec(t)
	cases := []struct {
		name    string
		locked  bool
		enabled bool
		want    string
	}{
		{"another check holds the lock", true, true, "check_in_progress"},
		{"check disabled", false, false, "check_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := updatesTestService(updatesFakeTags{tags: []string{"4.6.0"}}, &updatesFakeLocker{held: tc.locked}, tc.enabled)
			w := get(updatesTestRouter(updatesHandlers(svc)), http.MethodPost, "/updates/check")
			if w.Code != http.StatusConflict {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "UpdateCheckConflict", w.Body.Bytes())
			var e ErrorResponse
			_ = json.Unmarshal(w.Body.Bytes(), &e)
			if e.Error != tc.want {
				t.Fatalf("error = %q, want %q", e.Error, tc.want)
			}
		})
	}
}

type updatesBrokenService struct{}

func (updatesBrokenService) Read(context.Context) (updates.View, error) {
	return updates.View{}, errors.New("db down")
}
func (updatesBrokenService) Check(context.Context) (updates.View, error) {
	return updates.View{}, errors.New("db down")
}

func TestUpdates_StorageFailuresAndUnconfiguredService(t *testing.T) {
	r := updatesTestRouter(updatesHandlers(updatesBrokenService{}))
	if w := get(r, http.MethodGet, "/updates"); w.Code != http.StatusInternalServerError {
		t.Errorf("GET with a broken store = %d", w.Code)
	}
	if w := get(r, http.MethodPost, "/updates/check"); w.Code != http.StatusInternalServerError {
		t.Errorf("POST with a broken store = %d", w.Code)
	}
	r = updatesTestRouter(New(nil, nil, nil, nil, Config{}, nil))
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		path := "/updates"
		if m == http.MethodPost {
			path = "/updates/check"
		}
		if w := get(r, m, path); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with no service = %d, want 503", m, w.Code)
		}
	}
}
