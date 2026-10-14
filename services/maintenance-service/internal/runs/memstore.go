package runs

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore is an in-memory Store with the database's one-running rule,
// for tests (here and in the packages whose runs the Runner executes).
type MemoryStore struct {
	mu   sync.Mutex
	runs map[uuid.UUID]Run
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{runs: map[uuid.UUID]Run{}} }

// Create implements Store.
func (m *MemoryStore) Create(_ context.Context, run Run) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		if r.Status == StatusRunning {
			return Run{}, ErrRunInProgress
		}
	}
	run.Status = StatusRunning
	run.StartedAt = time.Now().UTC()
	run.Steps = cloneSteps(run.Steps)
	m.runs[run.ID] = run
	return run, nil
}

// Get implements Store.
func (m *MemoryStore) Get(_ context.Context, id uuid.UUID) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return Run{}, ErrNotFound
	}
	r.Steps = cloneSteps(r.Steps)
	return r, nil
}

// List implements Store, newest first.
func (m *MemoryStore) List(_ context.Context, limit int) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Run{}
	for _, r := range m.runs {
		r.Steps = cloneSteps(r.Steps)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[j].StartedAt.Before(out[i].StartedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListRunning implements Store.
func (m *MemoryStore) ListRunning(context.Context) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Run
	for _, r := range m.runs {
		if r.Status == StatusRunning {
			r.Steps = cloneSteps(r.Steps)
			out = append(out, r)
		}
	}
	return out, nil
}

// SetJobName implements Store.
func (m *MemoryStore) SetJobName(_ context.Context, id uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[id]
	r.JobName = name
	m.runs[id] = r
	return nil
}

// UpdateSteps implements Store.
func (m *MemoryStore) UpdateSteps(_ context.Context, id uuid.UUID, steps []Step) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[id]
	if r.Status == StatusRunning {
		r.Steps = cloneSteps(steps)
		m.runs[id] = r
	}
	return nil
}

// Finish implements Store.
func (m *MemoryStore) Finish(_ context.Context, id uuid.UUID, status Status, steps []Step, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[id]
	if r.Status != StatusRunning {
		return nil
	}
	now := time.Now().UTC()
	r.Status, r.Steps, r.Error, r.FinishedAt = status, cloneSteps(steps), msg, &now
	m.runs[id] = r
	return nil
}
