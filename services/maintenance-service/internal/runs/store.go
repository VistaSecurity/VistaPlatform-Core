package runs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Store persists runs. SQLStore is the implementation; tests use an in-memory one.
type Store interface {
	// Create inserts a running run. ErrRunInProgress when one already is.
	Create(ctx context.Context, run Run) (Run, error)
	Get(ctx context.Context, id uuid.UUID) (Run, error)
	// List returns the newest runs first.
	List(ctx context.Context, limit int) ([]Run, error)
	ListRunning(ctx context.Context) ([]Run, error)
	SetJobName(ctx context.Context, id uuid.UUID, name string) error
	UpdateSteps(ctx context.Context, id uuid.UUID, steps []Step) error
	// Finish settles a run that is still running. A run already settled is
	// left as it is (settling is idempotent: the watcher and a reconcile may
	// both reach the same Job's end).
	Finish(ctx context.Context, id uuid.UUID, status Status, steps []Step, errMsg string) error
}

// oneRunningIndex is the partial unique index that allows one running run.
const oneRunningIndex = "platform_maintenance_runs_one_running"

// SQLStore is Store over platform_maintenance_runs.
type SQLStore struct{ DB *sql.DB }

const runColumns = `id, kind, status, started_by, started_at, finished_at,
	COALESCE(from_version, ''), COALESCE(to_version, ''), COALESCE(k8s_job_name, ''), steps, COALESCE(error, '')`

func scanRun(row interface{ Scan(...any) error }) (Run, error) {
	var (
		r         Run
		startedBy uuid.NullUUID
		finished  sql.NullTime
		steps     []byte
	)
	if err := row.Scan(&r.ID, &r.Kind, &r.Status, &startedBy, &r.StartedAt, &finished,
		&r.FromVersion, &r.ToVersion, &r.JobName, &steps, &r.Error); err != nil {
		return Run{}, err
	}
	if startedBy.Valid {
		id := startedBy.UUID
		r.StartedBy = &id
	}
	if finished.Valid {
		t := finished.Time
		r.FinishedAt = &t
	}
	if err := json.Unmarshal(steps, &r.Steps); err != nil {
		return Run{}, fmt.Errorf("runs: decode steps: %w", err)
	}
	if r.Steps == nil {
		r.Steps = []Step{}
	}
	return r, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Create implements Store.
func (s SQLStore) Create(ctx context.Context, run Run) (Run, error) {
	steps, err := json.Marshal(nonNilSteps(run.Steps))
	if err != nil {
		return Run{}, err
	}
	var startedBy any
	if run.StartedBy != nil {
		startedBy = *run.StartedBy
	}
	row := s.DB.QueryRowContext(ctx, `
		INSERT INTO public.platform_maintenance_runs (id, kind, status, started_by, from_version, to_version, steps)
		VALUES ($1, $2, 'running', $3, $4, $5, $6)
		RETURNING `+runColumns,
		run.ID, string(run.Kind), startedBy, nullable(run.FromVersion), nullable(run.ToVersion), steps)
	out, err := scanRun(row)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == oneRunningIndex {
		return Run{}, ErrRunInProgress
	}
	return out, err
}

// Get implements Store.
func (s SQLStore) Get(ctx context.Context, id uuid.UUID) (Run, error) {
	r, err := scanRun(s.DB.QueryRowContext(ctx, `SELECT `+runColumns+` FROM public.platform_maintenance_runs WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

func (s SQLStore) query(ctx context.Context, q string, args ...any) ([]Run, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// List implements Store.
func (s SQLStore) List(ctx context.Context, limit int) ([]Run, error) {
	return s.query(ctx, `SELECT `+runColumns+` FROM public.platform_maintenance_runs ORDER BY started_at DESC, id LIMIT $1`, limit)
}

// ListRunning implements Store.
func (s SQLStore) ListRunning(ctx context.Context) ([]Run, error) {
	return s.query(ctx, `SELECT `+runColumns+` FROM public.platform_maintenance_runs WHERE status = 'running' ORDER BY started_at`)
}

// SetJobName implements Store.
func (s SQLStore) SetJobName(ctx context.Context, id uuid.UUID, name string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE public.platform_maintenance_runs SET k8s_job_name = $2 WHERE id = $1`, id, name)
	return err
}

// UpdateSteps implements Store. Only a running run's steps move.
func (s SQLStore) UpdateSteps(ctx context.Context, id uuid.UUID, steps []Step) error {
	b, err := json.Marshal(nonNilSteps(steps))
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE public.platform_maintenance_runs SET steps = $2 WHERE id = $1 AND status = 'running'`, id, b)
	return err
}

// Finish implements Store.
func (s SQLStore) Finish(ctx context.Context, id uuid.UUID, status Status, steps []Step, errMsg string) error {
	b, err := json.Marshal(nonNilSteps(steps))
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
		UPDATE public.platform_maintenance_runs
		   SET status = $2, steps = $3, error = $4, finished_at = $5
		 WHERE id = $1 AND status = 'running'`,
		id, string(status), b, nullable(errMsg), time.Now().UTC())
	return err
}

func nonNilSteps(s []Step) []Step {
	if s == nil {
		return []Step{}
	}
	return s
}
