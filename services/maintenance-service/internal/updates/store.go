package updates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Status is the platform_update_status row. Every field is nullable: before the
// first check the row does not exist and a Status is all nil.
type Status struct {
	CheckedAt       *time.Time `json:"checked_at"`
	Source          *string    `json:"source"`
	CurrentVersion  *string    `json:"current_version"`
	LatestVersion   *string    `json:"latest_version"`
	NotesURL        *string    `json:"notes_url"`
	Error           *string    `json:"error"`
	PrereleasesSeen []string   `json:"prereleases_seen"`
}

// Store persists the single status row.
type Store interface {
	Get(ctx context.Context) (Status, error)
	// SaveSuccess replaces the row with a successful check's result and clears
	// the error.
	SaveSuccess(ctx context.Context, s Status) error
	// SaveFailure records that a check failed. It touches only checked_at,
	// source, current_version and error: the last good latest_version stays, so
	// a registry outage does not make an announced release vanish.
	SaveFailure(ctx context.Context, checkedAt time.Time, source, current, errMsg string) error
}

// PGStore is the Postgres Store.
type PGStore struct{ DB *sql.DB }

// Get implements Store.
func (p PGStore) Get(ctx context.Context) (Status, error) {
	var (
		s                                       Status
		checked                                 sql.NullTime
		source, cur, latest, notes, errMsg, pre sql.NullString
	)
	err := p.DB.QueryRowContext(ctx, `
		SELECT checked_at, source, current_version, latest_version, notes_url, error, prereleases_seen::text
		  FROM public.platform_update_status WHERE id = 1`).
		Scan(&checked, &source, &cur, &latest, &notes, &errMsg, &pre)
	if errors.Is(err, sql.ErrNoRows) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	if checked.Valid {
		t := checked.Time
		s.CheckedAt = &t
	}
	s.Source, s.CurrentVersion, s.LatestVersion = strPtr(source), strPtr(cur), strPtr(latest)
	s.NotesURL, s.Error = strPtr(notes), strPtr(errMsg)
	if pre.Valid && pre.String != "" {
		if err := json.Unmarshal([]byte(pre.String), &s.PrereleasesSeen); err != nil {
			return Status{}, err
		}
	}
	return s, nil
}

func strPtr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

// SaveSuccess implements Store.
func (p PGStore) SaveSuccess(ctx context.Context, s Status) error {
	pre, err := json.Marshal(nonNil(s.PrereleasesSeen))
	if err != nil {
		return err
	}
	_, err = p.DB.ExecContext(ctx, `
		INSERT INTO public.platform_update_status
		    (id, checked_at, source, current_version, latest_version, notes_url, error, prereleases_seen)
		VALUES (1, $1, $2, $3, $4, $5, NULL, $6::jsonb)
		ON CONFLICT (id) DO UPDATE SET
		    checked_at = EXCLUDED.checked_at,
		    source = EXCLUDED.source,
		    current_version = EXCLUDED.current_version,
		    latest_version = EXCLUDED.latest_version,
		    notes_url = EXCLUDED.notes_url,
		    error = NULL,
		    prereleases_seen = EXCLUDED.prereleases_seen`,
		s.CheckedAt, s.Source, s.CurrentVersion, s.LatestVersion, s.NotesURL, string(pre))
	return err
}

// SaveFailure implements Store.
func (p PGStore) SaveFailure(ctx context.Context, checkedAt time.Time, source, current, errMsg string) error {
	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO public.platform_update_status (id, checked_at, source, current_version, error)
		VALUES (1, $1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET
		    checked_at = EXCLUDED.checked_at,
		    source = EXCLUDED.source,
		    current_version = EXCLUDED.current_version,
		    error = EXCLUDED.error`,
		checkedAt, source, current, errMsg)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// lockKey is the advisory-lock key serialising update checks across replicas
// ("VistaUpd" in ASCII).
const lockKey int64 = 0x5669737461557064

// PGLocker takes a session-level Postgres advisory lock on a dedicated
// connection, so exactly one replica checks at a time and the lock dies with
// the connection if the pod does.
type PGLocker struct{ DB *sql.DB }

// TryLock returns ok=false (and a no-op release) when another holder has it.
func (l PGLocker) TryLock(ctx context.Context) (release func(), ok bool, err error) {
	conn, err := l.DB.Conn(ctx)
	if err != nil {
		return func() {}, false, err
	}
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil {
		_ = conn.Close()
		return func() {}, false, err
	}
	if !got {
		_ = conn.Close()
		return func() {}, false, nil
	}
	return func() {
		// Unlock on its own context: the caller's may already be cancelled.
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(uctx, `SELECT pg_advisory_unlock($1)`, lockKey)
		_ = conn.Close()
	}, true, nil
}
