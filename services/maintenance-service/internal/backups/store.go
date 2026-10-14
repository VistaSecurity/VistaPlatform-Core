package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Store persists backups. SQLStore is the implementation.
type Store interface {
	Insert(ctx context.Context, b Backup) error
	Get(ctx context.Context, id uuid.UUID) (Backup, error)
	GetByRun(ctx context.Context, runID uuid.UUID) (Backup, error)
	// List returns every backup not deleted, newest first.
	List(ctx context.Context) ([]Backup, error)
	MarkReady(ctx context.Context, id uuid.UUID, size int64, m Manifest, filePath string) error
	MarkFailed(ctx context.Context, id uuid.UUID) error
	MarkDeleted(ctx context.Context, id uuid.UUID) error
	// ReadyBeyond returns the ready backups older than the newest keep, oldest first.
	ReadyBeyond(ctx context.Context, keep int) ([]Backup, error)
}

// SQLStore is Store over platform_backups.
type SQLStore struct{ DB *sql.DB }

const backupColumns = `id, run_id, created_at, size_bytes, contents, encrypted, manifest, COALESCE(file_path, ''), status, deleted_at`

func scanBackup(row interface{ Scan(...any) error }) (Backup, error) {
	var (
		b        Backup
		runID    uuid.NullUUID
		size     sql.NullInt64
		contents []byte
		manifest []byte
		deleted  sql.NullTime
	)
	if err := row.Scan(&b.ID, &runID, &b.CreatedAt, &size, &contents, &b.Encrypted, &manifest, &b.FilePath, &b.Status, &deleted); err != nil {
		return Backup{}, err
	}
	if runID.Valid {
		id := runID.UUID
		b.RunID = &id
	}
	if size.Valid {
		v := size.Int64
		b.SizeBytes = &v
	}
	if deleted.Valid {
		t := deleted.Time
		b.DeletedAt = &t
	}
	if err := json.Unmarshal(contents, &b.Contents); err != nil {
		return Backup{}, fmt.Errorf("backups: decode contents: %w", err)
	}
	// An empty object is a backup whose manifest was never written (running
	// or failed): report null, not a zero manifest.
	if len(manifest) > 0 && string(manifest) != "{}" {
		var m Manifest
		if err := json.Unmarshal(manifest, &m); err != nil {
			return Backup{}, fmt.Errorf("backups: decode manifest: %w", err)
		}
		b.Manifest = &m
	}
	return b, nil
}

// Insert implements Store.
func (s SQLStore) Insert(ctx context.Context, b Backup) error {
	contents, err := json.Marshal(b.Contents)
	if err != nil {
		return err
	}
	var runID any
	if b.RunID != nil {
		runID = *b.RunID
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO public.platform_backups (id, run_id, created_at, contents, encrypted, manifest, file_path, status)
		VALUES ($1, $2, COALESCE($3, now()), $4, $5, '{}'::jsonb, $6, $7)`,
		b.ID, runID, nullTime(b.CreatedAt), contents, b.Encrypted, b.FilePath, b.Status)
	return err
}

func (s SQLStore) one(ctx context.Context, where string, arg any) (Backup, error) {
	b, err := scanBackup(s.DB.QueryRowContext(ctx, `SELECT `+backupColumns+` FROM public.platform_backups WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Backup{}, ErrNotFound
	}
	return b, err
}

// Get implements Store.
func (s SQLStore) Get(ctx context.Context, id uuid.UUID) (Backup, error) {
	return s.one(ctx, `id = $1`, id)
}

// GetByRun implements Store.
func (s SQLStore) GetByRun(ctx context.Context, runID uuid.UUID) (Backup, error) {
	return s.one(ctx, `run_id = $1`, runID)
}

func (s SQLStore) many(ctx context.Context, q string, args ...any) ([]Backup, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Backup{}
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// List implements Store.
func (s SQLStore) List(ctx context.Context) ([]Backup, error) {
	return s.many(ctx, `SELECT `+backupColumns+` FROM public.platform_backups WHERE status <> 'deleted' ORDER BY created_at DESC, id LIMIT 200`)
}

// MarkReady implements Store.
func (s SQLStore) MarkReady(ctx context.Context, id uuid.UUID, size int64, m Manifest, filePath string) error {
	mb, err := json.Marshal(m)
	if err != nil {
		return err
	}
	// contents gains what is only known once packed (cbom_signing_key).
	cb, err := json.Marshal(m.Contents)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
		UPDATE public.platform_backups SET status = 'ready', size_bytes = $2, manifest = $3, file_path = $4, contents = $5
		 WHERE id = $1 AND status = 'running'`, id, size, mb, filePath, cb)
	return err
}

// MarkFailed implements Store.
func (s SQLStore) MarkFailed(ctx context.Context, id uuid.UUID) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE public.platform_backups SET status = 'failed' WHERE id = $1 AND status = 'running'`, id)
	return err
}

// MarkDeleted implements Store.
func (s SQLStore) MarkDeleted(ctx context.Context, id uuid.UUID) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE public.platform_backups SET status = 'deleted', deleted_at = now() WHERE id = $1 AND status <> 'deleted'`, id)
	return err
}

// ReadyBeyond implements Store.
func (s SQLStore) ReadyBeyond(ctx context.Context, keep int) ([]Backup, error) {
	return s.many(ctx, `
		SELECT `+backupColumns+` FROM (
			SELECT * FROM public.platform_backups WHERE status = 'ready' ORDER BY created_at DESC, id OFFSET $1
		) older ORDER BY created_at, id`, keep)
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
