package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var sessionPools sync.Map // *sql.DB -> *sql.DB; removed by CloseWithSessionPool.

// RegisterSessionPool binds a small control pool to the exact DSN used to open
// its data pool. Session-lock callbacks may open data transactions, so holding
// these locks on the data pool itself would deadlock when that pool is full.
// Registration does not connect or log the DSN. Owners must close both pools
// with CloseWithSessionPool (the shared connection and test helpers do so).
func RegisterSessionPool(db *sql.DB, driverName, dsn string) error {
	pool, err := sql.Open(driverName, dsn)
	if err != nil {
		return fmt.Errorf("open session control pool: %w", err)
	}
	pool.SetMaxOpenConns(8)
	pool.SetMaxIdleConns(1)
	pool.SetConnMaxIdleTime(time.Minute)
	pool.SetConnMaxLifetime(5 * time.Minute)
	if _, loaded := sessionPools.LoadOrStore(db, pool); loaded {
		_ = pool.Close()
		return errors.New("session control pool already registered")
	}
	return nil
}

// CloseWithSessionPool releases the associated control pool and the data pool.
func CloseWithSessionPool(db *sql.DB) error {
	var controlErr error
	if pool, ok := sessionPools.LoadAndDelete(db); ok {
		controlErr = pool.(*sql.DB).Close()
	}
	return errors.Join(controlErr, db.Close())
}

// SessionAdvisoryLock names one session lock. All keys in an operation must be
// acquired together: callbacks must not nest another session-lock helper.
type SessionAdvisoryLock struct {
	Key    string
	Shared bool
}

// WithSessionAdvisoryLocks acquires deterministic session locks using the
// dedicated control pool before fn opens any data transaction. Include every
// needed key in this call instead of nesting helpers, which could otherwise
// exhaust the bounded control pool. No implicit environment/credential fallback
// exists for unregistered database handles.
func WithSessionAdvisoryLocks(ctx context.Context, db *sql.DB, requested []SessionAdvisoryLock, fn func() error) (err error) {
	pool, ok := sessionPools.Load(db)
	if !ok {
		return errors.New("database has no registered session control pool")
	}
	byKey := make(map[string]bool, len(requested))
	for _, lock := range requested {
		if shared, exists := byKey[lock.Key]; !exists || shared {
			byKey[lock.Key] = lock.Shared
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	conn, err := pool.(*sql.DB).Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	acquired := make([]string, 0, len(keys))
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for i := len(acquired) - 1; i >= 0; i-- {
			key := acquired[i]
			query := `SELECT pg_advisory_unlock(hashtextextended($1,0))`
			if byKey[key] {
				query = `SELECT pg_advisory_unlock_shared(hashtextextended($1,0))`
			}
			var unlocked bool
			unlockErr := conn.QueryRowContext(unlockCtx, query, key).Scan(&unlocked)
			if unlockErr == nil && !unlocked {
				unlockErr = errors.New("session advisory lock was not held")
			}
			if unlockErr != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				err = errors.Join(err, fmt.Errorf("unlock session advisory lock: %w", unlockErr))
				return
			}
		}
	}()
	for _, key := range keys {
		query := `SELECT pg_advisory_lock(hashtextextended($1,0))`
		if byKey[key] {
			query = `SELECT pg_advisory_lock_shared(hashtextextended($1,0))`
		}
		if _, err := conn.ExecContext(ctx, query, key); err != nil {
			// Cancellation can make acquisition ambiguous. Closing the actual
			// connection releases every held lock, including an ambiguous one.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			acquired = nil
			return fmt.Errorf("acquire session advisory lock: %w", err)
		}
		acquired = append(acquired, key)
	}
	return fn()
}
