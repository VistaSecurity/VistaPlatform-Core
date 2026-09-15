package testdb

// RequireSchemaShareLock in both polarities, and the one in between.
//
// A guard has to be able to fail, and a guard for a RACE has to be shown
// failing deterministically — otherwise "it passed" only means the two binaries
// did not line up this time. These three drive the verdict function directly so
// the failing polarities are observed rather than raised.

import (
	"strings"
	"testing"
)

func TestIntegration_RequireSchemaShareLock_AcceptsAGuardedPass(t *testing.T) {
	err := checkSchemaShareLock(t, func(t *testing.T) func() {
		db := Connect(t)
		return func() {
			WithSchemaShareLock(t, db, func() {
				RetryTransient(t, func() error {
					_, err := db.Exec(`SELECT count(*) FROM tenants`)
					return err
				})
			})
		}
	})
	if err != nil {
		t.Fatalf("a pass that takes the share lock before its first query was reported: %v", err)
	}
}

func TestIntegration_RequireSchemaShareLock_ReportsAnUnguardedPass(t *testing.T) {
	err := checkSchemaShareLock(t, func(t *testing.T) func() {
		db := Connect(t)
		return func() {
			RetryTransient(t, func() error {
				_, err := db.Exec(`SELECT count(*) FROM tenants`)
				return err
			})
		}
	})
	if err == nil {
		t.Fatal("a pass that touches a table with no share lock was accepted — the guard cannot fail")
	}
	if !strings.Contains(err.Error(), "ran to completion") {
		t.Fatalf("wrong verdict for an unguarded pass: %v", err)
	}
}

// Taking the lock AFTER a table is already locked is the same cycle with extra
// steps: the apply waits on the table this transaction holds, this transaction
// waits on the advisory lock the apply holds.
func TestIntegration_RequireSchemaShareLock_ReportsALateLock(t *testing.T) {
	err := checkSchemaShareLock(t, func(t *testing.T) func() {
		db := Connect(t)
		return func() {
			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			if _, err := tx.Exec(`SELECT 1 FROM tenants LIMIT 1`); err != nil {
				t.Fatalf("read: %v", err)
			}
			WithSchemaShareLock(t, db, func() {
				if err := tx.Commit(); err != nil {
					t.Fatalf("commit: %v", err)
				}
			})
		}
	})
	if err == nil {
		t.Fatal("a pass that locks a table and only then takes the share lock was accepted")
	}
	if !strings.Contains(err.Error(), "already holding") {
		t.Fatalf("wrong verdict for a late lock: %v", err)
	}
}
