package database

import (
	"database/sql"
	"os"
	"testing"
)

// TestIntegration_ConnectSendsJITOff proves the wiring, not just the DSN
// helper: pools opened through Connect (the data pool and the session-lock
// control pool) really have jit=off on the server, and DB_JIT=on leaves the
// server default (on, in stock Postgres).
func TestIntegration_ConnectSendsJITOff(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	show := func(t *testing.T, db *sql.DB) string {
		t.Helper()
		var v string
		if err := db.QueryRow(`SHOW jit`).Scan(&v); err != nil {
			t.Fatalf("show jit: %v", err)
		}
		return v
	}

	t.Run("default is off", func(t *testing.T) {
		t.Setenv(DBJITEnvVar, "")
		db, err := Connect(url)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer func() { _ = CloseWithSessionPool(db) }()
		if got := show(t, db); got != "off" {
			t.Fatalf("data pool SHOW jit = %q, want off", got)
		}
		control, ok := sessionPools.Load(db)
		if !ok {
			t.Fatal("no session control pool registered")
		}
		if got := show(t, control.(*sql.DB)); got != "off" {
			t.Fatalf("control pool SHOW jit = %q, want off", got)
		}
	})
	t.Run("kill switch leaves server default", func(t *testing.T) {
		t.Setenv(DBJITEnvVar, "on")
		db, err := Connect(url)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer func() { _ = CloseWithSessionPool(db) }()
		if got := show(t, db); got != "on" {
			t.Fatalf("SHOW jit = %q, want on (server default)", got)
		}
	})
}
