package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// ScratchDatabase creates a brand-new database on the TEST_DATABASE_URL server,
// applies scripts/database/schema.sql and seed.sql to it, and drops it when the
// test ends. It skips, like Connect, when TEST_DATABASE_URL is unset.
//
// It exists for tests that must write GLOBAL state — a row every tenant and
// every service sees, such as the install's licence (platform_license) or its
// identity (platform_install). On the shared database such a row changes the
// behaviour of every other test binary running concurrently against it: an
// Enterprise licence written by one package makes another package's "Core
// denies paid capabilities" test fail, and which one loses depends on timing.
// Seeded-row isolation (restore in t.Cleanup) cannot help, because the
// pollution is visible DURING the test, not after it. A database of its own
// can.
//
// It costs a schema+seed apply (a few seconds), so use it only for tests that
// genuinely write global state; everything tenant-scoped belongs on Connect +
// NewTenant.
func ScratchDatabase(t *testing.T) *sql.DB {
	t.Helper()
	admin := Connect(t)

	name := "scratch_" + uuid.New().String()[:8]
	// CREATE DATABASE cannot run inside a transaction block, so a plain Exec.
	if _, err := admin.Exec(fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Fatalf("testdb: create scratch database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, name)); err != nil {
			t.Logf("testdb: drop scratch database %s: %v", name, err)
		}
	})

	u, err := url.Parse(os.Getenv(URLEnv))
	if err != nil {
		t.Fatalf("testdb: parse %s: %v", URLEnv, err)
	}
	u.Path = "/" + name
	dsn := u.String()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("testdb: open scratch database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("testdb: ping scratch database: %v", err)
	}
	if err := shareddb.RegisterSessionPool(db, "postgres", dsn); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	// Registered after the DROP, so it runs before it (Cleanup is LIFO): the
	// pools must be closed before the database can be dropped cleanly.
	t.Cleanup(func() { _ = shareddb.CloseWithSessionPool(db) })

	// schema.sql creates and alters cluster-wide roles, which a concurrent apply
	// to the SHARED database also does; two of those at once fail with "tuple
	// concurrently updated". Holding the shared database's schema lock while
	// applying here serializes the two. (The apply itself takes the scratch
	// database's own lock; advisory locks are per database, so the two cannot
	// deadlock each other.)
	withSchemaLock(t, admin, func(context.Context, *sql.Conn) {
		ApplySchemaAndSeed(t, db)
	})
	return db
}
