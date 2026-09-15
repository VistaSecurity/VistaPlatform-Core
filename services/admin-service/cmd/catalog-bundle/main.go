// Command catalog-bundle exports the platform catalogues (end-of-life,
// vulnerability) as an offline bundle for an air-gapped install.
//
//	make build-catalog-bundle DATABASE_URL=postgres://…
//
// Run it against a CONNECTED install whose mirror feeds are up to date; carry
// the resulting tarball across the gap; import it in the disconnected install's
// admin console at Catalog ▸ End-of-life ▸ Import bundle (or POST it to
// /api/v1/admin-service/admin/catalogs/import-bundle).
//
// The bundle is a gzipped tar of `manifest.json` plus one JSONL file per
// catalogue. The manifest carries a SHA-256 and a row count per file, and the
// importer verifies every one of them BEFORE applying a single row. Integrity,
// not entitlement: these catalogues are Core, so there is nothing to license and
// no key this product would then have to manage. An operator who also wants
// provenance can sign the tarball with their own key and check it before import.
//
// See docsv4/core/operate/catalogs.md.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/jobs/catalogfeeds"
)

func main() {
	out := flag.String("out", "", "output path (default: ./catalog-bundle-<YYYY-MM-DD>.tar.gz)")
	dsn := flag.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string (default: $DATABASE_URL)")
	flag.Parse()

	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "catalog-bundle: no database. Pass --database-url or set DATABASE_URL.")
		os.Exit(2)
	}
	path := *out
	if path == "" {
		path = fmt.Sprintf("catalog-bundle-%s.tar.gz", time.Now().UTC().Format("2006-01-02"))
	}

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog-bundle: open database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "catalog-bundle: connect: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog-bundle: create %s: %v\n", path, err)
		os.Exit(1)
	}
	// Removed on failure so a partial tarball is never left behind looking like
	// a usable bundle — it would fail verification on import, but only after
	// someone had carried it across the gap.
	manifest, err := catalogfeeds.BuildBundle(context.Background(), catalogfeeds.NewSQLStore(db), f)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		fmt.Fprintf(os.Stderr, "catalog-bundle: %v\n", err)
		os.Exit(1)
	}

	info, statErr := os.Stat(path)
	fmt.Printf("wrote %s\n", path)
	if statErr == nil {
		fmt.Printf("  %d bytes compressed\n", info.Size())
	}
	fmt.Printf("  generated_at %s\n", manifest.GeneratedAt.Format(time.RFC3339))
	for _, file := range manifest.Files {
		fmt.Printf("  %-32s %8d rows  sha256:%s\n", file.Name, file.Rows, file.SHA256)
	}
	fmt.Println()
	fmt.Println("Import it in the disconnected install: Catalog ▸ End-of-life ▸ Import bundle.")
}
