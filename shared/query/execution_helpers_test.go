package query_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
)

// Fixtures and helpers for the execution tests. They write real rows, so every
// one is scoped to a throwaway tenant that testdb.NewTenant CASCADE-deletes.

func testcatalogTargets() []catalog.Target { return testcatalog.New().Targets() }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// matchIDs compiles a query, runs it as the caller is meant to — inside a
// transaction that has set the tenant context, which is how RLS scopes it
// (§7.2) — and returns the ids it matched.
func matchIDs(t *testing.T, db *sql.DB, tenant uuid.UUID, q string) map[uuid.UUID]bool {
	t.Helper()
	c, err := query.Compile(q, "asset", testcatalog.New(), query.DefaultOptions(testcatalog.Ladder))
	if err != nil {
		t.Fatalf("Compile(%q): %v", q, err)
	}

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The translator emits no tenant predicate, by design. The caller sets the
	// tenant context and RLS does the scoping — so the test scopes the same
	// way, and a tenant predicate sneaking into the generated SQL would break
	// these tests rather than hide in them.
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		t.Fatalf("set tenant context: %v", err)
	}

	// The owner connection bypasses RLS, so the tenant filter is added here
	// explicitly — around the generated clause, never inside it.
	stmt := "SELECT a.id FROM assets a WHERE a.tenant_id = $" +
		itoa(len(c.Args)+1) + " AND (" + c.Where + ")"
	args := append(append([]any{}, c.Args...), tenant)

	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		t.Fatalf("run %q:\n  %s\n  %v", q, stmt, err)
	}
	defer func() { _ = rows.Close() }()

	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// matchOn is matchIDs over an arbitrary target, for the shapes that are not
// reached from `asset` — `endpoint/crypto`, `crypto_configuration/asset` and
// `certificate/asset`. Same contract: the tenant scoping is added around the
// generated clause, never inside it.
func matchOn(t *testing.T, db *sql.DB, tenant uuid.UUID, target, table, alias, q string) map[uuid.UUID]bool {
	t.Helper()
	c, err := query.Compile(q, target, testcatalog.New(), query.DefaultOptions(testcatalog.Ladder))
	if err != nil {
		t.Fatalf("Compile(%q) over %q: %v", q, target, err)
	}

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		t.Fatalf("set tenant context: %v", err)
	}

	stmt := "SELECT " + alias + ".id FROM " + table + " " + alias +
		" WHERE " + alias + ".tenant_id = $" + itoa(len(c.Args)+1) + " AND (" + c.Where + ")"
	args := append(append([]any{}, c.Args...), tenant)

	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		t.Fatalf("run %q over %q:\n  %s\n  %v", q, target, stmt, err)
	}
	defer func() { _ = rows.Close() }()

	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

func insertAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, name string, score int, assessedBy []string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	by := pq.Array([]string{})
	if assessedBy != nil {
		by = pq.Array(assessedBy)
	}
	_, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, class_key, class_path, display_name, risk_score, risk_assessed_by)
		VALUES ($1, $2, 'server', 'hardware.computer.server', $3, $4, $5)`,
		id, tenant, name, score, by)
	if err != nil {
		t.Fatalf("insert asset %s: %v", name, err)
	}
	return id
}

func insertFact(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, key, value, sourceKind, sourceRef string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6)`,
		tenant, asset, key, value, sourceKind, sourceRef)
	if err != nil {
		t.Fatalf("insert fact %s=%s (%s): %v", key, value, sourceKind, err)
	}
}

func insertIdentifier(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, kind, value string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value)
		VALUES ($1, $2, $3, $4)`, tenant, asset, kind, value)
	if err != nil {
		t.Fatalf("insert identifier %s=%s: %v", kind, value, err)
	}
}

func insertEndpoint(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, port int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO asset_endpoints
			(id, tenant_id, asset_id, address, port, transport, protocol, status)
		VALUES ($1, $2, $3, '198.51.100.10', $4, 'tcp', 'TLS', 'active')`, id, tenant, asset, port)
	if err != nil {
		t.Fatalf("insert endpoint :%d: %v", port, err)
	}
	return id
}

// insertCryptoConfiguration writes one crypto_implementations row. A NIL
// endpoint is written as SQL NULL — the at-rest case the shapes must reach
// through asset_id.
func insertCryptoConfiguration(t *testing.T, db *sql.DB, tenant, asset, endpoint uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var ep any
	method := "cloud_api"
	if endpoint != uuid.Nil {
		ep, method = endpoint, "active"
	}
	_, err := db.Exec(`
		INSERT INTO crypto_implementations
			(id, tenant_id, asset_id, endpoint_id, protocol, discovery_method)
		VALUES ($1, $2, $3, $4, 'TLS', $5)`, id, tenant, asset, ep, method)
	if err != nil {
		t.Fatalf("insert crypto configuration (endpoint %v): %v", ep, err)
	}
	return id
}

// insertCertificate writes a certificate and the junction row that links it to
// a configuration. `expiresIn` is a Postgres interval literal.
//
// The junction is the only link written, and deliberately: fixed the
// leaf-certificate divergence at the write side, and every reader that walks
// down from an asset reads the junction alone.
func insertCertificate(t *testing.T, db *sql.DB, tenant, configuration uuid.UUID, expiresIn string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO certificates
			(id, tenant_id, subject_dn, issuer_dn, fingerprint_sha256,
			 public_key_algorithm, not_before, not_after)
		VALUES ($1, $2, 'CN=shape.example.test', 'CN=Test CA', $3,
		        'RSA', now() - interval '1 day', now() + $4::interval)`,
		id, tenant, strings.ReplaceAll(uuid.New().String()+uuid.New().String(), "-", ""), expiresIn)
	if err != nil {
		t.Fatalf("insert certificate: %v", err)
	}
	_, err = db.Exec(`
		INSERT INTO crypto_implementation_certificates
			(crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, configuration, id)
	if err != nil {
		t.Fatalf("link certificate to configuration: %v", err)
	}
	return id
}

func insertFinding(t *testing.T, db *sql.DB, tenant uuid.UUID, producer, kind, subjectType string, subject uuid.UUID) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO findings
			(tenant_id, producer, kind, subject_type, subject_id, severity, score, summary)
		VALUES ($1, $2, $3, $4, $5, 'high', 70, 'seeded by the query conformance tests')`,
		tenant, producer, kind, subjectType, subject)
	if err != nil {
		t.Fatalf("insert finding %s/%s on %s: %v", producer, kind, subjectType, err)
	}
}

func setAttributes(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, attributes string) {
	t.Helper()
	_, err := db.Exec(`UPDATE assets SET attributes = $3::jsonb WHERE tenant_id = $1 AND id = $2`,
		tenant, asset, attributes)
	if err != nil {
		t.Fatalf("set attributes: %v", err)
	}
}
