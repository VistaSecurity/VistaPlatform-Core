package services

// The two Core frameworks workstream 3.6 seeds: Inventory Hygiene and
// Lifecycle (ADR-0005 D5).
//
// These are the first frameworks whose controls measure the inventory RECORD
// rather than the cryptography on it, and the first that read facts and
// findings instead of columns on certificates and crypto configurations. What
// makes them worth an integration test is not the arithmetic — it is the
// three-valued behaviour, which no unit test can reach because it depends on
// rows being absent from real tables:
//
//   - a lifecycle control over an asset the EOL catalogue has never resolved a
//     date for must read NOT ASSESSED, never "supported";
//   - a hygiene counting control over an asset the hygiene producer has never
//     evaluated must read NOT ASSESSED, never "zero findings, therefore clean".
//
// Both are the failure this codebase keeps rediscovering: "we did not check"
// rendered as "it passed". They are asserted here against the SEEDED framework
// rows, so a seed that loses a measurement fails this test rather than silently
// scoring 100.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type inventoryFrameworkFixture struct {
	db   *sqlx.DB
	eval *RuleEvaluator
}

func newInventoryFrameworkFixture(t *testing.T) *inventoryFrameworkFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	return &inventoryFrameworkFixture{db: db, eval: NewRuleEvaluator(db, NewMeasurementExtractor(db))}
}

// controlID resolves a seeded control by its framework and control code. It
// fails the test when the row is missing, which is the point: these tests are
// as much about the seed as about the evaluator.
func (f *inventoryFrameworkFixture) controlID(t *testing.T, framework, control string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.db.Get(&id, `
		SELECT c.id
		FROM platform_framework_controls c
		JOIN platform_frameworks f ON f.id = c.framework_id
		WHERE f.code = $1 AND c.control_id = $2`, framework, control); err != nil {
		t.Fatalf("seeded control %s/%s not found: %v", framework, control, err)
	}
	return id
}

// tenant returns a fresh tenant. Controls evaluate over a whole tenant, so each
// scenario gets its own rather than trying to compose passing and failing
// assets in one.
func (f *inventoryFrameworkFixture) tenant(t *testing.T) uuid.UUID {
	t.Helper()
	return testdb.NewTenant(t, f.db.DB)
}

type assetSpec struct {
	hostname     string
	class        string
	classPath    string
	owner        string
	supportGroup string
	site         string
	lastSeenDays int
	status       string
	assessedBy   []string
}

func (f *inventoryFrameworkFixture) asset(t *testing.T, tenant uuid.UUID, spec assetSpec) uuid.UUID {
	t.Helper()
	if spec.class == "" {
		spec.class, spec.classPath = "server", "hardware.computer.server"
	}
	if spec.status == "" {
		spec.status = "monitoring"
	}
	var id uuid.UUID
	var owner, group, site interface{}
	if spec.owner != "" {
		owner = spec.owner
	}
	if spec.supportGroup != "" {
		group = spec.supportGroup
	}
	if spec.site != "" {
		site = spec.site
	}
	if err := f.db.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, hostname, display_name, owner_email,
			support_group, site, asset_status, last_seen_at)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, NOW() - ($9 || ' days')::interval)
		RETURNING id`,
		tenant, spec.class, spec.classPath, spec.hostname, owner, group, site, spec.status,
		spec.lastSeenDays).Scan(&id); err != nil {
		t.Fatalf("seed asset %s: %v", spec.hostname, err)
	}

	// Coverage goes in `producer_assessments`, which is what the finding shape
	// gates on (workstream 3.2) — NOT `assets.risk_assessed_by`, which carries
	// only the RISK-feeding producers and therefore never carries `hygiene`.
	// Seeding the array here would have made these cases pass against a gate
	// that, in production, nothing would ever satisfy.
	for _, producer := range spec.assessedBy {
		if _, err := f.db.Exec(`
			INSERT INTO producer_assessments (tenant_id, asset_id, producer)
			VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, tenant, id, producer); err != nil {
			t.Fatalf("seed coverage %s/%s: %v", spec.hostname, producer, err)
		}
	}
	return id
}

func (f *inventoryFrameworkFixture) fact(t *testing.T, tenant, asset uuid.UUID, key string, value string) {
	t.Helper()
	if _, err := f.db.Exec(`
		INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, $3, to_jsonb($4::text), 'measured', 'eol_catalogue:test', NOW())`,
		tenant, asset, key, value); err != nil {
		t.Fatalf("seed fact %s: %v", key, err)
	}
}

func (f *inventoryFrameworkFixture) finding(t *testing.T, tenant, subject uuid.UUID, subjectType, producer, kind string) {
	t.Helper()
	if _, err := f.db.Exec(`
		INSERT INTO findings (tenant_id, producer, kind, subject_type, subject_id, severity, score,
			summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, $5, 'medium', 0, $3, 'ACTIVE', 'NEW')`,
		tenant, producer, kind, subjectType, subject); err != nil {
		t.Fatalf("seed finding %s/%s: %v", producer, kind, err)
	}
}

// evaluate runs one seeded control for one tenant.
func (f *inventoryFrameworkFixture) evaluate(t *testing.T, tenant uuid.UUID, framework, control string) *EvaluationResult {
	t.Helper()
	res, err := f.eval.EvaluateControl(tenant, f.controlID(t, framework, control), "platform")
	if err != nil {
		t.Fatalf("evaluate %s/%s: %v", framework, control, err)
	}
	return res
}

func assertStatus(t *testing.T, res *EvaluationResult, want string, why string) {
	t.Helper()
	if res.Status != want {
		t.Errorf("status = %q (reason %q, %d finding(s)), want %q — %s",
			res.Status, res.NotAssessedReason, len(res.Findings), want, why)
	}
}

// ---------------------------------------------------------------- hygiene --

func TestIntegration_InventoryHygiene_ScoresTheRecord(t *testing.T) {
	f := newInventoryFrameworkFixture(t)

	t.Run("IH-001 an asset with neither owner nor support group fails", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "unowned.example.test"})
		res := f.evaluate(t, tenant, "inventory-hygiene", "IH-001")
		assertStatus(t, res, "fail", "the asset names nobody")
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(res.Findings))
		}
		if res.Findings[0].SubjectType != SubjectAsset {
			t.Errorf("subject type = %q, want %q", res.Findings[0].SubjectType, SubjectAsset)
		}
	})

	t.Run("IH-001 a support group counts as an owner", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "team-owned.example.test", supportGroup: "platform-ops"})
		assertStatus(t, f.evaluate(t, tenant, "inventory-hygiene", "IH-001"), "pass",
			"accountability is a person OR a group; the hygiene producer's no_owner finding says both must be missing")
	})

	t.Run("IH-001 ignores assets still waiting in Approvals", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "pending.example.test", status: "pending_approval"})
		res := f.evaluate(t, tenant, "inventory-hygiene", "IH-001")
		assertStatus(t, res, "not_assessed",
			"a discovery nobody has approved yet has no owner BY CONSTRUCTION; scoring it would make "+
				"every new discovery a hygiene violation and the score a function of scan volume")
	})

	t.Run("IH-002 the unknown_host placeholder fails, a real class passes", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "mystery.example.test", class: "unknown_host", classPath: "unknown_host"})
		assertStatus(t, f.evaluate(t, tenant, "inventory-hygiene", "IH-002"), "fail",
			"unknown_host is the classifier saying it could not decide")

		classified := f.tenant(t)
		f.asset(t, classified, assetSpec{hostname: "known.example.test"})
		assertStatus(t, f.evaluate(t, classified, "inventory-hygiene", "IH-002"), "pass",
			"a classified asset is compliant")
	})

	t.Run("IH-003 location may be any of site, region, zone or a location row", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "nowhere.example.test"})
		assertStatus(t, f.evaluate(t, tenant, "inventory-hygiene", "IH-003"), "fail", "no location at all")

		sited := f.tenant(t)
		f.asset(t, sited, assetSpec{hostname: "dc1.example.test", site: "dc1"})
		assertStatus(t, f.evaluate(t, sited, "inventory-hygiene", "IH-003"), "pass", "a site is a location")
	})

	t.Run("IH-004 stale beyond thirty days fails", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "stale.example.test", lastSeenDays: 45})
		assertStatus(t, f.evaluate(t, tenant, "inventory-hygiene", "IH-004"), "fail",
			"45 days without an observation is past the hygiene producer's first stale rung")

		fresh := f.tenant(t)
		f.asset(t, fresh, assetSpec{hostname: "fresh.example.test", lastSeenDays: 3})
		assertStatus(t, f.evaluate(t, fresh, "inventory-hygiene", "IH-004"), "pass", "seen three days ago")
	})
}

// TestIntegration_InventoryHygiene_CountingControlsAreThreeValued is the one
// that matters. IH-005 and IH-006 count findings, and a count of zero means two
// completely different things depending on whether anything ever looked.
func TestIntegration_InventoryHygiene_CountingControlsAreThreeValued(t *testing.T) {
	f := newInventoryFrameworkFixture(t)

	t.Run("not assessed until the hygiene producer has evaluated the asset", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "unjudged.example.test", owner: "ops@example.test"})
		res := f.evaluate(t, tenant, "inventory-hygiene", "IH-005")
		assertStatus(t, res, "not_assessed",
			"nothing has looked for duplicates on this asset. Reporting PASS here is the "+
				"check-that-cannot-fail shape: every install without the producer would score 100")
		if res.Score != nil {
			t.Errorf("score = %d, want nil — a control nobody assessed has no score", *res.Score)
		}
	})

	t.Run("assessed and clean passes", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "judged-clean.example.test", assessedBy: []string{"hygiene"}})
		assertStatus(t, f.evaluate(t, tenant, "inventory-hygiene", "IH-005"), "pass",
			"the producer ran and found no duplicate: that is assessed clean, and it is a different "+
				"answer from the case above")
	})

	t.Run("assessed with a duplicate fails", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "twin.example.test", assessedBy: []string{"hygiene"}})
		f.finding(t, tenant, asset, "asset", "hygiene", "duplicate_suspected")
		assertStatus(t, f.evaluate(t, tenant, "inventory-hygiene", "IH-005"), "fail", "one open duplicate finding")
	})

	t.Run("IH-006 counts findings on the asset's relationships, not on the asset", func(t *testing.T) {
		tenant := f.tenant(t)
		from := f.asset(t, tenant, assetSpec{hostname: "edge-from.example.test", assessedBy: []string{"hygiene"}})
		to := f.asset(t, tenant, assetSpec{hostname: "edge-to.example.test", assessedBy: []string{"hygiene"}})
		var edge uuid.UUID
		if err := f.db.QueryRow(`
			INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, status)
			VALUES ($1, $2, $3, 'connects_to', 'active') RETURNING id`, tenant, from, to).Scan(&edge); err != nil {
			t.Fatalf("seed relationship: %v", err)
		}
		f.finding(t, tenant, edge, "relationship", "hygiene", "orphan_relationship")

		res := f.evaluate(t, tenant, "inventory-hygiene", "IH-006")
		assertStatus(t, res, "fail",
			"the finding's subject is the RELATIONSHIP, so a control that only looked at findings "+
				"whose subject is the asset would count nothing, forever and silently")
		if len(res.Findings) != 2 {
			t.Errorf("got %d findings, want 2 — an edge has two ends and both assets own the problem",
				len(res.Findings))
		}
	})
}

// -------------------------------------------------------------- lifecycle --

func TestIntegration_Lifecycle_ScoresResolvedDatesOnly(t *testing.T) {
	f := newInventoryFrameworkFixture(t)
	day := func(offset int) string {
		// Twelve hours past midnight, so the day count is never sitting on the
		// boundary between two answers.
		return time.Now().UTC().AddDate(0, 0, offset).Add(12 * time.Hour).Format(time.RFC3339)
	}

	t.Run("an OS the catalogue does not cover is NOT ASSESSED", func(t *testing.T) {
		tenant := f.tenant(t)
		f.asset(t, tenant, assetSpec{hostname: "uncatalogued.example.test"})
		res := f.evaluate(t, tenant, "lifecycle", "LC-001")
		assertStatus(t, res, "not_assessed",
			"no eol.os.date fact exists for this asset. 'We could not find out' and 'it is supported' "+
				"are different answers and a lifecycle report that conflates them is worse than none")
		if res.Score != nil {
			t.Errorf("score = %d, want nil", *res.Score)
		}
	})

	t.Run("an OS past end of life fails", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "eol-os.example.test"})
		f.fact(t, tenant, asset, "eol.os.date", day(-120))
		res := f.evaluate(t, tenant, "lifecycle", "LC-001")
		assertStatus(t, res, "fail", "the end-of-life date passed four months ago")
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(res.Findings))
		}
		if got := res.Findings[0].Evidence["measurement_value"]; got != -120 {
			t.Errorf("measurement_value = %v, want -120 (days, negative once the date has passed)", got)
		}
	})

	t.Run("an OS with support remaining passes", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "supported-os.example.test"})
		f.fact(t, tenant, asset, "eol.os.date", day(400))
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-001"), "pass", "over a year of support left")
	})

	t.Run("LC-002 is the ninety-day warning, and LC-001 is silent about it", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "soon.example.test"})
		f.fact(t, tenant, asset, "eol.os.date", day(45))
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-002"), "fail",
			"45 days out is inside the planning window")
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-001"), "pass",
			"it is not past end of life YET; the two controls exist so the difference is visible")
	})

	// The ladder is CUMULATIVE, and this pins it because the wording of a
	// "90-day warning" reads as though it were a window.
	//
	// LC-002's predicate is `days > 90`, so everything with ninety days or less
	// of support left fails it — including an asset that has none. That is not
	// an oversight: the rule vocabulary has no disjoint-window form (a `range`
	// rule passes INSIDE its bounds, which is the opposite polarity), and it is
	// the same cumulative shape the shipped cert-expiry-30/90 frameworks use.
	// The consequence a reader has to know is that a past-EOL operating system
	// appears on BOTH worklists and is scored by both controls, so the customer
	// documentation says "ninety days or less remaining, including none" rather
	// than "within 90 days".
	t.Run("an OS already past end of life fails the ninety-day control too", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "long-gone.example.test"})
		f.fact(t, tenant, asset, "eol.os.date", day(-120))
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-002"), "fail",
			"the ladder is cumulative: 'ninety days or less of support remaining' includes none at all")
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-001"), "fail",
			"and the High control fires as well — one asset, both rungs")
	})

	t.Run("software and hardware read their own facts", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "old-box.example.test"})
		f.fact(t, tenant, asset, "eol.sw.date", day(-10))
		f.fact(t, tenant, asset, "eol.hw.date", day(-800))
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-003"), "fail", "the package is ten days past EOL")
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-004"), "fail", "the hardware is years past support")

		// The OS control must NOT fire off the software fact. Each control
		// reads one key; a shape that ignored `af.key` would make all three
		// controls the same control.
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-001"), "not_assessed",
			"there is no eol.os.date for this asset, whatever its software and hardware say")
	})

	t.Run("an expired fact is not a current statement", func(t *testing.T) {
		tenant := f.tenant(t)
		asset := f.asset(t, tenant, assetSpec{hostname: "stale-fact.example.test"})
		f.fact(t, tenant, asset, "eol.os.date", day(-120))
		if _, err := f.db.Exec(`UPDATE asset_facts SET expires_at = NOW() - interval '1 day'
			WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset); err != nil {
			t.Fatalf("expire fact: %v", err)
		}
		assertStatus(t, f.evaluate(t, tenant, "lifecycle", "LC-001"), "not_assessed",
			"a fact past its expires_at has stopped being an answer")
	})
}
