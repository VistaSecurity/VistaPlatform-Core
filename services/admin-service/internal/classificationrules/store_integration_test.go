package classificationrules

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Real-Postgres assertions the stub store cannot make: that class_key is
// actually NULLABLE (most OUI rules depend on it), that the rule_kind CHECK
// carries all eight kinds including the two 2.10a added, that the
// (rule_kind, pattern) unique index is what the duplicate path maps to a 409,
// and that the seeded rows the generator writes really do load into an engine.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

func integrationStore(t *testing.T) (*SQLStore, *sql.DB) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchema(t, db)
	return NewSQLStore(db), db
}

// uniquePattern keeps parallel package binaries from colliding on the table's
// natural key. classification_rules is platform-scoped, so there is no tenant
// to isolate by — the same problem, and the same fix, as the EOL catalogue's.
func uniquePattern(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func str(s string) *string { return &s }

func TestIntegration_ClassificationRules_CreateReadUpdateDelete(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	pattern := uniquePattern(t, "it_crud")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.classification_rules WHERE pattern = $1`, pattern) })

	made, err := store.Create(ctx, Input{
		RuleKind: classify.KindCloudType, Pattern: pattern,
		ClassKey: str("object_storage"), Confidence: 0.95,
		SourceURL: str("https://example.test/docs"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if made.ID == "" {
		t.Fatal("Create returned no id — the RETURNING clause is not reading it back")
	}
	if made.CreatedAt == "" || made.UpdatedAt == "" {
		t.Errorf("Create returned no timestamps: %+v", made)
	}

	got, err := store.Get(ctx, made.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClassKey == nil || *got.ClassKey != "object_storage" {
		t.Errorf("Get returned %+v", got)
	}

	updated, err := store.Update(ctx, made.ID, Input{
		RuleKind: classify.KindCloudType, Pattern: pattern,
		ClassKey: str("managed_database"), Vendor: str("Example Cloud"), Confidence: 0.90,
		SourceURL: str("https://example.test/docs"),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.ClassKey == nil || *updated.ClassKey != "managed_database" {
		t.Errorf("Update did not take: %+v", updated)
	}
	if updated.Vendor == nil || *updated.Vendor != "Example Cloud" {
		t.Errorf("Update did not set the vendor: %+v", updated)
	}

	if err := store.Delete(ctx, made.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, made.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, made.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete: err = %v, want ErrNotFound", err)
	}
}

// class_key must be NULLABLE. It shipped NOT NULL in the 2.10 data-model slice
// and 2.10a dropped the constraint, because most OUI rules assert a VENDOR and
// deliberately no class — "a wrong class is worse than none". If the column
// goes back to NOT NULL, 123 of the 215 seeded rules stop being expressible and
// the seed fails at install.
func TestIntegration_ClassificationRules_VendorOnlyRuleHasANullClass(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	pattern := uniquePattern(t, "it_vendoronly")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.classification_rules WHERE pattern = $1`, pattern) })

	made, err := store.Create(ctx, Input{
		RuleKind: classify.KindPlatform, Pattern: pattern,
		Vendor: str("Vendor Only Ltd"), Confidence: 0.85,
		SourceURL: str("https://example.test/"),
	})
	if err != nil {
		t.Fatalf("Create: %v — class_key is NOT NULL again, and every vendor-only rule is now unexpressible", err)
	}
	if made.ClassKey != nil {
		t.Errorf("ClassKey = %q, want NULL", *made.ClassKey)
	}

	var isNullable string
	if err := db.QueryRow(`
        SELECT is_nullable FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'classification_rules'
          AND column_name = 'class_key'`).Scan(&isNullable); err != nil {
		t.Fatalf("read column nullability: %v", err)
	}
	if isNullable != "YES" {
		t.Errorf("class_key is_nullable = %q, want YES", isNullable)
	}
}

// The rule_kind CHECK must accept every kind the engine matches. `model` and
// `platform` were added in 2.10a when the in-package class hints moved into the
// table; a CHECK that lags the engine means a rule the admin console offers is
// one the database refuses, with a 500 as the only explanation.
func TestIntegration_ClassificationRules_CheckAcceptsEveryEngineKind(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()

	for _, kind := range classify.Kinds {
		t.Run(kind, func(t *testing.T) {
			pattern := uniquePattern(t, "it_kind_"+kind)
			t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.classification_rules WHERE pattern = $1`, pattern) })

			if _, err := store.Create(ctx, Input{
				RuleKind: kind, Pattern: pattern, Vendor: str("Kind Probe"),
				Confidence: 0.80, SourceURL: str("https://example.test/"),
			}); err != nil {
				t.Fatalf("the rule_kind CHECK refuses %q, which the engine matches: %v", kind, err)
			}
		})
	}

	// And it still refuses a kind nothing matches, so the constraint is doing
	// work rather than merely existing.
	if _, err := db.Exec(`
        INSERT INTO public.classification_rules (rule_kind, pattern, vendor, confidence)
        VALUES ('astrology', 'mercury_retrograde', 'Nobody', 0.80)`); err == nil {
		_, _ = db.Exec(`DELETE FROM public.classification_rules WHERE rule_kind = 'astrology'`)
		t.Error("the rule_kind CHECK accepted a kind the engine has no matcher for")
	}
}

// A rule that asserts nothing is refused by the database, not just by the
// handler. The handler is the message; this is the guarantee.
func TestIntegration_ClassificationRules_RefusesARuleThatAssertsNothing(t *testing.T) {
	_, db := integrationStore(t)
	pattern := uniquePattern(t, "it_empty")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.classification_rules WHERE pattern = $1`, pattern) })

	if _, err := db.Exec(`
        INSERT INTO public.classification_rules (rule_kind, pattern, confidence)
        VALUES ('oui', $1, 0.80)`, pattern); err == nil {
		t.Error("a rule with no class, no vendor and no model was accepted")
	}
}

// The duplicate path really is the (rule_kind, pattern) unique index — which is
// what makes the handler's 409 correct rather than a guess about what went
// wrong.
func TestIntegration_ClassificationRules_DuplicateIdentityIsDetected(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	pattern := uniquePattern(t, "it_dupe")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.classification_rules WHERE pattern = $1`, pattern) })

	in := Input{
		RuleKind: classify.KindPlatform, Pattern: pattern,
		Vendor: str("Dupe Co"), Confidence: 0.80, SourceURL: str("https://example.test/"),
	}
	if _, err := store.Create(ctx, in); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := store.Create(ctx, in); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Create: err = %v, want ErrDuplicate — the handler would answer 500 instead of 409", err)
	}

	// The same pattern under a DIFFERENT kind is a different rule, and must not
	// collide: the index is on the pair.
	other := in
	other.RuleKind = classify.KindCloudType
	if _, err := store.Create(ctx, other); err != nil {
		t.Errorf("the same pattern under a different kind collided: %v", err)
	}
}

// The rows seed.sql writes load into a working engine.
//
// This is the assertion that ties the two homes together: the generator emits
// the Go table AND the seeded rows from one YAML, and if the seeded shape were
// wrong — a class key that is not in the taxonomy, a banner regexp that does not
// compile, a confidence outside the band — the compiled-in table would still be
// fine and only a running deployment would find out.
func TestIntegration_ClassificationRules_SeededRowsBuildAnEngine(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	testdb.ApplySeed(t, db)

	rules, err := store.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(rules) < 100 {
		t.Fatalf("only %d seeded rules; the generated seed region is not being applied", len(rules))
	}

	engine, err := classify.NewStrict(rules)
	if err != nil {
		t.Fatalf("the seeded rows do not build an engine: %v", err)
	}

	// And it classifies. A cloud resource type is the highest-confidence
	// evidence in the table and needs no fixture beyond its own name.
	got := engine.Classify(ctx, classify.ClassifyInput{CloudResourceType: "aws_s3_bucket"})
	if got.Class != "object_storage" {
		t.Errorf("an engine over the seeded rows classified aws_s3_bucket as %q, want object_storage", got.Class)
	}

	// Every kind the YAML seeds is present in the table. A kind whose rows
	// silently failed to insert is a whole class of evidence gone.
	seen := map[string]int{}
	for _, r := range rules {
		seen[r.Kind]++
	}
	for _, kind := range classify.Kinds {
		if seen[kind] == 0 {
			t.Errorf("no %s rules were seeded", kind)
		}
	}
}

// Re-applying the seed reconciles a seeded rule rather than erroring or
// duplicating it, and leaves an admin's OWN rule alone. That is the documented
// contract of the generated region's ON CONFLICT, and the chart re-runs seed.sql
// on every helm upgrade.
func TestIntegration_ClassificationRules_ReseedingIsIdempotentAndKeepsAdminRules(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	testdb.ApplySeed(t, db)

	if _, _, err := store.List(ctx, Query{PageSize: MaxPageSize}); err != nil {
		t.Fatalf("List after the first seed: %v", err)
	}

	pattern := uniquePattern(t, "it_adminrule")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.classification_rules WHERE pattern = $1`, pattern) })
	mine, err := store.Create(ctx, Input{
		RuleKind: classify.KindPlatform, Pattern: pattern,
		ClassKey: str("switch"), Vendor: str("Admin Co"), Confidence: 0.70,
		SourceURL: str("https://example.test/"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	countSeeded := func() int {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM public.classification_rules WHERE rule_kind = 'cloud_type'`,
		).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	seededBefore := countSeeded()

	// FORCE: re-applying the seed is the assertion, so it must not be skipped as
	// already-applied.
	testdb.ForceApplySeed(t, db)

	if got := countSeeded(); got != seededBefore {
		t.Errorf("re-seeding changed the cloud_type row count from %d to %d — the ON CONFLICT target is wrong", seededBefore, got)
	}
	if _, err := store.Get(ctx, mine.ID); err != nil {
		t.Errorf("re-seeding removed a rule the admin added: %v", err)
	}
}
