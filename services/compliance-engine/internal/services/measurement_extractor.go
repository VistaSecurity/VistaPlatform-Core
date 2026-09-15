package services

// The measurement extractor: ONE executor over the registry, replacing the
// nineteen hand-written SQL blocks this file used to hold (ADR-0005 D5,
// BUILD_PLAN workstream 3.6).
//
// A measurement type declares, in standards/measurement-types.yaml:
//
//	shape   — one of the whitelisted skeletons in measurement_shapes.go
//	value   — the name of a selectable that shape offers
//	where   — a QUERY-LANGUAGE predicate, compiled by shared/query against the
//	          production catalogue into a parameterised clause
//	evidence — which selectables travel on the resulting finding
//
// and this file turns that into one statement. Nothing the registry says
// reaches SQL as text: identifiers come from the shape and from the query
// catalogue, values are bind parameters. `measurement_types.extraction_query`
// — a column that held SQL and was never executed — is dropped rather than
// honoured, because a seeded query is an injection hazard and an upgrade hazard
// at once.
//
// The old switch was kept as a test oracle until the executor reproduced it
// measurement-for-measurement over a fixture (measurement_parity_integration_test.go
// and its golden file), then deleted. The golden file stays: it is what any
// future change to a shape, a transform or a predicate is checked against.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
)

// MeasurementValue represents a measurement value with metadata.
//
// SubjectID/SubjectType name the object the measurement was TAKEN ON, in the
// findings registry's subject vocabulary (shared/findings). The shape decides
// it, and the registry row's own `subject` is checked against the shape's by the
// generator, so a row cannot claim something untrue of every one of its
// instances:
//
//	asset       — every configuration, hygiene, fact and finding measurement.
//	              The query selects the ASSET's id and scopes on it, so the
//	              value is a statement about the asset, taken over whichever of
//	              its configurations or facts carry the column. The
//	              configurations themselves travel in
//	              evidence.crypto_implementation_ids.
//	certificate — every certificate measurement. The query selects c.id and
//	              scopes on c.id, so the value is about that one certificate.
//
// `crypto_configuration` as a SUBJECT is reserved for the configuration
// producer (workstream 3.5), which measures one configuration at a time.
type MeasurementValue struct {
	Value       interface{}            `json:"value"`
	SubjectID   uuid.UUID              `json:"subject_id"`
	SubjectType string                 `json:"subject_type"` // asset, certificate, crypto_configuration
	TenantID    uuid.UUID              `json:"tenant_id"`
	MeasuredAt  time.Time              `json:"measured_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MeasurementExtractor extracts measurements from inventory for compliance
// evaluation, one registry row at a time.
type MeasurementExtractor struct {
	db *sqlx.DB
	// plans are the registry compiled once: SQL, bind arguments, transform and
	// evidence writer per measurement-type code. A row that does not compile is
	// stored as its error and returned on every extraction of that code — an
	// unusable measurement type must fail loudly at the point of use, where the
	// rule evaluator counts it as a failed check, never silently pass.
	plans map[string]*measurementPlan
	errs  map[string]error
}

// measurementPlan is one registry row, ready to run.
type measurementPlan struct {
	def       MeasurementTypeDef
	shape     measurementShape
	sql       string
	extraArgs []any // the shape's own bind parameters beyond tenant and asset
	predArgs  []any // the compiled predicates' bind parameters
	columns   []string
	transform measurementTransform
	rowFilter measurementRowFilter
}

// compileMeasurementRegistry turns every row of a registry into a runnable
// plan, returning the plans that compiled and, by code, the error for each row
// that did not.
//
// It is a function over the registry rather than a method so the extractor and
// the CATALOGUE (measurement_catalogue.go) answer "does this row work?" from
// one place. They must agree: a code the extractor cannot serve must not be a
// code the rule builder offers, or an admin authors a control that errors on
// every evaluation. Two implementations of the same question is how they would
// come to disagree.
//
// Nothing here is cached. Compiling 28 rows is string work in the tens of
// microseconds, `GET /measurement-types` is a page-load endpoint, and a cache
// would need a reset hook to stay testable — which is a worse trade than
// recomputing.
func compileMeasurementRegistry(defs []MeasurementTypeDef) (map[string]*measurementPlan, map[string]error) {
	// The production catalogue with its own band ladder. No registry predicate
	// uses a band comparison — TestMeasurementRegistryUsesNoBandPredicate pins
	// that — so the ladder cannot influence an extraction; it is wired
	// correctly anyway rather than left to a zero value.
	cat := registrycatalog.New(registrycatalog.Options{})
	opts := query.DefaultOptionsFor(cat)
	plans := make(map[string]*measurementPlan, len(defs))
	errs := make(map[string]error)
	for _, def := range defs {
		plan, err := buildMeasurementPlan(def, cat, opts)
		if err != nil {
			errs[def.Code] = err
			continue
		}
		plans[def.Code] = plan
	}
	return plans, errs
}

// measurementCompileErrors reports which of the SHIPPED registry's rows do not
// compile. The catalogue withholds them; the extractor refuses them.
func measurementCompileErrors() map[string]error {
	_, errs := compileMeasurementRegistry(measurementTypeRegistry)
	return errs
}

// NewMeasurementExtractor compiles the registry and returns an extractor.
//
// Compilation is eager, and a row that fails it is LOGGED here by name — which
// is the only moment anything says so out loud. Storing the error and waiting
// for the first extraction would make a broken registry row look like a
// measurement that merely never fires, and "nothing is happening" is the one
// symptom this codebase keeps mistaking for "everything is fine". The
// catalogue withholds the same rows, so the log line is the operator's only
// notice that a measurement type shipped and then vanished from the rule
// builder.
//
// The shipped registry has no such row — TestMeasurementRegistryCompiles fails
// the build otherwise — so in production this loop is silent, and any line it
// prints means the deployed binary's registry and its shapes disagree.
func NewMeasurementExtractor(db *sqlx.DB) *MeasurementExtractor {
	plans, errs := compileMeasurementRegistry(measurementTypeRegistry)
	codes := make([]string, 0, len(errs))
	for code := range errs {
		codes = append(codes, code)
	}
	sort.Strings(codes) // deterministic order; map iteration is not
	for _, code := range codes {
		log.Printf("[MeasurementExtractor] ERROR: measurement type %q does not compile; it will be "+
			"withheld from the rule builder and refused on every extraction: %v", code, errs[code])
	}
	return &MeasurementExtractor{db: db, plans: plans, errs: errs}
}

// buildMeasurementPlan turns one registry row into a runnable statement.
func buildMeasurementPlan(def MeasurementTypeDef, cat *registrycatalog.Catalog, opts query.Options) (*measurementPlan, error) {
	shape, ok := measurementShapes[def.Source.Shape]
	if !ok {
		return nil, fmt.Errorf("measurement %q: unknown shape %q", def.Code, def.Source.Shape)
	}
	if def.Subject != shape.Subject {
		return nil, fmt.Errorf("measurement %q: declares subject %q but shape %q measures %q",
			def.Code, def.Subject, shape.Name, shape.Subject)
	}
	transform, ok := measurementTransforms[transformName(def)]
	if !ok {
		return nil, fmt.Errorf("measurement %q: unknown transform %q", def.Code, def.Source.Transform)
	}
	var rowFilter measurementRowFilter
	if def.Source.RowFilter != "" {
		rowFilter, ok = measurementRowFilters[def.Source.RowFilter]
		if !ok {
			return nil, fmt.Errorf("measurement %q: unknown row filter %q", def.Code, def.Source.RowFilter)
		}
	}
	measuredAt, ok := shape.MeasuredAt[def.Source.MeasuredAt]
	if !ok {
		return nil, fmt.Errorf("measurement %q: shape %q has no measured-at %q", def.Code, shape.Name, def.Source.MeasuredAt)
	}
	orderBy, ok := shape.OrderBy[def.Source.OrderBy]
	if !ok {
		return nil, fmt.Errorf("measurement %q: shape %q has no ordering %q", def.Code, shape.Name, def.Source.OrderBy)
	}

	// The shape's own bind parameter, when it has one. Bound, never
	// interpolated: a fact key and a producer are both registry text.
	var extraArgs []any
	switch {
	case shape.NeedsFactKey:
		if def.Source.FactKey == "" {
			return nil, fmt.Errorf("measurement %q: shape %q needs a fact_key", def.Code, shape.Name)
		}
		extraArgs = append(extraArgs, def.Source.FactKey)
	case shape.NeedsAssessedBy:
		if def.Source.AssessedBy == "" {
			return nil, fmt.Errorf("measurement %q: shape %q needs assessed_by", def.Code, shape.Name)
		}
		extraArgs = append(extraArgs, def.Source.AssessedBy)
	}
	paramStart := 3 + len(extraArgs)

	// The two predicates. AliasPrefix keeps the aliases each translation
	// generates apart, since both land in one statement.
	var predArgs []any
	where, err := compilePredicate(def.Source.Where, shape.Target, shape.Alias, "w", cat, opts, paramStart)
	if err != nil {
		return nil, fmt.Errorf("measurement %q: where: %w", def.Code, err)
	}
	predArgs = append(predArgs, where.args...)
	subjectWhere := compiled{clause: "TRUE"}
	if def.Source.SubjectWhere != "" {
		if shape.SubjectTarget == "" {
			return nil, fmt.Errorf("measurement %q: shape %q offers no subject predicate", def.Code, shape.Name)
		}
		subjectWhere, err = compilePredicate(def.Source.SubjectWhere, shape.SubjectTarget, shape.SubjectAlias, "s",
			cat, opts, paramStart+len(predArgs))
		if err != nil {
			return nil, fmt.Errorf("measurement %q: subject_where: %w", def.Code, err)
		}
		predArgs = append(predArgs, subjectWhere.args...)
	}

	// Which selectables this row reads: the value first, then every evidence
	// entry, de-duplicated so a column named twice is read once.
	columns, err := planMeasurementColumns(def, shape)
	if err != nil {
		return nil, err
	}

	selectList := []string{
		shape.SubjectIDExpr + " AS subject_id",
		shape.TenantExpr + " AS tenant_id",
		measuredAt + " AS measured_at",
	}
	for i, name := range columns {
		expr, err := selectableSQL(shape, name, def, where.clause)
		if err != nil {
			return nil, fmt.Errorf("measurement %q: %w", def.Code, err)
		}
		selectList = append(selectList, fmt.Sprintf("%s AS col_%d", expr, i))
	}

	// The finding shape folds its predicate into the count subquery, so it must
	// not also appear in the outer WHERE — there is nothing in the outer row to
	// apply a finding predicate to.
	outerWhere := append(append([]string{}, shape.Base...), "("+where.clause+")", "("+subjectWhere.clause+")")
	if shape.Name == "finding" {
		outerWhere = append(append([]string{}, shape.Base...), "("+subjectWhere.clause+")")
	}

	stmt := "SELECT\n\t\t\t" + strings.Join(selectList, ",\n\t\t\t") +
		"\n\t\tFROM " + shape.From +
		"\n\t\tWHERE " + strings.Join(outerWhere, "\n\t\t\tAND ") +
		"\n\t\tORDER BY " + orderBy

	return &measurementPlan{
		def:       def,
		shape:     shape,
		sql:       stmt,
		extraArgs: extraArgs,
		predArgs:  predArgs,
		columns:   columns,
		transform: transform,
		rowFilter: rowFilter,
	}, nil
}

func transformName(def MeasurementTypeDef) string {
	if def.Source.Transform == "" {
		return "identity"
	}
	return def.Source.Transform
}

// compiled is a translated query-language predicate.
type compiled struct {
	clause string
	args   []any
}

// compilePredicate translates one query-language predicate against a target.
// An empty predicate is TRUE, which under RLS is "every row this tenant may
// see" — the shape's own base predicates still apply.
func compilePredicate(src, target, alias, aliasPrefix string, cat *registrycatalog.Catalog, opts query.Options, paramStart int) (compiled, error) {
	if strings.TrimSpace(src) == "" {
		return compiled{clause: "TRUE"}, nil
	}
	o := opts
	o.SQL.OuterAlias = alias
	o.SQL.AliasPrefix = aliasPrefix
	o.SQL.ParamStart = paramStart
	c, err := query.Compile(src, target, cat, o)
	if err != nil {
		return compiled{}, err
	}
	return compiled{clause: c.Where, args: c.Args}, nil
}

// planColumns lists the selectables a row reads, value first, de-duplicated.
func planMeasurementColumns(def MeasurementTypeDef, shape measurementShape) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(name string) error {
		if name == "" || seen[name] {
			return nil
		}
		if _, ok := shape.Selectables[name]; !ok {
			return fmt.Errorf("measurement %q: shape %q has no selectable %q", def.Code, shape.Name, name)
		}
		seen[name] = true
		out = append(out, name)
		return nil
	}
	if err := add(def.Source.Value); err != nil {
		return nil, err
	}
	if def.Source.Value == "" {
		return nil, fmt.Errorf("measurement %q: no value declared", def.Code)
	}
	for _, ev := range expandEvidence(def, shape) {
		if ev.Const != "" {
			continue
		}
		if err := add(ev.From); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// expandEvidence resolves group references into the projections they stand for.
func expandEvidence(def MeasurementTypeDef, shape measurementShape) []EvidenceProjection {
	var out []EvidenceProjection
	for _, ev := range def.Source.Evidence {
		if ev.Group != "" {
			out = append(out, shape.EvidenceGroups[ev.Group]...)
			continue
		}
		out = append(out, ev)
	}
	return out
}

// selectableSQL renders one selectable, building the finding shape's dynamic
// count from the compiled predicate.
func selectableSQL(shape measurementShape, name string, def MeasurementTypeDef, predicate string) (string, error) {
	sel, ok := shape.Selectables[name]
	if !ok {
		return "", fmt.Errorf("shape %q has no selectable %q", shape.Name, name)
	}
	if sel.Dynamic == "" {
		return sel.SQL, nil
	}
	if sel.Dynamic != "finding_count" {
		return "", fmt.Errorf("shape %q: unknown dynamic selectable %q", shape.Name, sel.Dynamic)
	}
	if !measurementFindingVias[def.Source.Via] {
		return "", fmt.Errorf("unknown finding via %q", def.Source.Via)
	}
	return findingCountSQL(def.Source.Via, predicate), nil
}

// ExtractMeasurementsForAsset returns the measurement values for a single asset
// (ADR-0015 per-asset reconcile: a change folds controls over one asset's values
// and reconciles only that asset's findings). The asset filter is pushed into
// the shape's SQL, so a per-asset reconcile reads only that asset's rows.
func (s *MeasurementExtractor) ExtractMeasurementsForAsset(tenantID, assetID uuid.UUID, measurementTypeCode string) ([]MeasurementValue, error) {
	return s.extract(tenantID, assetID, measurementTypeCode)
}

// ExtractMeasurements extracts measurements for a given measurement type and
// tenant (all assets).
func (s *MeasurementExtractor) ExtractMeasurements(tenantID uuid.UUID, measurementTypeCode string) ([]MeasurementValue, error) {
	return s.extract(tenantID, uuid.Nil, measurementTypeCode)
}

// extract runs one registry row. assetID == uuid.Nil means "all assets for the
// tenant"; a concrete assetID scopes extraction to that one asset.
func (s *MeasurementExtractor) extract(tenantID, assetID uuid.UUID, measurementTypeCode string) ([]MeasurementValue, error) {
	if err, bad := s.errs[measurementTypeCode]; bad {
		return nil, err
	}
	plan, ok := s.plans[measurementTypeCode]
	if !ok {
		return nil, fmt.Errorf("unsupported measurement type: %s", measurementTypeCode)
	}

	args := append([]any{tenantID, assetArg(assetID)}, plan.extraArgs...)
	args = append(args, plan.predArgs...)

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets
	// app.tenant_id; the explicit `tenant_id = $1` in every shape's base stays
	// as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), plan.sql, args...)
		if qerr != nil {
			return fmt.Errorf("failed to query measurement %q: %w", plan.def.Code, qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			value, ok, serr := plan.scanRow(rows)
			if serr != nil {
				return serr
			}
			if !ok {
				continue
			}
			measurements = append(measurements, value)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// scanRow reads one row into a MeasurementValue. The bool is false when the row
// yields no measurement — the row filter rejected it, or the value could not be
// interpreted — which leaves its subject NOT ASSESSED rather than scored.
func (p *measurementPlan) scanRow(rows *sql.Rows) (MeasurementValue, bool, error) {
	var subjectID, tenantID uuid.UUID
	var measuredAt time.Time
	dest := []interface{}{&subjectID, &tenantID, &measuredAt}

	values := make([]scannedValue, len(p.columns))
	for i, name := range p.columns {
		sel := p.shape.Selectables[name]
		values[i] = scannedValue{kind: sel.Kind, emptyIsAbsent: sel.EmptyIsAbsent}
		dest = append(dest, values[i].dest())
	}
	if err := rows.Scan(dest...); err != nil {
		return MeasurementValue{}, false, fmt.Errorf("failed to scan measurement %q: %w", p.def.Code, err)
	}

	row := make(map[string]scannedValue, len(p.columns))
	for i, name := range p.columns {
		row[name] = values[i]
	}

	if p.rowFilter != nil && !p.rowFilter(row) {
		return MeasurementValue{}, false, nil
	}

	value, err := p.transform(row[p.def.Source.Value])
	if err != nil {
		// errNoMeasurement and its wrappers are not extraction failures: the
		// row simply says nothing about its subject.
		return MeasurementValue{}, false, nil
	}

	metadata := make(map[string]interface{})
	for _, ev := range expandEvidence(p.def, p.shape) {
		if ev.Const != "" {
			metadata[ev.Key] = ev.Const
			continue
		}
		scanned, ok := row[ev.From]
		if !ok {
			continue
		}
		if ev.Always {
			// The row filter or the predicate has already proven this present,
			// so an empty string is a real value rather than an absence.
			scanned.emptyIsAbsent = false
		}
		v, present := scanned.evidence()
		if !present {
			continue
		}
		metadata[ev.Key] = v
	}

	return MeasurementValue{
		Value:       value,
		SubjectID:   subjectID,
		SubjectType: p.shape.Subject,
		TenantID:    tenantID,
		MeasuredAt:  measuredAt,
		Metadata:    metadata,
	}, true, nil
}

// assetArg maps a uuid.Nil "all assets" sentinel to a SQL NULL and a concrete
// asset id to itself, for the `($2::uuid IS NULL OR <id> = $2)` filter every
// shape carries.
func assetArg(assetID uuid.UUID) interface{} {
	if assetID == uuid.Nil {
		return nil
	}
	return assetID
}
