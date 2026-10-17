package services

// Bulk CSV import and export per object kind (DCIM BUILD_PLAN row 2.7;
// ADR-0006 D8).
//
// One importer, many kinds. A kind is a column spec: which CSV columns exist,
// which are required, and how a reference column ("vrf", "rir", "parent")
// resolves to a row (by name, or by path for a hierarchy). The kinds served by
// the object engine (IPAM and the device catalogue) run through the engine's
// own create/update entry points inside one tenant transaction, so a row is
// validated by exactly the rules a person's API call meets, and a DRY RUN IS
// THE REAL APPLY IN A TRANSACTION THAT IS ROLLED BACK: the plan cannot promise
// what the apply then refuses. Business units, locations, assets and
// interfaces keep their own services (their own transactions and rules), so
// their dry run is a preview (references, enumerations, identity) and their
// own rules surface as row errors at apply (bulk_import_services.go).
//
// Conventions every kind shares:
//   - A row is matched to an existing object by its natural key (a name, a
//     prefix in a VRF, a model under a manufacturer), never by id: a CSV is
//     portable between tenants.
//   - A blank cell leaves an existing value alone; a cell holding "-" clears
//     it. Export writes a blank for "no value", so export → import is a no-op.
//   - Created rows carry source_kind `imported`; every change is recorded in
//     object_changes with source `intake:import`.
//   - A row that refers to a row later in the same file is retried after the
//     rows that create it, so parents need not be listed first.
//
// Racks, rack roles, rack reservations, site groups, regions and the
// asset placement columns arrive with rows 2.1 and 2.3 as one kind spec each
// (see bulkEngineKinds).

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/customfields"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// Limits and the change source of an import.
const (
	BulkMaxRows   = 10000
	bulkChunkRows = 500
	bulkMaxPasses = 4
	bulkSourceRef = "import:csv"
)

// BulkChangeSource is the object_changes source of an imported row. The
// schema's CHECK admits ui | api | system | intake:<x> | sync:<x>; an import is
// intake from a file.
const BulkChangeSource changes.Source = "intake:import"

// Actions a plan row can carry.
const (
	BulkCreate    = "create"
	BulkUpdate    = "update"
	BulkUnchanged = "unchanged"
	BulkError     = "error"
)

// Errors the handler maps onto statuses.
var (
	ErrBulkUnknownKind = errors.New("unknown object kind")
	ErrBulkBadFile     = errors.New("invalid file")
)

// BulkRecord is one CSV row: header → cell.
type BulkRecord map[string]string

// BulkRowResult is one row of a plan (dry run) or of the outcome (apply).
type BulkRowResult struct {
	// Row is the 1-based line number in the file (the header is line 1).
	Row     int      `json:"row"`
	Action  string   `json:"action"`
	Key     string   `json:"key,omitempty"`
	ID      string   `json:"id,omitempty"`
	Changed []string `json:"changed,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	// unresolved marks an error that a later row in the file may cure.
	unresolved bool
}

// BulkSummary counts a plan's rows by action.
type BulkSummary struct {
	Total     int `json:"total"`
	Create    int `json:"create"`
	Update    int `json:"update"`
	Unchanged int `json:"unchanged"`
	Error     int `json:"error"`
}

// BulkPlan is the answer to an import call.
type BulkPlan struct {
	Kind    string          `json:"kind"`
	Mode    string          `json:"mode"`
	Applied bool            `json:"applied"`
	Preview bool            `json:"preview"` // dry run was validation only (kind runs its own transactions)
	Columns []string        `json:"columns"`
	Unknown []string        `json:"unknown_columns,omitempty"`
	Summary BulkSummary     `json:"summary"`
	Rows    []BulkRowResult `json:"rows"`
}

// BulkColumn describes one CSV column.
type BulkColumn struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	// Ref names the kind a reference column resolves against ("rir").
	Ref     string `json:"ref,omitempty"`
	Example string `json:"example"`
	Help    string `json:"help,omitempty"`
}

// BulkKindInfo describes one importable kind for the UI and the template.
type BulkKindInfo struct {
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	Plural     string `json:"plural"`
	Permission string `json:"permission"`
	// ReadPermission gates the kind's export.
	ReadPermission string       `json:"read_permission"`
	Columns        []BulkColumn `json:"columns"`
	// Preview is true when the kind's dry run validates without executing.
	Preview bool `json:"preview"`
}

// BulkExportQuery is the filter of an export: the lens's text search and any
// engine filter parameter (vrf_id, status, …).
type BulkExportQuery struct {
	Q       string
	Filters map[string]string
}

// bulkKind is a registered kind.
type bulkKind struct {
	info   BulkKindInfo
	engine *bulkEngineKind // nil for the service-backed kinds
	custom bulkCustomKind  // nil for engine kinds
}

// bulkCustomKind is a kind backed by its own service.
type bulkCustomKind interface {
	// process handles one record: a dry run only plans; an apply writes.
	process(ctx context.Context, tenant uuid.UUID, rec BulkRecord, row int, dryRun bool, st *bulkCustomState) BulkRowResult
	// export emits every row matching q, in an order a re-import accepts.
	export(ctx context.Context, tenant uuid.UUID, q BulkExportQuery, emit func(BulkRecord) error) error
}

// bulkCustomState is shared across a custom kind's rows in one run: what a
// dry run would have created, so a child can name a parent planned earlier in
// the same file.
type bulkCustomState struct {
	simple *bulkSimpleState
}

// BulkImportService is the importer/exporter over every kind.
type BulkImportService struct {
	db    *sql.DB
	ipam  *IPAMService
	cat   *IPAMService
	kinds map[string]*bulkKind
	order []string
}

// BulkDeps are the services the service-backed kinds write through.
type BulkDeps struct {
	BusinessUnits *BusinessUnitService
	Sites         *SiteService
	Assets        *AssetService
	Catalogue     *CatalogueService
	Interfaces    *InterfaceService
}

// NewBulkImportService returns the importer over db (the app-role pool).
func NewBulkImportService(db *sql.DB, deps BulkDeps) *BulkImportService {
	s := &BulkImportService{db: db, ipam: NewIPAMService(db), cat: newObjectEngine(db, catalogueSpecs()), kinds: map[string]*bulkKind{}}
	for _, ek := range bulkEngineKinds() {
		ek := ek
		eng := s.ipam
		if ek.DeviceCatalogue {
			eng = s.cat
		}
		sp, err := eng.spec(ek.Route)
		if err != nil {
			panic(fmt.Sprintf("bulk import: %v", err))
		}
		ek.spec, ek.eng = sp, eng
		s.register(&bulkKind{info: ek.info(), engine: ek})
	}
	for _, ck := range bulkCustomKinds(s.db, deps) {
		s.register(&bulkKind{info: ck.info, custom: ck.impl})
	}
	// Dependency order: a kind comes after every kind its reference columns name.
	s.order = s.order[:0]
	for _, k := range bulkKindOrder {
		if _, ok := s.kinds[k]; ok {
			s.order = append(s.order, k)
		}
	}
	if len(s.order) != len(s.kinds) {
		panic("bulk import: bulkKindOrder does not list every registered kind")
	}
	return s
}

// bulkKindOrder lists the kinds in dependency order. Racks, rack roles, rack
// reservations, site groups and regions slot in here with rows 2.1/2.3.
var bulkKindOrder = []string{
	"business_unit", "site", "location",
	"manufacturer", "device_role", "platform", "device_type",
	"asset", "interface",
	"rir", "aggregate", "vrf", "vlan_group", "vlan", "prefix", "ip_range", "ip_address",
}

func (s *BulkImportService) register(k *bulkKind) {
	k.info.ReadPermission = bulkReadPermission(k.info.Kind, k.info.Permission)
	s.kinds[k.info.Kind] = k
	s.order = append(s.order, k.info.Kind)
}

// Kinds lists the importable kinds in dependency order (import a kind after
// the kinds its reference columns name).
func (s *BulkImportService) Kinds() []BulkKindInfo {
	out := make([]BulkKindInfo, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.kinds[k].info)
	}
	return out
}

// Kind returns one kind's description.
func (s *BulkImportService) Kind(kind string) (BulkKindInfo, error) {
	k, ok := s.kinds[kind]
	if !ok {
		return BulkKindInfo{}, fmt.Errorf("%w: %q", ErrBulkUnknownKind, kind)
	}
	return k.info, nil
}

// Template returns the kind's header row and one example row.
func (s *BulkImportService) Template(kind string) (header, example []string, err error) {
	info, err := s.Kind(kind)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range info.Columns {
		header = append(header, c.Name)
		example = append(example, c.Example)
	}
	return header, example, nil
}

// ParseBulkCSV reads a CSV body into records. A UTF-8 byte-order mark and
// surrounding space on headers are tolerated; a blank line is skipped.
func ParseBulkCSV(r io.Reader) (header []string, rows []BulkRecord, lines []int, err error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true
	line := 0
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %v", ErrBulkBadFile, err)
		}
		line, _ = cr.FieldPos(0)
		if header == nil {
			for i, h := range rec {
				h = strings.TrimSpace(h)
				if i == 0 {
					h = strings.TrimPrefix(h, "\xef\xbb\xbf")
				}
				header = append(header, strings.ToLower(h))
			}
			continue
		}
		blank := true
		for _, c := range rec {
			if strings.TrimSpace(c) != "" {
				blank = false
			}
		}
		if blank {
			continue
		}
		if len(rows) >= BulkMaxRows {
			return nil, nil, nil, fmt.Errorf("%w: more than %d rows; split the file", ErrBulkBadFile, BulkMaxRows)
		}
		m := BulkRecord{}
		for i, h := range header {
			if i < len(rec) {
				m[h] = strings.TrimSpace(rec[i])
			}
		}
		rows = append(rows, m)
		lines = append(lines, line)
	}
	if header == nil {
		return nil, nil, nil, fmt.Errorf("%w: the file is empty", ErrBulkBadFile)
	}
	return header, rows, lines, nil
}

// Import plans (dry_run) or applies a CSV for one kind.
func (s *BulkImportService) Import(ctx context.Context, tenant uuid.UUID, kind string, body io.Reader, apply bool) (*BulkPlan, error) {
	k, ok := s.kinds[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrBulkUnknownKind, kind)
	}
	header, recs, lines, err := ParseBulkCSV(body)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, c := range k.info.Columns {
		known[c.Name] = true
	}
	var unknown []string
	have := map[string]bool{}
	for _, h := range header {
		if h == "" {
			continue
		}
		have[h] = true
		// A `cf.<name>` column is a custom field (DCIM row 5.1): the engine
		// kinds read it against the tenant's definitions, per row.
		if k.engine != nil && strings.HasPrefix(h, customfields.ColumnPrefix) {
			continue
		}
		if !known[h] {
			unknown = append(unknown, h)
		}
	}
	var missing []string
	for _, c := range k.info.Columns {
		if c.Required && !have[c.Name] {
			missing = append(missing, c.Name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: missing required column(s): %s", ErrBulkBadFile, strings.Join(missing, ", "))
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%w: the file has a header but no rows", ErrBulkBadFile)
	}

	ctx = changes.WithSource(ctx, BulkChangeSource)
	var results []BulkRowResult
	if k.engine != nil {
		results, err = k.engine.run(ctx, s.db, tenant, recs, !apply)
	} else {
		results = runCustom(ctx, k.custom, tenant, recs, !apply)
	}
	if err != nil {
		return nil, err
	}
	plan := &BulkPlan{Kind: kind, Mode: "dry_run", Applied: apply, Preview: !apply && k.info.Preview, Unknown: unknown, Rows: results}
	if apply {
		plan.Mode = "apply"
	}
	for _, c := range k.info.Columns {
		plan.Columns = append(plan.Columns, c.Name)
	}
	for i := range plan.Rows {
		plan.Rows[i].Row = lines[i]
		plan.Summary.Total++
		switch plan.Rows[i].Action {
		case BulkCreate:
			plan.Summary.Create++
		case BulkUpdate:
			plan.Summary.Update++
		case BulkUnchanged:
			plan.Summary.Unchanged++
		default:
			plan.Summary.Error++
		}
	}
	return plan, nil
}

// runCustom drives a service-backed kind: each row on its own, retrying rows
// whose references a later row creates.
func runCustom(ctx context.Context, k bulkCustomKind, tenant uuid.UUID, recs []BulkRecord, dryRun bool) []BulkRowResult {
	st := &bulkCustomState{}
	results := make([]BulkRowResult, len(recs))
	pending := make([]int, len(recs))
	for i := range recs {
		pending[i] = i
	}
	for pass := 0; pass < bulkMaxPasses && len(pending) > 0; pass++ {
		var retry []int
		for _, i := range pending {
			r := k.process(ctx, tenant, recs[i], i+1, dryRun, st)
			if r.unresolved && pass < bulkMaxPasses-1 {
				results[i] = r
				retry = append(retry, i)
				continue
			}
			results[i] = r
		}
		if len(retry) == len(pending) {
			break // no progress; the remaining rows are real errors
		}
		pending = retry
	}
	return results
}

// Export streams every row of kind matching q to emit, as CSV records.
func (s *BulkImportService) Export(ctx context.Context, tenant uuid.UUID, kind string, q BulkExportQuery, emit func(BulkRecord) error) error {
	k, ok := s.kinds[kind]
	if !ok {
		return fmt.Errorf("%w: %q", ErrBulkUnknownKind, kind)
	}
	if k.engine != nil {
		return k.engine.export(ctx, s.db, tenant, q, emit)
	}
	return k.custom.export(ctx, tenant, q, emit)
}

// CustomFieldColumns returns the `cf.<name>` columns a kind's export carries
// for tenant: one per custom field definition that applies to the kind
// (engine kinds; the service-backed kinds carry none yet).
func (s *BulkImportService) CustomFieldColumns(ctx context.Context, tenant uuid.UUID, kind string) ([]string, error) {
	k, ok := s.kinds[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrBulkUnknownKind, kind)
	}
	if k.engine == nil {
		return nil, nil
	}
	if _, ok := k.engine.spec.col("custom_fields"); !ok {
		return nil, nil
	}
	var out []string
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		defs, err := customfields.Load(ctx, tx, k.engine.Kind)
		for _, d := range defs {
			out = append(out, customfields.ColumnPrefix+d.Name)
		}
		return err
	})
	return out, err
}

// BulkColumnNames returns a kind's CSV header in order.
func (s *BulkImportService) BulkColumnNames(kind string) ([]string, error) {
	info, err := s.Kind(kind)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(info.Columns))
	for _, c := range info.Columns {
		out = append(out, c.Name)
	}
	return out, nil
}

// bulkReadPermission is the permission that lets a person read what a kind's
// manage permission lets them write.
func bulkReadPermission(kind, manage string) string {
	switch {
	case kind == "asset":
		return rbac.PermissionAssetsRead
	case strings.HasPrefix(manage, "ipam."):
		return rbac.PermissionIpamRead
	}
	return rbac.PermissionDcimRead
}
