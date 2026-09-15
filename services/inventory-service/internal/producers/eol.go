package producers

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/software"
	swpostgres "github.com/vistasecurity/vistaplatform/shared/software/postgres"
)

// EOLProducer is the `eol` finding producer (ADR-0005 D3, workstream 3.3
// part 2).
//
// It answers one question per subject — "does the end-of-life catalogue know
// this, and has the date passed?" — for three kinds of subject:
//
//	os.name + os.version     → eol/os_end_of_life           on the ASSET
//	hw.vendor + hw.model     → eol/hardware_end_of_support   on the ASSET
//	each software install    → eol/software_end_of_life      on the INSTALL
//
// The software finding's subject is the INSTALL, not the asset, and that is
// forced by the identity index: `findings_open_subject_uniq` allows exactly one
// open row per (producer, kind, subject), so an asset-subject software finding
// would collapse forty end-of-life packages into one row and lose thirty-nine.
// The registry says the same thing — `software_end_of_life.subject_types` is
// `[software_install]` — and `findings.AssetSubjects` walks
// `software_installs.asset_id`, so those findings are still "on" the asset
// everywhere the product asks that question.
//
// # Resolution goes through the shared lookup, not a second matcher
//
// Every subject is resolved by [catalogs.LookupEnricher.ResolveEOL] — the same
// call the Enricher seam's rule default makes. A miss is counted on
// `catalog_lookup_misses` by that same code, which is what keeps the admin
// console's gap list fed by real questions rather than by a separate opinion
// about what counts as unanswerable.
//
// # It also writes the eol.* facts
//
// A finding says "this is a problem"; the fact says "this is the date". The
// asset page shows the second whether or not there is a first — a product whose
// support ends in two years has an `eol.os.date` and no finding — so both are
// written, from the same resolved row, in the same transaction. `source_ref` is
// `catalog:eol:<id>`, so a disputed date leads back to the exact row.
//
// # And it records what each INSTALL resolved to
//
// For software the finding and the fact between them still could not answer
// "is this package supported?" — the fact is keyed by asset and catalogue row,
// not by install, and a missing finding collapsed a catalogue miss, a row with
// no date, a date beyond the warning window and a skipped non-active install
// into one silence. So the resolve phase keeps each install's OUTCOME and the
// write phase records it on `software_install_lifecycle` — `supported`,
// `end_of_life`, `no_date` or `not_in_catalogue`, with the catalogue row it
// came from — in the same transaction as everything else, then sweeps the rows
// of every install this pass did not assess. The Software surfaces read those
// words; nothing downstream re-runs the resolution. The lifecycle analogue of
// `producer_assessments`, one level down.
type EOLProducer struct {
	// repo writes facts and owns the tenant-scoped transaction the findings
	// share, so a run's facts and findings land together or not at all.
	repo *pgidentity.Repository
	// db is the RLS-subject handle for the read phase.
	db     *sql.DB
	writer *producer.Writer
	lookup *catalogs.LookupEnricher
	// store is the lookup's own store, kept so the bounded-gap path can re-wrap
	// it without rebuilding a connection.
	store catalogs.LookupStore

	now func() time.Time
	// maxMisses bounds how many gaps ONE run records. See recordMiss.
	maxMisses int
}

// DefaultMaxMissesPerRun bounds the gap rows one producer run can create.
//
// The gap list exists to be read by a person and sorted by a count, and a
// tenant with fifty thousand distinct unrecognised packages would fill it with
// one run's worth of long-tail npm dependencies — burying the "Cisco IOS-XE
// 17.9, asked about four thousand times" row the generative pass should
// actually work on. Bounded per RUN rather than per tenant so the list still
// grows: the next pass records the next slice, and anything genuinely common
// reappears immediately.
const DefaultMaxMissesPerRun = 500

// NewEOLProducer builds the producer.
//
// lookupDB is the handle the catalogue lookup reads on and should be the
// BYPASSRLS one: `eol_catalogue` and `vulnerability_matches` carry no tenant_id
// and no policy today, so the two handles behave identically — and using the
// bypass one means a future decision to put a policy on a platform catalogue
// does not silently empty every tenant's end-of-life findings.
func NewEOLProducer(appDB *sql.DB, lookupDB *sql.DB) (*EOLProducer, error) {
	w, err := producer.New(findings.ProducerEOL)
	if err != nil {
		return nil, err
	}
	store := catalogs.NewSQLLookupStore(lookupDB)
	return &EOLProducer{
		repo:      pgidentity.New(appDB),
		db:        appDB,
		writer:    w,
		lookup:    catalogs.NewLookupEnricher(store),
		store:     store,
		now:       time.Now,
		maxMisses: DefaultMaxMissesPerRun,
	}, nil
}

// newEOLProducerWithStore builds a producer over an arbitrary lookup store, for
// the unit tests: the matching and ladder decisions are the substance here and
// they are testable against in-memory catalogue rows.
func newEOLProducerWithStore(appDB *sql.DB, store catalogs.LookupStore) (*EOLProducer, error) {
	w, err := producer.New(findings.ProducerEOL)
	if err != nil {
		return nil, err
	}
	return &EOLProducer{
		repo:      pgidentity.New(appDB),
		db:        appDB,
		writer:    w,
		lookup:    catalogs.NewLookupEnricher(store),
		store:     store,
		now:       time.Now,
		maxMisses: DefaultMaxMissesPerRun,
	}, nil
}

// Run is one full pass over one tenant.
type Run struct {
	// Raised is how many findings were upserted (created or re-observed).
	Raised int
	// Resolved is how many the sweep moved to INACTIVE.
	Resolved int
	// Matched is how many subjects resolved to a catalogue row, whether or not
	// the row produced a finding — a row with a future date matches and raises
	// nothing, and that is a different answer from "the catalogue has never
	// heard of this".
	Matched int
	// Misses is how many gaps were recorded; MissesDropped is how many were not
	// because the per-run bound was reached. Reported separately because "the
	// gap list is complete" and "the gap list is the first 500" are different
	// claims and only one of them is true after a big run.
	Misses        int
	MissesDropped int
	// Skipped counts subjects that could not be asked about at all — no product
	// name to look up. Not a gap: a subject with no name is a caller with
	// nothing to ask, and counting it would put noise at the top of the list.
	Skipped int
	// FactsWritten is how many eol.* facts the run stored.
	FactsWritten int
	// FactsExpired counts (asset, kind) pairs this pass declined to judge
	// because the `asset_facts` row it would have judged them from is past its
	// `expires_at`. Reported rather than swallowed, for the same reason
	// NoBaseline is on the drift run: "we could not evaluate" is an answer and
	// a pass that silently produced fewer findings than yesterday's is one
	// nobody can explain.
	FactsExpired int
	// Assessed is how many assets this pass claimed coverage of — the ones it
	// actually asked the catalogue about. Reported beside Skipped because
	// "assessed, nothing found" and "nothing to ask" are the two halves of the
	// three-valued rule and only one of them is reassuring.
	Assessed int
	// Lifecycle is how many software installs had their outcome recorded on
	// software_install_lifecycle; LifecycleSwept is how many stale records
	// (installs this pass did not assess) were removed.
	Lifecycle      int
	LifecycleSwept int
}

// assetSubject is one asset and the facts the producer reads off it.
type assetSubject struct {
	id       uuid.UUID
	label    string
	osName   string
	osVer    string
	hwVendor string
	hwModel  string
	// osExpired / hwExpired are true when the newest fact behind that pair has
	// passed its `asset_facts.expires_at`.
	//
	// An expired fact is NOT ASSESSED, which is neither "end of life" nor
	// "supported". It is the third value, and the whole pass is built to keep
	// it: the producer asks the catalogue nothing, claims no coverage for this
	// asset on this kind, and — this is the half that is easy to miss —
	// WITHHOLDS the subject from the sweep, so a finding raised while the fact
	// was current is left exactly where it is instead of being resolved by a
	// pass that had nothing to say. Resolving it would render "we stopped
	// knowing" as "the problem went away".
	osExpired bool
	hwExpired bool
	installs  []installSubject
}

// sweepHold is the set of subjects, per kind, that a pass DECLINED to judge and
// therefore declines to resolve.
//
// It is the third value made operational. A producer's sweep means "everything
// I did not restate this pass has gone away", which is only true of subjects
// the pass could actually evaluate. A subject whose input is missing is
// evaluable — there is nothing there, so the condition is genuinely absent — but
// a subject whose input EXPIRED is not: the producer has stopped knowing, and a
// sweep that resolved it would publish "fixed" on a judgement nobody made.
type sweepHold map[string][]producer.Subject

// installSubject is one software install and the product behind it.
type installSubject struct {
	installID uuid.UUID
	productID uuid.UUID
	name      string
	vendor    string
	version   string
}

// Run executes the pass for one tenant.
//
// Read, resolve, write — see the package comment for why the phases are
// separate. An error from the first two phases returns WITHOUT sweeping: a run
// that failed part way has not made a full statement about what it sees, and
// sweeping on a partial answer inactivates live findings and re-raises them on
// the next pass.
func (p *EOLProducer) Run(ctx context.Context, tenantID uuid.UUID) (Run, error) {
	var run Run

	subjects, err := p.read(ctx, tenantID)
	if err != nil {
		return Run{}, fmt.Errorf("eol producer: reading tenant %s: %w", tenantID, err)
	}

	planned, assessed, lifecycle, withheld, err := p.resolve(ctx, subjects, &run)
	if err != nil {
		return Run{}, fmt.Errorf("eol producer: resolving tenant %s: %w", tenantID, err)
	}
	run.Assessed = len(assessed)

	if err := p.write(ctx, tenantID, planned, assessed, lifecycle, withheld, &run); err != nil {
		return Run{}, fmt.Errorf("eol producer: writing tenant %s: %w", tenantID, err)
	}
	return run, nil
}

// plannedFinding is one finding the resolve phase decided on, with the fact
// that goes beside it.
type plannedFinding struct {
	finding producer.Finding
	// fact is the eol.* fact for the same catalogue row, or nil when the row
	// carried no date or no citation. Written on the asset even when the
	// finding's subject is a software install: `eol.sw.date` is a statement
	// about the asset's software, and asset_facts is keyed by asset.
	fact    *pgidentity.Fact
	assetID uuid.UUID
}

// assessed is the set of assets this run actually asked the catalogue about
// (workstream 3.2's coverage record).
//
// "Asked about", not "read": an asset with no os.name and no hardware model and
// no software is one this producer has nothing to look up, and claiming to have
// assessed it would turn "the catalogue was never consulted" into "the
// catalogue had nothing against it". A lookup that came back a MISS still
// counts — the question was asked and answered.
type assessedSet map[uuid.UUID]bool

func (a assessedSet) add(id uuid.UUID) {
	if id != uuid.Nil {
		a[id] = true
	}
}

func (a assessedSet) list() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(a))
	for id := range a {
		out = append(out, id)
	}
	return out
}

// eolOutcome is what one lookup concluded.
//
// Kept as its own value rather than inferred afterwards from "was a finding
// planned?", because three of the five produce no finding and two of those
// produce nothing at all — and telling them apart is the whole reason the
// per-install record exists.
type eolOutcome int

const (
	// outcomeSkipped: nothing to ask — no product name. Not a gap, not
	// coverage, and no lifecycle row.
	outcomeSkipped eolOutcome = iota
	// outcomeNotInCatalogue: the catalogue was asked and had nothing. Coverage
	// is claimed (the question was answered), the gap is recorded, and the
	// install's row says `not_in_catalogue`.
	outcomeNotInCatalogue
	// outcomeNoDate: a row matched and publishes no date. Nothing to judge.
	outcomeNoDate
	// outcomeSupported: a row matched and its date is beyond the warning
	// window. The fact is still written; no finding is.
	outcomeSupported
	// outcomeEndOfLife: a row matched and its date is inside the window or
	// past. The finding is planned.
	outcomeEndOfLife
)

// resolution is one lookup's answer: the outcome and, when a row matched, the
// row it came from.
type resolution struct {
	outcome eolOutcome
	row     *catalogs.EOLRow
}

// asked reports whether the catalogue was consulted at all — the coverage rule
// (workstream 3.2): a miss still counts, a subject with no name does not.
func (r resolution) asked() bool { return r.outcome != outcomeSkipped }

// lifecycleFor turns an install's resolution into the row the write phase
// records, or ok=false when there is nothing to record (the install was
// skipped, so no completed pass has assessed it and no row is the honest
// state).
//
// The catalogue row id becomes the citation. It is a uuid in the database and
// a string on [catalogs.EOLRow]; a row whose id does not parse is a corrupt
// catalogue, and the pass fails rather than recording a lifecycle answer it
// cannot cite.
func lifecycleFor(installID uuid.UUID, res resolution) (swpostgres.LifecycleRow, bool, error) {
	switch res.outcome {
	case outcomeSkipped:
		return swpostgres.LifecycleRow{}, false, nil
	case outcomeNotInCatalogue:
		return swpostgres.LifecycleRow{InstallID: installID, Assessment: software.LifecycleNotInCatalogue}, true, nil
	}
	if res.row == nil {
		return swpostgres.LifecycleRow{}, false, fmt.Errorf("producers: eol outcome %d for install %s carries no catalogue row", res.outcome, installID)
	}
	cid, err := uuid.Parse(res.row.ID)
	if err != nil {
		return swpostgres.LifecycleRow{}, false, fmt.Errorf("producers: catalogue row id %q for install %s is not a uuid: %w", res.row.ID, installID, err)
	}
	row := swpostgres.LifecycleRow{InstallID: installID, CatalogueID: &cid}
	switch res.outcome {
	case outcomeNoDate:
		row.Assessment = software.LifecycleNoDate
	case outcomeSupported, outcomeEndOfLife:
		if res.row.EOLDate == nil {
			return swpostgres.LifecycleRow{}, false, fmt.Errorf("producers: eol outcome %d for install %s has no date to record", res.outcome, installID)
		}
		d := res.row.EOLDate.UTC()
		row.EOLDate = &d
		row.Assessment = software.LifecycleSupported
		if res.outcome == outcomeEndOfLife {
			row.Assessment = software.LifecycleEndOfLife
		}
	default:
		return swpostgres.LifecycleRow{}, false, fmt.Errorf("producers: unknown eol outcome %d for install %s", res.outcome, installID)
	}
	return row, true, nil
}

// read loads every asset the producer judges, with its facts and its software.
//
// Archived and soft-deleted assets are excluded: an archived asset is one the
// tenant has decided to stop tracking, and raising fresh end-of-life findings
// against it would put work back in the queue they took it out of.
func (p *EOLProducer) read(ctx context.Context, tenantID uuid.UUID) ([]assetSubject, error) {
	byID := map[uuid.UUID]*assetSubject{}
	var order []uuid.UUID

	err := p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		// One row per asset, with the four facts folded in. DISTINCT ON picks
		// the most recently observed value per key — facts are stored per
		// SOURCE (the unique key is (tenant, asset, key, source_ref)), so an
		// asset seen by both an agent and a CMDB has two os.version rows and
		// something has to choose. Most-recent is the honest default here: full
		// reconciliation precedence (ADR-0002 D4) is per attribute GROUP and
		// belongs to the asset read, not to a lifecycle pass.
		//
		// `expires_at` travels with the value rather than filtering the CTE.
		// Filtering would make an expired fact indistinguishable from one that
		// was never written, and those are different answers: "nobody ever told
		// us what OS this runs" leaves nothing to resolve, while "what we were
		// told has expired" must leave an existing finding standing (see
		// assetSubject.osExpired). The compliance fact shape already honours the
		// column (scope_probe.go); these two producers did not.
		rows, err := tx.QueryContext(ctx, `
			WITH latest AS (
			    SELECT DISTINCT ON (asset_id, key) asset_id, key, value, expires_at
			    FROM asset_facts
			    WHERE tenant_id = $1 AND key = ANY($2::text[])
			    ORDER BY asset_id, key, observed_at DESC
			),
			expired AS (
			    SELECT asset_id, key FROM latest
			    WHERE expires_at IS NOT NULL AND expires_at <= now()
			)
			SELECT a.id,
			       coalesce(nullif(a.display_name, ''), nullif(a.hostname, ''), ''),
			       coalesce((SELECT value #>> '{}' FROM latest WHERE latest.asset_id = a.id AND latest.key = $3), ''),
			       coalesce((SELECT value #>> '{}' FROM latest WHERE latest.asset_id = a.id AND latest.key = $4), ''),
			       coalesce((SELECT value #>> '{}' FROM latest WHERE latest.asset_id = a.id AND latest.key = $5), ''),
			       coalesce((SELECT value #>> '{}' FROM latest WHERE latest.asset_id = a.id AND latest.key = $6), ''),
			       EXISTS (SELECT 1 FROM expired WHERE expired.asset_id = a.id AND expired.key IN ($3, $4)),
			       EXISTS (SELECT 1 FROM expired WHERE expired.asset_id = a.id AND expired.key IN ($5, $6))
			FROM assets a
			WHERE a.tenant_id = $1
			  AND a.deleted_at IS NULL
			  AND a.asset_status <> 'archived'`,
			tenantID,
			textArray(facts.KeyOSName, facts.KeyOSVersion, facts.KeyHWVendor, facts.KeyHWModel),
			facts.KeyOSName, facts.KeyOSVersion, facts.KeyHWVendor, facts.KeyHWModel)
		if err != nil {
			return fmt.Errorf("query assets: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a assetSubject
			if err := rows.Scan(&a.id, &a.label, &a.osName, &a.osVer, &a.hwVendor, &a.hwModel,
				&a.osExpired, &a.hwExpired); err != nil {
				return fmt.Errorf("scan asset: %w", err)
			}
			cp := a
			byID[a.id] = &cp
			order = append(order, a.id)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// Software installs. `status = 'active'` only: a removed install is
		// software that is no longer there, and an end-of-life finding about it
		// would be a finding about the past.
		iRows, err := tx.QueryContext(ctx, `
			SELECT si.id, si.asset_id, sp.id,
			       sp.name, coalesce(sp.vendor, ''), coalesce(sp.version, '')
			FROM software_installs si
			JOIN software_products sp ON sp.tenant_id = si.tenant_id AND sp.id = si.product_id
			WHERE si.tenant_id = $1 AND si.status = 'active'`, tenantID)
		if err != nil {
			return fmt.Errorf("query software installs: %w", err)
		}
		defer func() { _ = iRows.Close() }()
		for iRows.Next() {
			var assetID uuid.UUID
			var in installSubject
			if err := iRows.Scan(&in.installID, &assetID, &in.productID, &in.name, &in.vendor, &in.version); err != nil {
				return fmt.Errorf("scan software install: %w", err)
			}
			if a, ok := byID[assetID]; ok {
				a.installs = append(a.installs, in)
			}
		}
		return iRows.Err()
	})
	if err != nil {
		return nil, err
	}

	out := make([]assetSubject, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// resolve turns each subject into a finding, a fact, both or neither.
//
// No transaction: the catalogue tables carry no tenant_id and this phase makes
// no tenant-scoped query, so holding one open across thousands of lookups would
// pin a connection and a snapshot for no isolation benefit.
func (p *EOLProducer) resolve(ctx context.Context, subjects []assetSubject, run *Run) ([]plannedFinding, assessedSet, []swpostgres.LifecycleRow, sweepHold, error) {
	var planned []plannedFinding
	var lifecycle []swpostgres.LifecycleRow
	assessed := assessedSet{}
	withheld := sweepHold{}

	for _, a := range subjects {
		if a.osExpired {
			run.FactsExpired++
			withheld[findings.KindOSEndOfLife] = append(withheld[findings.KindOSEndOfLife],
				producer.Subject{Type: findings.SubjectAsset, ID: a.id})
		} else {
			osPlan, osRes, err := p.resolveOne(ctx, run, catalogs.KindOS, findings.KindOSEndOfLife,
				a.id, a.label, producer.Subject{Type: findings.SubjectAsset, ID: a.id},
				"", a.osName, a.osVer, nil)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			planned = appendPlan(planned, osPlan)
			if osRes.asked() {
				assessed.add(a.id)
			}
		}

		if a.hwExpired {
			run.FactsExpired++
			withheld[findings.KindHardwareEndOfSupport] = append(withheld[findings.KindHardwareEndOfSupport],
				producer.Subject{Type: findings.SubjectAsset, ID: a.id})
		} else {
			hwPlan, hwRes, err := p.resolveOne(ctx, run, catalogs.KindHardware, findings.KindHardwareEndOfSupport,
				a.id, a.label, producer.Subject{Type: findings.SubjectAsset, ID: a.id},
				a.hwVendor, a.hwModel, "", nil)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			planned = appendPlan(planned, hwPlan)
			if hwRes.asked() {
				assessed.add(a.id)
			}
		}

		for _, in := range a.installs {
			label := in.name
			if in.version != "" {
				label = in.name + " " + in.version
			}
			swPlan, swRes, err := p.resolveOne(ctx, run, catalogs.KindSoftware, findings.KindSoftwareEndOfLife,
				a.id, label, producer.Subject{Type: findings.SubjectSoftwareInstall, ID: in.installID},
				in.vendor, in.name, in.version,
				map[string]any{
					"asset_id":   a.id.String(),
					"product_id": in.productID.String(),
					"install_id": in.installID.String(),
				})
			if err != nil {
				return nil, nil, nil, nil, err
			}
			planned = appendPlan(planned, swPlan)
			if swRes.asked() {
				assessed.add(a.id)
			}
			// The per-install record. Only software subjects have one: an
			// asset's OS and hardware answers are already legible from the
			// asset-keyed facts and findings; an install's were not.
			lr, ok, err := lifecycleFor(in.installID, swRes)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			if ok {
				lifecycle = append(lifecycle, lr)
			}
		}
	}
	return planned, assessed, lifecycle, withheld, nil
}

// resolveOne resolves one (vendor, product, version) and plans what to write.
func (p *EOLProducer) resolveOne(
	ctx context.Context,
	run *Run,
	productKind, findingKind string,
	assetID uuid.UUID,
	label string,
	subject producer.Subject,
	vendor, product, version string,
	extraEvidence map[string]any,
) (*plannedFinding, resolution, error) {
	if strings.TrimSpace(product) == "" {
		run.Skipped++
		return nil, resolution{outcome: outcomeSkipped}, nil
	}

	// The gap bound is applied by swapping in a lookup whose RecordMiss is a
	// no-op once the run's budget is spent — rather than by skipping the
	// LOOKUP, which would also lose the finding.
	suppressed := run.Misses >= p.maxMisses
	lookup := p.lookup
	if suppressed {
		lookup = catalogs.NewLookupEnricher(missSuppressed{p.lookupStore()})
	}

	res, err := lookup.ResolveEOL(ctx, seams.EnrichmentSubject{
		Class:   productKind,
		Vendor:  vendor,
		Model:   product,
		Version: version,
	})
	if err != nil {
		return nil, resolution{}, err
	}
	if res.Row == nil {
		// The counters have to describe what actually happened. The suppressed
		// store returns a nil error from RecordMiss, so `res.MissRecorded` is
		// true whether the gap was written or swallowed — counting that as a
		// miss would make a bounded run report a full gap list.
		switch {
		case suppressed:
			run.MissesDropped++
		case res.MissRecorded:
			run.Misses++
		}
		// A miss is still an ANSWER: the catalogue was asked and had nothing.
		// The asset is assessed by this producer — with a gap recorded — and
		// that is different from an asset it had nothing to ask about.
		return nil, resolution{outcome: outcomeNotInCatalogue}, nil
	}
	run.Matched++

	// A row with no date is a MATCH that says nothing. endoflife.date publishes
	// `true` for "support has ended, date unknown" and `false` for "not
	// announced", and the mirror stores both as NULL rather than inventing a
	// date — so there is no date to judge, and judging the absence would be the
	// "not assessed rendered as failed" mistake pointed the other way.
	row := *res.Row
	if row.EOLDate == nil {
		return nil, resolution{outcome: outcomeNoDate, row: &row}, nil
	}

	plan := &plannedFinding{assetID: assetID}
	if f, ok := catalogs.EOLFact(row); ok {
		plan.fact = &pgidentity.Fact{
			Key:   f.Key,
			Value: f.Value,
			// imported, not inferred: the date was read out of a catalogue row
			// a mirror imported. Calling it inferred would understate its
			// provenance as badly as the reverse overstates it.
			SourceKind: identity.SourceImported,
			SourceRef:  f.SourceRef,
			ObservedAt: p.now().UTC(),
		}
		run.FactsWritten++
	}

	days := daysUntil(p.now(), *row.EOLDate)
	rung, report, err := rungFor(findingKind, days)
	if err != nil {
		return nil, resolution{}, err
	}
	if !report {
		// Supported, and further out than the warning window. The fact still
		// travels: the asset page shows the date whether or not it is a problem
		// yet, which is how somebody plans an upgrade before it becomes one.
		return plan, resolution{outcome: outcomeSupported, row: &row}, nil
	}

	detail := eolDetail(days)
	evidence := map[string]any{
		// The citation. Both halves: the row id so a disputed date leads to the
		// exact thing that said it, and the URL so a person can check it
		// without database access.
		"catalogue_id":         row.ID,
		"catalogue_source_url": row.SourceURL,
		"catalogue_product":    row.Product,
		"catalogue_cycle":      row.Cycle,
		"product_kind":         row.ProductKind,
		"eol_date":             row.EOLDate.UTC().Format("2006-01-02"),
		"days_remaining":       days,
		"observed_product":     product,
		"observed_version":     version,
	}
	if row.Vendor != "" {
		evidence["catalogue_vendor"] = row.Vendor
	}
	if row.ExtendedSupportDate != nil {
		evidence["extended_support_date"] = row.ExtendedSupportDate.UTC().Format("2006-01-02")
	}
	for k, v := range extraEvidence {
		evidence[k] = v
	}

	plan.finding = producer.Finding{
		Kind:         findingKind,
		Subject:      subject,
		SubjectLabel: label,
		Severity:     rung.Severity,
		Score:        rung.Score,
		Summary:      eolSummary(findingKind, label, detail),
		Evidence:     evidence,
		// imported: the judgement is ours, but the DATE this finding turns on
		// was imported from a catalogue. `measured` would claim we observed the
		// end of support ourselves.
		SourceKind: producer.SourceImported,
	}
	return plan, resolution{outcome: outcomeEndOfLife, row: &row}, nil
}

// write commits the run: every finding, every fact, then the sweep — one
// transaction, because a sweep that lands without its upserts inactivates live
// findings.
func (p *EOLProducer) write(ctx context.Context, tenantID uuid.UUID, planned []plannedFinding, assessed assessedSet, lifecycle []swpostgres.LifecycleRow, withheld sweepHold, run *Run) error {
	seen := map[string][]producer.Subject{}
	for _, kind := range eolKinds {
		// Seeded with the subjects this pass DECLINED to judge, before a single
		// upsert. `seen` is what the sweep spares, and a subject whose fact has
		// expired is one the producer can say nothing about — not one it can
		// say the condition went away about. See assetSubject.osExpired.
		seen[kind] = append([]producer.Subject(nil), withheld[kind]...)
	}

	return p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		factsByAsset := map[uuid.UUID][]pgidentity.Fact{}
		for _, plan := range planned {
			if plan.fact != nil {
				factsByAsset[plan.assetID] = append(factsByAsset[plan.assetID], *plan.fact)
			}
			if plan.finding.Kind == "" {
				continue
			}
			if _, err := p.writer.Upsert(ctx, tx, tenantID, plan.finding); err != nil {
				return err
			}
			run.Raised++
			seen[plan.finding.Kind] = append(seen[plan.finding.Kind], plan.finding.Subject)
		}

		for assetID, fs := range factsByAsset {
			if err := r.UpsertFacts(ctx,
				identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()},
				facts.ProducerEnricher, fs); err != nil {
				return fmt.Errorf("writing eol facts for asset %s: %w", assetID, err)
			}
		}

		// What each install resolved to — the per-install record the Software
		// surfaces read. In the SAME transaction as the findings: a row saying
		// "supported" that outlived a rolled-back pass would be exactly the
		// unearned credit the record exists to prevent. Restate every install
		// this pass assessed, then sweep the rows of every install it did not,
		// so a removed install's row goes and "no row" keeps meaning "no
		// completed pass has assessed this install since it was last active".
		n, err := swpostgres.UpsertLifecycle(ctx, tx, tenantID, lifecycle, p.now().UTC())
		if err != nil {
			return err
		}
		run.Lifecycle = n
		keep := make([]uuid.UUID, 0, len(lifecycle))
		for _, lr := range lifecycle {
			keep = append(keep, lr.InstallID)
		}
		swept, err := swpostgres.SweepLifecycle(ctx, tx, tenantID, keep)
		if err != nil {
			return err
		}
		run.LifecycleSwept = swept

		// The coverage claim, in the SAME transaction as the upserts and the
		// sweep: a pass that dies half way rolls it back and the asset keeps the
		// coverage its last COMPLETED pass gave it (ADR-0005 D4).
		if _, err := p.writer.MarkAssessed(ctx, tx, tenantID, assessed.list()); err != nil {
			return err
		}

		// The sweep, per kind. Everything this producer no longer asserts goes
		// INACTIVE — which is how a finding disappears when the catalogue row
		// changes, when the install is removed, or when somebody upgrades.
		for _, kind := range eolKinds {
			n, err := p.writer.Sweep(ctx, tx, tenantID, kind, seen[kind])
			if err != nil {
				return err
			}
			run.Resolved += n
		}
		return nil
	})
}

// eolKinds is every kind this producer emits, which is also every kind it
// sweeps. Derived from the registry rather than listed, so a kind added to the
// `eol` producer without a sweep here is impossible.
var eolKinds = func() []string {
	var out []string
	for _, k := range findings.All {
		if k.Producer == findings.ProducerEOL {
			out = append(out, k.Key)
		}
	}
	return out
}()

// eolSummary renders the registry's title_template.
func eolSummary(kind, subject, detail string) string {
	k, ok := findings.Get(findings.ProducerEOL, kind)
	if !ok {
		return subject + " is end of life (" + detail + ")"
	}
	s := strings.ReplaceAll(k.TitleTemplate, "{subject}", subject)
	return strings.ReplaceAll(s, "{detail}", detail)
}

// daysUntil is whole days from now to date, in UTC, counting calendar days
// rather than 24-hour periods: an end-of-life date is a DATE, and a product
// does not become unsupported eleven hours early because the run started in the
// afternoon.
func daysUntil(now, date time.Time) int {
	n := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	d := time.Date(date.UTC().Year(), date.UTC().Month(), date.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return int(d.Sub(n).Hours() / 24)
}

func appendPlan(planned []plannedFinding, p *plannedFinding) []plannedFinding {
	if p == nil {
		return planned
	}
	return append(planned, *p)
}

// missSuppressed wraps a lookup store so RecordMiss does nothing. Used once a
// run has spent its gap budget: the LOOKUP still happens (so the finding is
// still raised), only the bookkeeping stops.
type missSuppressed struct{ catalogs.LookupStore }

func (missSuppressed) RecordMiss(context.Context, catalogs.MissSubject) error { return nil }

// lookupStore is the store the enricher was built over.
func (p *EOLProducer) lookupStore() catalogs.LookupStore { return p.store }

func textArray(vals ...string) any { return pq.Array(vals) }
