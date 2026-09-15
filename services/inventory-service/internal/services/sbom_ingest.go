package services

// SBOM ingestion, workstream 2.6b: an uploaded bill of materials becomes
// `software_products` (the tenant catalogue) and `software_installs` (what is
// on this asset).
//
// 2.6a shipped the parser — shared/sbom turns CycloneDX and SPDX JSON into
// values, and shared/software is the shape of a row. Nothing there touches a
// database.
//
// The SQL that writes those two tables is shared/software/postgres, and has
// been since workstream 2.11b gave the tables a SECOND producer (the host
// agent's package enumeration, which runs in device-interrogation-service and
// so could not call a method on this type). The rules it owns — the
// ABSENT-MEANS-NULL identity contract, the columns ON CONFLICT may not touch,
// the refusal to downgrade a measured install — are stated there.
//
// What stays HERE is what is specific to a bill of materials: the `imported`
// provenance an uploaded document carries, the upload id as the source ref, the
// two formats' disagreement about whether the subject is also a component, and
// the counts a user reconciles against their own build output.
// TestIntegration_SBOM_PurlLessProductsAreDistinctRows still drives that
// contract from this end, against a real Postgres.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/sbom"
	"github.com/vistasecurity/vistaplatform/shared/software"
	swpostgres "github.com/vistasecurity/vistaplatform/shared/software/postgres"
)

// ErrSBOMAssetNotFound is returned when the upload names an asset this tenant
// does not have. It is separated from a parse failure so the handler can answer
// 404 rather than 400: the document may be perfect and the id simply wrong.
var ErrSBOMAssetNotFound = errors.New("asset not found")

// SBOMIngestService writes a parsed bill of materials into the software
// inventory.
//
// It holds the AssetService rather than duplicating its pieces because two of
// the things an upload does are the AssetService's: resolving a subject into an
// asset through the identification engine, and appending the asset-history row
// that says the upload happened.
type SBOMIngestService struct {
	db     *database.DB
	assets *AssetService

	// onIngested is called after a successful upload, with the tenant whose
	// software just changed. It is how the `vulnerability` and `eol` producers
	// learn that an inventory moved under a static catalogue, without waiting
	// for the nightly pass (workstream 3.4 part 2).
	//
	// An in-process callback rather than an event: inventory-service both
	// writes the software and runs the producers, so a NATS round trip would
	// leave the service publishing to itself, and the subscriber would be a
	// second thing to keep running. Optional and nil-safe — the producers are a
	// consumer of this data, not a condition of storing it.
	//
	// It MUST NOT block or fail the upload. The upload is the user's work; the
	// findings are ours, and coupling them would mean a catalogue problem
	// rejected the data. FindingProducerJob.Trigger returns immediately.
	onIngested func(ctx context.Context, tenantID uuid.UUID)
}

func NewSBOMIngestService(db *database.DB, assets *AssetService) *SBOMIngestService {
	return &SBOMIngestService{db: db, assets: assets}
}

// OnIngested installs the post-upload hook. See the field comment.
func (s *SBOMIngestService) OnIngested(fn func(ctx context.Context, tenantID uuid.UUID)) {
	s.onIngested = fn
}

// SBOMIngestResult is what one upload did, in numbers a person can check
// against their own document.
//
// Every count is reported separately rather than rolled into a single "ingested
// N": "480 components, 412 products, 12 excluded, 3 dependency edges ignored"
// is a sentence a user can reconcile with their build output, and "412
// ingested" is not. The same reason the parser returns warnings instead of
// silently doing its best.
type SBOMIngestResult struct {
	// UploadID identifies this upload. It is written to every
	// `software_installs.source_ref` the upload touches, which is what makes
	// the absent-install sweep below possible without a second table.
	UploadID string `json:"upload_id"`
	Filename string `json:"filename,omitempty"`

	Format      string `json:"format"`
	SpecVersion string `json:"spec_version"`
	// DocumentSerial is the document's own identity — CycloneDX
	// `serialNumber`, SPDX `documentNamespace`. Reported so a support question
	// ("which document produced this row?") has an answer. It is NOT used for
	// deduplication: CycloneDX mints a fresh serialNumber on every export, so
	// two builds of one artefact carry two serials.
	DocumentSerial string `json:"document_serial,omitempty"`

	AssetID      string `json:"asset_id"`
	AssetName    string `json:"asset_name,omitempty"`
	AssetCreated bool   `json:"asset_created"`
	AssetStatus  string `json:"asset_status"`

	ComponentCount  int `json:"component_count"`
	ProductsCreated int `json:"products_created"`
	ProductsMatched int `json:"products_matched"`
	InstallsCreated int `json:"installs_created"`
	InstallsUpdated int `json:"installs_updated"`
	InstallsRemoved int `json:"installs_removed"`
	// ComponentsExcluded counts components the document marked
	// `scope: excluded`, which says they are NOT in the artefact. Ingesting one
	// as an install would be a false positive in an inventory whose whole job
	// is to be believed.
	ComponentsExcluded int `json:"components_excluded"`
	// DependencyEdgesIgnored counts the `dependsOn` / `DEPENDS_ON` edges the
	// document carried and this ingest did NOT store. See the note on
	// Ingest: component-to-component edges are not asset relationships and the
	// data model has no home for them. Counted rather than silent, because a
	// user who exported a dependency graph deserves to be told it was not kept.
	DependencyEdgesIgnored int `json:"dependency_edges_ignored"`

	// Warnings are the parser's, verbatim, plus any this writer added. A
	// document that parsed with warnings is a successful parse.
	Warnings []string `json:"warnings"`
}

// sbomSourceRef is the `source_ref` an upload writes, and the producer prefix
// `identity.Source.Producer()` reads. `sbom:<upload uuid>`.
func sbomSourceRef(uploadID uuid.UUID) string { return "sbom:" + uploadID.String() }

// sbomFactSourceRef is the `asset_facts.source_ref` the package-count fact is
// written under.
//
// It is the CONSTANT "sbom", not the upload id, and the difference matters.
// `asset_facts` is unique on (tenant, asset, key, source_ref) — per source,
// deliberately, so two sources may disagree — so keying the fact on the upload
// id would leave one stale row per upload, each claiming a count that was true
// once. One row per (asset, "sbom") is the honest shape: it is the SBOM
// source's current answer for this asset, replaced each time that source
// speaks.
const sbomFactSourceRef = "sbom"

// Ingest parses one document and writes it against an asset.
//
// `assetID` may be uuid.Nil, in which case the document's SUBJECT is resolved
// into an application asset through the identification engine — see
// resolveSubjectAsset — and the components are written against that.
//
// # What is NOT written: the dependency graph
//
// A document's `dependencies` are component→component edges: "this jar is on
// the classpath of that war". `asset_relationships` is an ASSET→ASSET table
// (DATA_MODEL §3), and a component is not an asset — the components of one
// upload are rows in `software_installs`, which has no self-reference and no
// edge table beside it. Writing these edges anywhere would mean inventing a
// table on the way past, and writing them into `asset_relationships` would mean
// asserting relationships between assets that do not exist. So they are
// counted, reported, and dropped. When the data model grows a home for them
// (ADR-0005 D6's xBOM work, BUILD_PLAN 3.7) this is where they get picked up.
func (s *SBOMIngestService) Ingest(
	ctx context.Context,
	tenantID, assetID, actorUserID uuid.UUID,
	filename string,
	r io.Reader,
) (*SBOMIngestResult, error) {
	doc, err := sbom.Parse(r)
	if err != nil {
		return nil, err
	}

	uploadID := uuid.New()
	res := &SBOMIngestResult{
		UploadID:               uploadID.String(),
		Filename:               strings.TrimSpace(filename),
		Format:                 string(doc.Format),
		SpecVersion:            doc.SpecVersion,
		DocumentSerial:         doc.Serial,
		ComponentCount:         len(doc.Components),
		DependencyEdgesIgnored: len(doc.Dependencies),
		Warnings:               append([]string{}, doc.Warnings...),
	}

	if assetID == uuid.Nil {
		asset, created, aerr := s.resolveSubjectAsset(tenantID, doc, uploadID)
		if aerr != nil {
			return nil, aerr
		}
		assetID = asset.ID
		res.AssetCreated = created
		res.AssetStatus = asset.AssetStatus
		if asset.DisplayName != nil {
			res.AssetName = *asset.DisplayName
		}
	} else {
		name, status, ok, aerr := s.assetNameAndStatus(ctx, tenantID, assetID)
		if aerr != nil {
			return nil, aerr
		}
		if !ok {
			return nil, ErrSBOMAssetNotFound
		}
		res.AssetName, res.AssetStatus = name, status
	}
	res.AssetID = assetID.String()

	rows := s.plan(doc, res)

	// One transaction for the whole document. A half-written SBOM is the
	// failure shape this codebase keeps paying for: the asset would show a
	// software list that looks complete, with no way to tell which half is
	// missing. The parser refuses an over-cap document rather than truncating
	// it for the same reason.
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return s.write(ctx, tx, tenantID, assetID, actorUserID, uploadID, rows, res)
	})
	if err != nil {
		return nil, err
	}

	// The software this tenant runs has changed, so the judgements about it are
	// stale. Fire-and-forget, after the commit: before it, the producers would
	// read the pre-upload inventory and write findings about software that is
	// no longer the current answer.
	s.notifyIngested(ctx, tenantID)
	return res, nil
}

// notifyIngested runs the post-upload hook, and cannot fail the upload.
//
// The recover is the difference between the comment on `onIngested` and an
// enforced rule. The hook runs AFTER the commit, so a panic inside it would
// unwind through the handler and return 500 for an upload whose data is
// already stored — the user re-uploads, and the second attempt sweeps and
// re-writes everything the first one landed. The guarantee "the upload is the
// user's work and the findings are ours" has to be the code's, not a sentence
// above it.
func (s *SBOMIngestService) notifyIngested(ctx context.Context, tenantID uuid.UUID) {
	if s.onIngested == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SBOM ingest: the post-upload finding-producer hook panicked and was contained: %v", r)
		}
	}()
	s.onIngested(ctx, tenantID)
}

// plannedInstall is one product the document says is present, deduplicated by
// catalogue identity.
type plannedInstall struct {
	product software.Product
	// identity is the value the `software_products` unique index keys on,
	// computed from the product AFTER the CPE fold below so the Go side and the
	// SQL side cannot disagree.
	identity string
}

// plan turns the parsed document into the set of catalogue rows to write, and
// fills in the counts that do not need the database.
//
// Three things happen here rather than in the write loop, because all three are
// decisions rather than mechanics:
//
//  1. `scope: excluded` components are dropped. CycloneDX `excluded` means the
//     component is NOT in the artefact; recording it as an install would be a
//     false positive.
//  2. The SUBJECT is added as a product too, unless it is already one of the
//     components. The two formats disagree about this and a writer has to
//     know: in CycloneDX the subject sits OUTSIDE the component list, in SPDX
//     it IS one of the packages, so writing both without checking creates the
//     subject's product twice. The subject is included rather than skipped
//     because an application asset created FROM a document, whose Software tab
//     then showed nothing, would read as "no software found" — the three-valued
//     dishonesty the fact registry and the risk rollup both go out of their way
//     to avoid.
//  3. Products are deduplicated by identity. One document listing the same purl
//     twice is one catalogue row and one install, not two round trips and a
//     doubled count.
func (s *SBOMIngestService) plan(doc *sbom.Document, res *SBOMIngestResult) []plannedInstall {
	seenRef := make(map[string]bool, len(doc.Components))
	seenIdentity := make(map[string]bool, len(doc.Components)+1)
	out := make([]plannedInstall, 0, len(doc.Components)+1)

	add := func(p software.Product) {
		folded := swpostgres.FoldForWrite(p)
		if !folded.Identifiable() {
			return
		}
		id := folded.Identity()
		if seenIdentity[id] {
			return
		}
		seenIdentity[id] = true
		out = append(out, plannedInstall{product: folded, identity: id})
	}

	for _, c := range doc.Components {
		if c.BOMRef != "" {
			seenRef[c.BOMRef] = true
		}
		if strings.EqualFold(strings.TrimSpace(c.Scope), "excluded") {
			res.ComponentsExcluded++
			continue
		}
		add(c.Product)
	}

	if doc.Subject != nil {
		// A subject whose bom-ref is one of the components is ALREADY in the
		// list (the SPDX shape). One whose ref is absent or unknown is not (the
		// CycloneDX shape). `add` deduplicates by identity as well, so a
		// CycloneDX document that happens to repeat its subject as a component
		// under a different bom-ref still yields one row.
		if doc.SubjectRef == "" || !seenRef[doc.SubjectRef] {
			add(*doc.Subject)
		}
	}
	return out
}

// write performs the whole document's writes on one tenant-scoped transaction.
func (s *SBOMIngestService) write(
	ctx context.Context,
	tx *sqlx.Tx,
	tenantID, assetID, actorUserID, uploadID uuid.UUID,
	rows []plannedInstall,
	res *SBOMIngestResult,
) error {
	sourceRef := sbomSourceRef(uploadID)

	// The catalogue and install writes are shared/software/postgres', not this
	// file's, because the host agent (workstream 2.11b) writes the same two
	// tables from another service and every rule in them — the NULL-not-''
	// identity contract, the columns ON CONFLICT may not touch, the refusal to
	// downgrade a measured row — was learned here and must not be learned
	// twice. What stays here is what is SBOM-specific: `imported` provenance,
	// the upload id as the source ref, and the counts a user reconciles against
	// their own document.
	for _, row := range rows {
		productID, productCreated, err := swpostgres.UpsertProduct(ctx, tx, tenantID, row.product, software.SourceImported)
		if err != nil {
			return fmt.Errorf("upserting product %q: %w", row.identity, err)
		}
		if productCreated {
			res.ProductsCreated++
		} else {
			res.ProductsMatched++
		}

		// No install path: an SBOM component has none.
		installCreated, err := swpostgres.UpsertInstall(ctx, tx, tenantID, assetID, productID,
			"", software.SourceImported, sourceRef)
		if err != nil {
			return fmt.Errorf("upserting install of %q: %w", row.identity, err)
		}
		if installCreated {
			res.InstallsCreated++
		} else {
			res.InstallsUpdated++
		}
	}

	removed, err := swpostgres.MarkAbsentRemoved(ctx, tx, tenantID, assetID, software.SourceImported, sourceRef)
	if err != nil {
		return fmt.Errorf("marking absent installs removed: %w", err)
	}
	res.InstallsRemoved = removed

	active, err := s.refreshPackageCountFact(ctx, tx, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("refreshing %s: %w", facts.KeySWPackageCount, err)
	}

	s.assets.recordAssetHistoryBy(tx, tenantID, assetID, actorUserID,
		identity.ActionSBOMImported,
		identity.Source{Kind: identity.SourceImported, Ref: sourceRef},
		map[string]any{
			"filename":                 res.Filename,
			"format":                   res.Format,
			"spec_version":             res.SpecVersion,
			"document_serial":          res.DocumentSerial,
			"component_count":          res.ComponentCount,
			"products_created":         res.ProductsCreated,
			"products_matched":         res.ProductsMatched,
			"installs_created":         res.InstallsCreated,
			"installs_updated":         res.InstallsUpdated,
			"installs_removed":         res.InstallsRemoved,
			"components_excluded":      res.ComponentsExcluded,
			"dependency_edges_ignored": res.DependencyEdgesIgnored,
			"active_installs":          active,
			// The parser's warnings are part of the record, not just of the
			// response: six months later "why does this asset list 412 of the
			// 480 things in my SBOM" is answered from the timeline or not at
			// all.
			"warnings": res.Warnings,
		})
	return nil
}

// refreshPackageCountFact rewrites `sw.package_count` for this asset from the
// SBOM source, and returns the number it wrote.
//
// The value is the count of ACTIVE IMPORTED installs, not the document's
// component count. Those differ for good reasons — excluded components, a
// subject that was already a component, two components sharing one purl — and
// the fact's job (per standards/fact-keys.yaml) is to distinguish "no software
// found" from "software was never enumerated". The number that answers that is
// the number of rows an inventory query would return, so it is the number
// stored.
//
// Scoped to `imported` because the fact is written under source_ref "sbom":
// counting a future host agent's measured rows here would have the SBOM source
// claim a coverage it did not provide.
func (s *SBOMIngestService) refreshPackageCountFact(
	ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID,
) (int, error) {
	count, err := swpostgres.ActiveInstallCount(ctx, tx, tenantID, assetID, software.SourceImported)
	if err != nil {
		return 0, err
	}

	// The key column has no CHECK constraint and the value column is jsonb, so
	// this validator is the only thing between a producer and a fact nobody can
	// read back. Checked even though the value is an int we just counted: the
	// call is what fails loudly if the key is ever renamed or retyped.
	if err := facts.ValidateValue(facts.KeySWPackageCount, count); err != nil {
		return 0, err
	}
	value, err := json.Marshal(count)
	if err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, now())
		ON CONFLICT (tenant_id, asset_id, key, source_ref)
		DO UPDATE SET value = excluded.value,
		              source_kind = excluded.source_kind,
		              observed_at = excluded.observed_at,
		              updated_at = now()`,
		tenantID, assetID, facts.KeySWPackageCount, string(value),
		software.SourceImported, sbomFactSourceRef); err != nil {
		return 0, err
	}
	return count, nil
}

// resolveSubjectAsset turns the document's subject into an asset, matching an
// existing one where the same subject has been uploaded before.
//
// It goes through AssetService.createAssetResolved, which means it goes through
// the identification engine — the same path manual create, spreadsheet import
// and the CMDB pull take. That is what makes a second upload of the same
// document MATCH rather than mint a second asset.
//
// # Provenance: declared, and still pending approval
//
// The source kind is `declared`: a bill of materials is a statement, not a
// measurement — nobody probed anything. But declared is not the same as
// approved. An asset a person creates in the UI is approved because a human
// with an account decided, in front of the inventory, that it belongs there; an
// API upload is a file arriving at an endpoint, and the person who chose it may
// not be the person who owns the inventory. So the asset lands in
// `pending_approval` and shows up in Discovery → Approvals labelled "declared
// from SBOM upload", where someone admits it deliberately.
//
// Mechanically that is the engine's own default (identity.StatusPendingApproval
// in the repository's CreateAsset) and this path passes an empty status rather
// than overriding it, so there is no second opinion to keep in sync.
func (s *SBOMIngestService) resolveSubjectAsset(
	tenantID uuid.UUID, doc *sbom.Document, uploadID uuid.UUID,
) (*models.Asset, bool, error) {
	if doc.Subject == nil {
		return nil, false, fmt.Errorf("%w: this document does not say what it is about "+
			"(no CycloneDX `metadata.component`, no SPDX DESCRIBES relationship), so there is nothing to create an "+
			"asset from. Upload it against an existing asset instead", ErrSBOMSubjectNotAnAsset)
	}
	classKey, err := sbomSubjectClass(doc.SubjectType)
	if err != nil {
		return nil, false, err
	}
	identifier, err := sbomSubjectIdentity(*doc.Subject)
	if err != nil {
		return nil, false, err
	}

	name := sbomSubjectDisplayName(*doc.Subject)
	scope := classKey
	subject, _ := doc.Subject.Normalize()
	input := models.AssetInput{
		ClassKey:    classKey,
		DisplayName: &name,
		Identifiers: []models.AssetIdentifierInput{{
			Kind: string(identity.KindName), Value: identifier, Scope: &scope,
		}},
		// The class registry gives `application` product / version / vendor
		// attributes, which is exactly what a subject carries. Recording them
		// means the asset page shows what it is without the reader having to
		// open the Software tab and infer it.
		Attributes: subjectAttributes(subject),
	}

	asset, outcome, err := s.assets.createAssetResolved(tenantID, input,
		identity.Source{Kind: identity.SourceDeclared, Ref: sbomSourceRef(uploadID)},
		"" /* no status override: the engine's pending_approval stands */)
	if err != nil {
		return nil, false, err
	}
	return asset, outcome == identity.OutcomeCreated, nil
}

// subjectAttributes projects the subject onto the `application` class's
// attribute schema. An explicit allowlist, not the whole product: the schema
// has three properties and `additionalProperties: false`, so anything else
// would be rejected at validation — and projecting deliberately is the habit
// this codebase keeps anyway.
func subjectAttributes(p software.Product) map[string]interface{} {
	out := map[string]interface{}{}
	if p.Name != "" {
		out["product"] = p.Name
	}
	if p.Version != "" {
		out["version"] = p.Version
	}
	if p.Vendor != "" {
		out["vendor"] = p.Vendor
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// assetNameAndStatus reads the display name and approval status of the asset an
// upload was aimed at, and reports whether it exists at all.
//
// Under RLS an asset in another tenant simply is not there, so "not found" and
// "not yours" are the same answer — which is the answer we want to give.
func (s *SBOMIngestService) assetNameAndStatus(
	ctx context.Context, tenantID, assetID uuid.UUID,
) (name, status string, ok bool, err error) {
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var display sql.NullString
		e := tx.QueryRowContext(ctx, `
			SELECT display_name, asset_status FROM assets
			 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
			tenantID, assetID).Scan(&display, &status)
		switch {
		case errors.Is(e, sql.ErrNoRows):
			return nil
		case e != nil:
			return e
		}
		name, ok = display.String, true
		return nil
	})
	return name, status, ok, err
}

// likePattern turns a user's search term into a LIKE pattern with the
// metacharacters neutralised.
//
// The term is already a bound parameter, so this is not about injection — it is
// about the search meaning what the user typed. `%` and `_` are LIKE wildcards,
// and both occur in the very strings this search exists to find: a purl
// percent-encodes the characters a namespace may not carry literally, so the
// canonical form of the npm package `@angular/core` is
// `pkg:npm/%40angular/core`, and searching for it unescaped asks for "anything,
// then 40angular" — which matches products that have nothing to do with it.
// `_` is as common in package names as `-` is.
//
// Backslash is Postgres's default LIKE escape character, so escaping with it
// needs no ESCAPE clause. Same rule, same spelling, as shared/query/sql's
// escapeLike and admin-service's likeEscape.
func likePattern(term string) string {
	var b strings.Builder
	b.WriteByte('%')
	for _, r := range strings.ToLower(term) {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('%')
	return b.String()
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// Lifecycle and vulnerability states a software row can be in.
//
// Many-valued on BOTH axes, and the last value on each is the one that keeps
// them honest: "no finding" is not "clean". A cell that renders 0
// vulnerabilities for a package nothing could match is the same collapse a
// risk score of 0 with an empty risk_assessed_by would be.
//
// The end-of-life axis reads TWO things the `eol` producer wrote in one
// transaction: its open `software_end_of_life` finding, and its per-install
// record on `software_install_lifecycle` of what the lifecycle catalogue
// resolved (`shared/software.Lifecycle*`). Neither is re-derived here.
const (
	// SoftwareEOLEndOfLife: an OPEN `eol/software_end_of_life` finding names
	// this install. The finding's own ladder decides how bad — within 90 days,
	// past, or past by more than a year.
	SoftwareEOLEndOfLife = "end_of_life"
	// SoftwareEOLSupported: the producer's record says the catalogue resolved
	// this version to a cycle whose end-of-life date is beyond the warning
	// window. The one reassuring answer, and it is EARNED — the catalogue was
	// asked and answered with a date. `eol_date` carries it.
	SoftwareEOLSupported = "supported"
	// SoftwareEOLNoDate: the catalogue has the version and publishes no date
	// (endoflife.date mirrors both "support ended, date unknown" and "not
	// announced" as NULL). Neither "supported" nor "end of life" can be
	// claimed, and the fix is with the vendor or the catalogue, not the gap
	// list.
	SoftwareEOLNoDate = "no_date"
	// SoftwareEOLNotInCatalogue: the catalogue has no entry for the product.
	// A recorded gap, which is a different problem from `no_date` with a
	// different fix.
	SoftwareEOLNotInCatalogue = "not_in_catalogue"
	// SoftwareEOLNotAssessed: no open finding AND no lifecycle record. That
	// is NOT "supported", and the UI must not render it as one. What it means
	// now is narrower than it used to be: no completed pass has recorded an
	// answer for this install — the producer has not run since the install
	// was seen, the install is not `active` and the producer skipped it (the
	// sweep removes its record), or the producer raised a finding a person has
	// since closed (the record says `end_of_life`, the finding is not open,
	// and crediting the package as supported would be wrong).
	SoftwareEOLNotAssessed = "not_assessed"

	// SoftwareVulnVulnerable: an OPEN `vulnerability/known_vulnerability`
	// finding names this install, carrying every CVE that matched.
	SoftwareVulnVulnerable = "vulnerable"
	// SoftwareVulnNoneKnown: the install carries a CPE or a PURL — so the
	// producer had something to match on — and nothing matched.
	SoftwareVulnNoneKnown = "none_known"
	// SoftwareVulnNotAssessed: the install has NEITHER a CPE nor a PURL. The
	// vulnerability producer skips it and counts it as unidentifiable, in its
	// own words: "'this install has no known vulnerabilities' and 'this install
	// could not be checked' are different answers and only one of them is
	// reassuring."
	SoftwareVulnNotAssessed = "not_assessed"
)

// SoftwareInstallRow is one row of an asset's Software tab: the install joined
// to its catalogue product.
type SoftwareInstallRow struct {
	InstallID   uuid.UUID  `json:"install_id" db:"install_id"`
	ProductID   uuid.UUID  `json:"product_id" db:"product_id"`
	Name        string     `json:"name" db:"name"`
	Vendor      *string    `json:"vendor,omitempty" db:"vendor"`
	Version     *string    `json:"version,omitempty" db:"version"`
	VersionSort *string    `json:"version_sort,omitempty" db:"version_sort"`
	PURL        *string    `json:"purl,omitempty" db:"purl"`
	CPE         *string    `json:"cpe,omitempty" db:"cpe"`
	LicenseID   *string    `json:"license_id,omitempty" db:"license_id"`
	InstallPath *string    `json:"install_path,omitempty" db:"install_path"`
	SourceKind  string     `json:"source_kind" db:"source_kind"`
	SourceRef   *string    `json:"source_ref,omitempty" db:"source_ref"`
	Status      string     `json:"status" db:"status"`
	FirstSeenAt time.Time  `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at" db:"last_seen_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty" db:"updated_at"`

	// The lifecycle and vulnerability rollup, joined from the ONE findings
	// table (workstream 3.8). It rides on the list rather than being fetched
	// per row: fifty installs on a Software tab would otherwise be fifty
	// subject-filtered calls to compliance-engine, and the page would be slower
	// than the answer is worth.
	//
	// These are a READ of what the `eol` and `vulnerability` producers wrote.
	// Nothing here re-decides whether a package is end of life or vulnerable —
	// that would be a second opinion, and the catalogue resolution the
	// producers do is not reproducible in a list query. The end-of-life state
	// reads the producer's per-install record as well as its finding, which is
	// what lets a supported package say so.
	EOLState string `json:"eol_state" db:"eol_state"`
	// EOLDate is the catalogue's end-of-life date for the matched cycle
	// (`YYYY-MM-DD`): the finding's evidence when EOLState is end_of_life, the
	// producer's record when it is supported. Nil in every other state.
	EOLDate *string `json:"eol_date,omitempty" db:"eol_date"`
	// EOLDaysRemaining is negative once the date has passed. Nil when the
	// producer wrote none.
	EOLDaysRemaining *int `json:"eol_days_remaining,omitempty" db:"eol_days_remaining"`
	// EOLSeverity is the finding's rung — low (approaching), medium (past),
	// high (past by more than a year).
	EOLSeverity  *string    `json:"eol_severity,omitempty" db:"eol_severity"`
	EOLFindingID *uuid.UUID `json:"eol_finding_id,omitempty" db:"eol_finding_id"`
	// EOLAssessedAt is when the `eol` producer last recorded this install's
	// lifecycle answer. Nil when no completed pass has — which is one of the
	// things `not_assessed` means, and the one a reader can tell apart by it.
	EOLAssessedAt *time.Time `json:"eol_assessed_at,omitempty" db:"eol_assessed_at"`

	VulnerabilityState string `json:"vulnerability_state" db:"vulnerability_state"`
	// VulnerabilityCount is how many CVEs the one finding carries (the producer
	// writes ONE finding per install with every match in its evidence). 0 for
	// every state but `vulnerable`.
	VulnerabilityCount int `json:"vulnerability_count" db:"vulnerability_count"`
	// WorstCVSS is the worst matching CVE's base score, 0–10. NIL, never 0.0,
	// when the catalogue scored none of them: the producer says so explicitly
	// with `worst_cvss_scored: false`, and 0.0 would read as harmless.
	WorstCVSS     *float64   `json:"worst_cvss,omitempty" db:"worst_cvss"`
	VulnSeverity  *string    `json:"vulnerability_severity,omitempty" db:"vulnerability_severity"`
	VulnFindingID *uuid.UUID `json:"vulnerability_finding_id,omitempty" db:"vulnerability_finding_id"`
}

// SoftwareProductRow is one row of the tenant catalogue, with how many assets
// carry it.
type SoftwareProductRow struct {
	ProductID   uuid.UUID `json:"product_id" db:"product_id"`
	Name        string    `json:"name" db:"name"`
	Vendor      *string   `json:"vendor,omitempty" db:"vendor"`
	Version     *string   `json:"version,omitempty" db:"version"`
	VersionSort *string   `json:"version_sort,omitempty" db:"version_sort"`
	PURL        *string   `json:"purl,omitempty" db:"purl"`
	CPE         *string   `json:"cpe,omitempty" db:"cpe"`
	LicenseID   *string   `json:"license_id,omitempty" db:"license_id"`
	SourceKind  string    `json:"source_kind" db:"source_kind"`
	// InstallCount counts ACTIVE installs. A product whose every install was
	// marked removed reports 0 and is still listed: it is part of the tenant's
	// history and "we used to run this" is a question the catalogue should be
	// able to answer.
	InstallCount int `json:"install_count" db:"install_count"`
	AssetCount   int `json:"asset_count" db:"asset_count"`

	// The catalogue-row rollup of the same two producers (workstream 3.8).
	//
	// A catalogue row IS an identity — name, version, purl/cpe — so every
	// install of it resolves identically for both producers. The states below
	// are therefore the state of the product, derived as "any install of it".
	// The counts are what makes that claim checkable rather than asserted.
	//
	// For end of life the derivation is worst-then-most-informative: an open
	// finding on any active install wins, then a `supported` record, then
	// `no_date`, then `not_in_catalogue`, then `not_assessed`. Installs of one
	// identity resolve identically, so a mixed set only arises across pass
	// boundaries — an install added since the last pass has no record yet —
	// and the recorded answer is the product's.
	EOLState string `json:"eol_state" db:"eol_state"`
	// EOLInstallCount is how many ACTIVE installs of this product carry an open
	// end-of-life finding.
	EOLInstallCount int `json:"eol_install_count" db:"eol_install_count"`
	// EOLDate is the finding's date when the state is end_of_life, the soonest
	// recorded date across supported installs when it is supported, else nil.
	EOLDate     *string `json:"eol_date,omitempty" db:"eol_date"`
	EOLSeverity *string `json:"eol_severity,omitempty" db:"eol_severity"`
	// EOLAssessedAt is the most recent lifecycle record across the product's
	// active installs. Nil when none has one.
	EOLAssessedAt *time.Time `json:"eol_assessed_at,omitempty" db:"eol_assessed_at"`

	VulnerabilityState string `json:"vulnerability_state" db:"vulnerability_state"`
	// VulnerableInstallCount is how many ACTIVE installs carry an open
	// vulnerability finding.
	VulnerableInstallCount int `json:"vulnerable_install_count" db:"vulnerable_install_count"`
	// VulnerabilityCount is the HIGHEST CVE count any of those findings carries,
	// which is not necessarily the count on the worst-scoring one — the two are
	// aggregated independently. They agree in practice because a catalogue row
	// IS an identity, so every install of it matches the same advisories; the
	// max is the honest answer when they ever do not.
	VulnerabilityCount int      `json:"vulnerability_count" db:"vulnerability_count"`
	WorstCVSS          *float64 `json:"worst_cvss,omitempty" db:"worst_cvss"`
	VulnSeverity       *string  `json:"vulnerability_severity,omitempty" db:"vulnerability_severity"`
}

// softwareSortColumns are the orderings the list endpoints accept.
//
// An allowlist rather than an interpolated column name, for the obvious reason,
// and `version` maps to `version_sort` for the reason QUERY_LANGUAGE §5.5 gives:
// sorting the raw string puts 1.10 below 1.9. NULLS LAST keeps the products
// whose version has no sort key at the end rather than at whichever end the
// planner picks.
//
// # Every clause ends in a UNIQUE column, and that is not decoration
//
// LIMIT/OFFSET only partitions a result set when the ordering is total. With
// ties, Postgres is free to return a tied row on page 1 and again on page 2 —
// or on neither — because nothing in the query says which comes first, and the
// order it picks may differ between two executions of the same statement.
//
// These orderings tie constantly rather than rarely. `last_seen` and
// `first_seen` are the extreme case: one upload writes `now()` into every row it
// touches inside ONE transaction, so every install on an asset shares a
// timestamp to the microsecond and the whole page set is one tie. `name` ties
// whenever two catalogue rows share a name and version — which is exactly what
// two different purls for one product produce, the case the identity rule
// deliberately keeps as two rows. `i.id` / `p.id` is a primary key, so appending
// it makes each ordering total.
var softwareSortColumns = map[string]string{
	"name":       "lower(p.name) ASC, p.version_sort ASC NULLS LAST, i.id ASC",
	"version":    "p.version_sort ASC NULLS LAST, lower(p.name) ASC, i.id ASC",
	"vendor":     "lower(coalesce(p.vendor, '')) ASC, lower(p.name) ASC, i.id ASC",
	"last_seen":  "i.last_seen_at DESC, lower(p.name) ASC, i.id ASC",
	"first_seen": "i.first_seen_at DESC, lower(p.name) ASC, i.id ASC",
}

const defaultSoftwareSort = "name"

// SoftwareSortClause resolves a client-supplied sort key, falling back to name.
// Exported for the handler's validation and pinned by a unit test.
func SoftwareSortClause(key string) (string, bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		k = defaultSoftwareSort
	}
	clause, ok := softwareSortColumns[k]
	return clause, ok
}

// ListAssetSoftware returns one asset's software installs with their products.
//
// `status` is returned rather than filtered on by default. A removed install is
// evidence — it is how "this was here last month" gets answered — and hiding it
// silently would make the list disagree with the count in the asset's history.
// The caller filters.
func (s *SBOMIngestService) ListAssetSoftware(
	ctx context.Context, tenantID, assetID uuid.UUID, q, status, sortKey string, limit, offset int,
) ([]SoftwareInstallRow, int, error) {
	order, ok := SoftwareSortClause(sortKey)
	if !ok {
		return nil, 0, fmt.Errorf("unknown sort %q", sortKey)
	}

	where := []string{"i.tenant_id = $1", "i.asset_id = $2"}
	args := []interface{}{tenantID, assetID}
	if term := strings.TrimSpace(q); term != "" {
		args = append(args, likePattern(term))
		n := fmt.Sprintf("$%d", len(args))
		where = append(where, "(lower(p.name) LIKE "+n+
			" OR lower(coalesce(p.vendor, '')) LIKE "+n+
			" OR lower(coalesce(p.purl, '')) LIKE "+n+
			" OR lower(coalesce(p.cpe, '')) LIKE "+n+")")
	}
	if st := strings.TrimSpace(status); st != "" {
		args = append(args, st)
		where = append(where, fmt.Sprintf("i.status = $%d", len(args)))
	}
	cond := strings.Join(where, " AND ")

	var (
		rows  []SoftwareInstallRow
		total int
	)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM software_installs i
			  JOIN software_products p ON p.tenant_id = i.tenant_id AND p.id = i.product_id
			 WHERE `+cond, args...).Scan(&total); e != nil {
			return e
		}
		pageArgs := append(append([]interface{}{}, args...), limit, offset)
		// The EOL / vulnerability rollup rides along (workstream 3.8) rather
		// than being fetched per row. See software_findings_rollup.go for what
		// each state means — in particular that `not_assessed` is not "clean".
		return tx.SelectContext(ctx, &rows, `
			SELECT i.id AS install_id, p.id AS product_id, p.name, p.vendor, p.version, p.version_sort,
			       p.purl, p.cpe, p.license_id,
			       i.install_path, i.source_kind, i.source_ref, i.status,
			       i.first_seen_at, i.last_seen_at, i.updated_at,
			       `+eolStateSQL("eolf", "lc")+` AS eol_state,
			       `+eolDateSQL("eolf", "lc")+`                    AS eol_date,
			       `+jsonInt("eolf.evidence", "days_remaining")+`  AS eol_days_remaining,
			       eolf.severity                                   AS eol_severity,
			       eolf.id                                         AS eol_finding_id,
			       lc.assessed_at                                  AS eol_assessed_at,
			       `+vulnStateSQL("vulnf", "p")+` AS vulnerability_state,
			       coalesce(`+jsonInt("vulnf.evidence", "cve_count")+`, 0) AS vulnerability_count,
			       `+worstCVSSSQL("vulnf")+`                       AS worst_cvss,
			       vulnf.severity                                  AS vulnerability_severity,
			       vulnf.id                                        AS vulnerability_finding_id
			  FROM software_installs i
			  JOIN software_products p ON p.tenant_id = i.tenant_id AND p.id = i.product_id`+
			softwareFindingJoin("eolf", sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife, "i.id", "i.tenant_id")+
			softwareLifecycleJoin("lc", "i.id", "i.tenant_id")+
			softwareFindingJoin("vulnf", sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability, "i.id", "i.tenant_id")+`
			 WHERE `+cond+`
			 ORDER BY `+order+`
			 LIMIT $`+fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2), pageArgs...)
	})
	if err != nil {
		return nil, 0, err
	}
	if rows == nil {
		rows = []SoftwareInstallRow{}
	}
	return rows, total, nil
}

// ListProducts returns the tenant software catalogue with install counts — the
// Inventory `software` lens.
func (s *SBOMIngestService) ListProducts(
	ctx context.Context, tenantID uuid.UUID, q, sortKey string, limit, offset int,
) ([]SoftwareProductRow, int, error) {
	// The catalogue has no install to order by, so the install-scoped sorts are
	// not offered here; name and version are. Every clause ends in `p.id` for
	// the reason softwareSortColumns gives: an ordering with ties does not
	// partition into pages, and `installs` in particular ties across every
	// product with the same count.
	order := "lower(p.name) ASC, p.version_sort ASC NULLS LAST, p.id ASC"
	switch strings.ToLower(strings.TrimSpace(sortKey)) {
	case "", "name":
	case "version":
		order = "p.version_sort ASC NULLS LAST, lower(p.name) ASC, p.id ASC"
	case "vendor":
		order = "lower(coalesce(p.vendor, '')) ASC, lower(p.name) ASC, p.id ASC"
	case "installs":
		order = "install_count DESC, lower(p.name) ASC, p.id ASC"
	case "eol_checked":
		// "Least recently checked" — the freshness question, which the
		// `eol_assessed_at` tooltip could state per row but nothing could sort
		// or filter on, so a tenant could not find the stale corner of the
		// catalogue without reading every tooltip in it.
		//
		// NULLS FIRST, and that is the load-bearing half. A NULL here is "no
		// completed pass has ever recorded an answer for any install of this
		// product", which is a WEAKER state than "checked a year ago", not a
		// missing value to sweep to the end. Sorting it last would put the
		// products nobody has ever looked at on the last page of a list whose
		// whole purpose is to surface what has not been looked at.
		order = "c.eol_assessed_at ASC NULLS FIRST, lower(p.name) ASC, p.id ASC"
	default:
		return nil, 0, fmt.Errorf("unknown sort %q", sortKey)
	}

	where := []string{"p.tenant_id = $1"}
	args := []interface{}{tenantID}
	if term := strings.TrimSpace(q); term != "" {
		args = append(args, likePattern(term))
		n := fmt.Sprintf("$%d", len(args))
		where = append(where, "(lower(p.name) LIKE "+n+
			" OR lower(coalesce(p.vendor, '')) LIKE "+n+
			" OR lower(coalesce(p.purl, '')) LIKE "+n+
			" OR lower(coalesce(p.cpe, '')) LIKE "+n+")")
	}
	cond := strings.Join(where, " AND ")

	var (
		rows  []SoftwareProductRow
		total int
	)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM software_products p WHERE `+cond, args...).Scan(&total); e != nil {
			return e
		}
		pageArgs := append(append([]interface{}{}, args...), limit, offset)
		// The catalogue-row rollup (workstream 3.8).
		//
		// A catalogue row IS an identity — name, version, purl/cpe — so every
		// install of it resolves identically for both producers, and the
		// product's state is "any active install of it". `eol_install_count`
		// and `vulnerable_install_count` ride along so that claim is checkable
		// on screen rather than asserted: a reader can see the state came from
		// four installs and not from one stale row.
		//
		// Aggregated in the SAME sub-select as the install counts rather than
		// in a second one, so the numbers beside each other are taken over one
		// scan of one set of rows.
		return tx.SelectContext(ctx, &rows, `
			SELECT p.id AS product_id, p.name, p.vendor, p.version, p.version_sort,
			       p.purl, p.cpe, p.license_id, p.source_kind,
			       coalesce(c.install_count, 0) AS install_count,
			       coalesce(c.asset_count, 0)   AS asset_count,
			       `+eolProductStateSQL("c")+` AS eol_state,
			       coalesce(c.eol_install_count, 0) AS eol_install_count,
			       `+eolProductDateSQL("c")+` AS eol_date,
			       c.eol_severity,
			       c.eol_assessed_at,
			       CASE WHEN coalesce(c.vulnerable_install_count, 0) > 0 THEN '`+SoftwareVulnVulnerable+`'
			            WHEN coalesce(p.purl, '') <> '' OR coalesce(p.cpe, '') <> ''
			                 THEN '`+SoftwareVulnNoneKnown+`'
			            ELSE '`+SoftwareVulnNotAssessed+`' END AS vulnerability_state,
			       coalesce(c.vulnerable_install_count, 0) AS vulnerable_install_count,
			       coalesce(c.vulnerability_count, 0)      AS vulnerability_count,
			       c.worst_cvss,
			       c.vulnerability_severity
			  FROM software_products p
			  LEFT JOIN (
			        SELECT i.product_id,
			               count(*)                    AS install_count,
			               count(DISTINCT i.asset_id)  AS asset_count,
			               count(eolf.id)              AS eol_install_count,
			               count(vulnf.id)             AS vulnerable_install_count,
			               min(eolf.evidence ->> 'eol_date')          AS eol_date,
			               (array_agg(eolf.severity ORDER BY eolf.score DESC NULLS LAST))[1]  AS eol_severity,
			               `+eolLifecycleAggregatesSQL("lc")+`,
			               (array_agg(vulnf.severity ORDER BY vulnf.score DESC NULLS LAST))[1] AS vulnerability_severity,
			               max(`+jsonInt("vulnf.evidence", "cve_count")+`)  AS vulnerability_count,
			               max(`+worstCVSSSQL("vulnf")+`)                   AS worst_cvss
			          FROM software_installs i`+
			// Plain joins, NOT the LATERAL the per-asset list uses: this
			// sub-select folds every install the tenant has, on every page it
			// serves, so a per-row LATERAL is two index probes per install
			// (120,000 on a 60,000-install tenant — 702ms against 101ms for the
			// same match hash-joined). One row per install is still guaranteed,
			// by `findings_open_subject_uniq` rather than by a LIMIT — see
			// softwareFindingAggregateJoin. The lifecycle record is keyed by
			// install, so its join is one row per install by primary key.
			softwareFindingAggregateJoin("eolf", sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife, "i.id", "i.tenant_id")+
			softwareLifecycleJoin("lc", "i.id", "i.tenant_id")+
			softwareFindingAggregateJoin("vulnf", sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability, "i.id", "i.tenant_id")+`
			         WHERE i.tenant_id = $1 AND i.status = 'active'
			         GROUP BY i.product_id
			  ) c ON c.product_id = p.id
			 WHERE `+cond+`
			 ORDER BY `+order+`
			 LIMIT $`+fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2), pageArgs...)
	})
	if err != nil {
		return nil, 0, err
	}
	if rows == nil {
		rows = []SoftwareProductRow{}
	}
	return rows, total, nil
}
