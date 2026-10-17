package services

// Source imports: the write (and two read) paths a connector running OUTSIDE
// this service uses to bring a system of record's objects into the inventory.
//
// Platform ADR-0002 D3 moved the connectors that pull from a system of record
// out of this service, and made one rule of it: they write the platform only
// through the owning service's API, never its tables. This file is that API's
// service layer. The HTTP surface is internal/handlers/source_import_handlers.go,
// mounted on an HMAC-only group (never reachable with a user token) and denied
// at the edge on every host.
//
// It is deliberately about SOURCES, not about any one connector. What it
// guarantees is the inventory's side of an import — admission, identity,
// approval, provenance, the tenant-wins rules on a prefix the tenant already
// drew — and those are the same whichever system of record the data came from.
// The mapping from a vendor's model to these shapes stays with the connector.
//
// Every call is scoped to ONE tenant, named by the caller and carried in the
// signed request, and every write runs tenant-scoped under RLS. A caller that
// names tenant A cannot touch tenant B: the tenant is part of every statement
// and of the transaction's RLS context, not something inferred from the data.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/network/addrscope"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// Source network outcomes, one per submitted item. A source's networks are
// written as global-VRF prefixes (DCIM row 1.6); the wire names (`segments`,
// SourcePrefix) are the connector contract row 1.9 reworks.
const (
	// SourcePrefixCreated: a new global-VRF prefix was written with the
	// source's provenance.
	SourcePrefixCreated = "created"
	// SourcePrefixMatched: a prefix with the same masked CIDR already
	// existed in the global table. Its provenance was stamped and its NetBox
	// id recorded; nothing the tenant configured on it was touched.
	SourcePrefixMatched = "matched"
	// SourcePrefixTooBroad: the prefix is too broad to be anybody's
	// (probeconsent.TooBroadToClaim) and matches no existing one. Not written.
	SourcePrefixTooBroad = "too_broad"
	// SourcePrefixError: the item could not be written; Error says why.
	SourcePrefixError = "error"
)

// MaxSourceBatch bounds one request's items. A connector with more sends
// several requests; a bound keeps one request's transaction count and
// response time predictable for the service that has to answer it.
const MaxSourceBatch = 500

// sourceEnvironments are the values of the environment_type enum.
var sourceEnvironments = map[string]bool{
	"production": true, "staging": true, "development": true, "test": true,
}

// SourcePrefix is one network a source declares, written as a prefix.
type SourcePrefix struct {
	// CIDR is the prefix. It is masked here, so "10.1.1.5/24" and
	// "10.1.1.0/24" are the same network.
	CIDR string `json:"cidr"`
	// Name is the created prefix's description when the source gives none.
	// A prefix that already exists keeps what the tenant gave it.
	Name string `json:"name"`
	// Environment is one of production / staging / development / test, used
	// only on create.
	Environment string `json:"environment"`
	// Description is used only on create.
	Description string `json:"description,omitempty"`
	// Metadata is the source's description of the network on create. Only
	// `netbox_prefix_id` is kept — as the prefix's `external_ids.netbox`, the
	// key the NetBox sync matches on (DCIM row 1.9); a prefix has no
	// free-form metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
	// MatchMetadata is the same for a prefix that already existed.
	MatchMetadata map[string]any `json:"match_metadata,omitempty"`
	// SourceRef names the source record, e.g. `<producer>:<connection>:prefix:<id>`.
	SourceRef string `json:"source_ref"`
}

// SourcePrefixResult is what happened to one submitted network.
type SourcePrefixResult struct {
	CIDR    string `json:"cidr"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

// SourceFact is one fact a source states about an asset it supplied. The
// producer is always `connector`; the source kind and ref are the request's.
type SourceFact struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// SourceAssetItem is one asset observation from a source.
type SourceAssetItem struct {
	Input models.AssetInput
	// Facts are written after the asset resolves, under the request's source.
	Facts []SourceFact
	// ClaimDiscoverySource is stamped as `metadata.discovery_source` on the
	// resolved asset ONLY when nothing has claimed it yet. A sensor-discovered
	// host that a source later matches stays a sensor discovery.
	ClaimDiscoverySource string
}

// SourceAssetResult is what happened to one submitted asset.
type SourceAssetResult struct {
	// Outcome is the identification engine's answer (`created`, `matched`,
	// `conflict`), or `retained` when the engine held the observation rather
	// than creating anything, or `error`.
	Outcome string     `json:"outcome"`
	AssetID *uuid.UUID `json:"asset_id,omitempty"`
	// ObservationID and Proposed describe a retained observation. Proposed is
	// true when the engine held it as a conflict awaiting a person.
	ObservationID string `json:"observation_id,omitempty"`
	Proposed      bool   `json:"proposed,omitempty"`
	Error         string `json:"error,omitempty"`
	// DiscoverySourceError and FactsError report the two follow-up writes on a
	// resolved asset. The asset itself was resolved either way.
	DiscoverySourceError string `json:"discovery_source_error,omitempty"`
	FactsError           string `json:"facts_error,omitempty"`
}

// SourceOutcomeRetained is the outcome of an observation the engine held.
const SourceOutcomeRetained = "retained"

// SourceOutcomeError is the outcome of an item that failed.
const SourceOutcomeError = "error"

// SourceAdmission answers "may a source import N assets for this tenant".
type SourceAdmission struct {
	// Prospective is true when the tenant's identity admission mode checks
	// each create transactionally (enforce / paused). The caller then scopes
	// each record by its source identity, and the plan cap is not checked in
	// advance because the engine checks it per create.
	Prospective bool `json:"prospective"`
	// Allowed is false when importing Count assets would exceed the plan's
	// asset cap. Always true when Prospective.
	Allowed bool `json:"allowed"`
	// Message is the cap check's sentence when Allowed is false.
	Message string `json:"message,omitempty"`
	// CurrentUsage, Limit and UpgradePrompt are the rest of the cap check's
	// answer when Allowed is false, so a caller can refuse its tenant with the
	// same 402 body every other asset-creating path answers. Limit is
	// null for an unlimited plan.
	CurrentUsage  int    `json:"current_usage,omitempty"`
	Limit         *int   `json:"limit,omitempty"`
	UpgradePrompt string `json:"upgrade_prompt,omitempty"`
}

// ErrAdmissionPolicy and ErrAssetLimit say which half of an admission check
// could not be answered. A check that cannot be answered is a FAILED check —
// the caller imports nothing — not a passed one.
var (
	ErrAdmissionPolicy = errors.New("could not read identity admission policy")
	ErrAssetLimit      = errors.New("could not check this plan's asset limit")
)

// SourceHardwareAsset is one asset a source reconciliation compares against:
// a live (monitoring or pending) hardware asset, or an unknown host, with its
// first serial number.
type SourceHardwareAsset struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
	Hostname    string    `json:"hostname"`
	Address     string    `json:"address"`
	ClassKey    string    `json:"class_key"`
	AssetStatus string    `json:"asset_status"`
	Site        string    `json:"site"`
	Serial      string    `json:"serial"`
}

// MaxSourceHardwarePage bounds one page of the hardware read.
const MaxSourceHardwarePage = 5000

// sourceAssetWriter is the slice of AssetService a source import drives. An
// interface so the unit tests can exercise the outcome mapping without a
// database; production passes the real AssetService.
type sourceAssetWriter interface {
	UsesIdentityAdmission(context.Context, uuid.UUID) (bool, error)
	CreateAssetFromSource(uuid.UUID, models.AssetInput, identity.Source) (*models.Asset, identity.Outcome, error)
	DeclareFor(ctx context.Context, tenantID, assetID uuid.UUID, sg identity.Sighting) (identity.Resolution, error)
}

// assetLimitChecker is the plan cap check (LimitEnforcementService).
type assetLimitChecker interface {
	CheckAssetLimit(tenantID uuid.UUID, additionalCount int) (*sharedservices.LimitCheckResult, error)
}

// SourceImportService is the service layer behind the internal source routes.
type SourceImportService struct {
	db       *database.DB
	assets   sourceAssetWriter
	limits   assetLimitChecker
	identity *pgidentity.Repository
	// archiver is the lifecycle archive a run undo uses (WithArchiver).
	archiver runArchiver
}

// NewSourceImportService wires it against Core's AssetService.
func NewSourceImportService(db *database.DB, assets *AssetService) *SourceImportService {
	return &SourceImportService{
		db:       db,
		assets:   assets,
		limits:   sharedservices.NewLimitEnforcementService(db.DB.DB),
		identity: pgidentity.New(db.DB.DB),
	}
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

// UpsertPrefixes writes a source's networks as prefixes, in order (DCIM row
// 1.6: the source's networks used to be written as network segments).
//
// A network that MATCHES an existing on-premises global-VRF prefix by masked
// CIDR is not duplicated: it is stamped with the source's provenance and its
// NetBox id, and NOTHING ELSE on it changes. Description, environment,
// auto-approval and scan posture are the tenant's, and an import that
// overwrote them would undo deliberate configuration on every scheduled run.
//
// A cloud subnet prefix with the same CIDR is not a match: a source prefix
// describes physical address space that belongs to no VPC.
//
// The error return is for the whole call (the existing prefixes could not be
// read); per-item failures are results, so one bad item does not cost the
// others.
func (s *SourceImportService) UpsertPrefixes(ctx context.Context, tenantID uuid.UUID, items []SourcePrefix) ([]SourcePrefixResult, error) {
	existing, err := s.onPremPrefixes(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("could not read existing prefixes: %w", err)
	}
	out := make([]SourcePrefixResult, 0, len(items))
	for _, item := range items {
		out = append(out, s.upsertSourcePrefix(ctx, tenantID, existing, item))
	}
	return out, nil
}

func (s *SourceImportService) upsertSourcePrefix(ctx context.Context, tenantID uuid.UUID,
	existing map[string]uuid.UUID, item SourcePrefix) SourcePrefixResult {

	prefix, err := netip.ParsePrefix(strings.TrimSpace(item.CIDR))
	if err != nil {
		return SourcePrefixResult{CIDR: item.CIDR, Outcome: SourcePrefixError,
			Error: fmt.Sprintf("%q is not a valid CIDR", item.CIDR)}
	}
	canonical := prefix.Masked().String()
	res := SourcePrefixResult{CIDR: canonical}
	fail := func(msg string) SourcePrefixResult {
		res.Outcome, res.Error = SourcePrefixError, msg
		return res
	}
	ref := strings.TrimSpace(item.SourceRef)
	if ref == "" {
		return fail("a source network needs a source_ref")
	}
	if len(ref) > 200 {
		return fail("source_ref is longer than 200 characters")
	}

	if id, ok := existing[canonical]; ok {
		if err := s.markPrefixImported(ctx, tenantID, id, ref, item.MatchMetadata); err != nil {
			return fail(err.Error())
		}
		res.Outcome = SourcePrefixMatched
		return res
	}

	// A prefix is a claim of ownership, so an imported one is held to the
	// rule a declared one is ( W5.13): nothing too broad to be anybody's.
	// An EXISTING prefix it matches is left alone either way (above).
	if probeconsent.TooBroadToClaim(prefix) {
		res.Outcome = SourcePrefixTooBroad
		return res
	}

	description := strings.TrimSpace(item.Description)
	if description == "" {
		description = strings.TrimSpace(item.Name)
	}
	if description == "" {
		return fail("a new network needs a name or a description")
	}
	env := strings.ToLower(strings.TrimSpace(item.Environment))
	if !sourceEnvironments[env] {
		return fail(fmt.Sprintf("environment %q is not one of production, staging, development, test", item.Environment))
	}
	if err := s.createSourcePrefix(ctx, tenantID, canonical, prefix, description, env, item.Metadata, ref); err != nil {
		return fail(err.Error())
	}
	res.Outcome = SourcePrefixCreated
	return res
}

// onPremPrefixes indexes this tenant's on-premises global-VRF prefixes by
// masked CIDR.
func (s *SourceImportService) onPremPrefixes(ctx context.Context, tenantID uuid.UUID) (map[string]uuid.UUID, error) {
	out := map[string]uuid.UUID{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, prefix::text FROM prefixes
			WHERE tenant_id = $1 AND vrf_id IS NULL AND cloud_network_ref IS NULL AND status <> 'rejected'`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var value string
			if err := rows.Scan(&id, &value); err != nil {
				return err
			}
			if p, perr := netip.ParsePrefix(strings.TrimSpace(value)); perr == nil {
				out[p.Masked().String()] = id
			}
		}
		return rows.Err()
	})
	return out, err
}

// sourceNetworkType is measured, not declared: whether a prefix is in private
// address space is a property of the prefix.
//
// It reads addrscope.MayAutoProbe, not IsTenantAddressable: a prefix's
// network_type "private" is what the automatic-scan gates read as ownership
// (autoscan.AutomaticPrefixTypes), so an imported CGNAT prefix stays "public"
// and does not become an unattended-scan target ( D1).
func sourceNetworkType(prefix netip.Prefix) string {
	if addrscope.MayAutoProbe(prefix.Addr()) {
		return "private"
	}
	return "public"
}

// sourceExternalIDs is the `external_ids` a source network contributes: the
// NetBox prefix id, under the key the NetBox sync matches on.
func sourceExternalIDs(meta map[string]any) string {
	ext := map[string]any{}
	if v, ok := meta["netbox_prefix_id"]; ok && v != nil {
		ext["netbox"] = v
	}
	return sourceJSON(ext)
}

func (s *SourceImportService) createSourcePrefix(ctx context.Context, tenantID uuid.UUID, canonical string,
	prefix netip.Prefix, description, env string, meta map[string]any, sourceRef string) error {

	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO prefixes
				(tenant_id, prefix, network_type, environment, description,
				 external_ids, source_kind, source_ref, status)
			SELECT $1, $2::cidr, $3, $4, $5, $6::jsonb, 'imported', $7, 'active'
			 WHERE NOT EXISTS (SELECT 1 FROM prefixes
			                    WHERE tenant_id = $1 AND vrf_id IS NULL AND prefix = $2::cidr AND status <> 'rejected'
			                      AND cloud_network_ref IS NULL)`,
			tenantID, canonical, sourceNetworkType(prefix), env, description,
			sourceExternalIDs(meta), sourceRef)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Another request created the on-premises prefix since this one
			// read them. A cloud subnet with the same CIDR does not stop the
			// insert: prefix identity includes the cloud network
			// (prefixes_identity_uniq), and a NetBox prefix belongs to none.
			return fmt.Errorf("%s was created concurrently; re-run the import to match it", canonical)
		}
		// The new prefix changes its parents' utilisation and its own: the
		// cache the Networks lens reads (ipam_prefix.go).
		return refreshChain(ctx, tx.Tx, tenantID, nil, canonical)
	})
}

// markPrefixImported stamps provenance on a prefix that already existed. It
// touches provenance and the NetBox id ONLY — the "empty never wins" rule
// applied to a whole row: the tenant's description, environment, auto-approval
// and scan posture stay.
func (s *SourceImportService) markPrefixImported(ctx context.Context, tenantID, prefixID uuid.UUID,
	sourceRef string, meta map[string]any) error {

	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE prefixes
			SET source_kind  = 'imported',
			    source_ref   = $1,
			    external_ids = COALESCE(external_ids, '{}'::jsonb) || $2::jsonb,
			    updated_at   = now()
			WHERE tenant_id = $3 AND id = $4`,
			sourceRef, sourceExternalIDs(meta), tenantID, prefixID)
		return err
	})
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

// Admission answers whether a source may import count assets for this tenant,
// BEFORE any is written.
//
// The subscription asset cap applies to a source import exactly as it does to
// spreadsheet import and CMDB pull. Without it a connector is a way to
// create assets past the plan limit that every other path blocks. A cap check
// that cannot be answered is an error, never an allowance.
func (s *SourceImportService) Admission(ctx context.Context, tenantID uuid.UUID, count int) (SourceAdmission, error) {
	prospective, err := s.assets.UsesIdentityAdmission(ctx, tenantID)
	if err != nil {
		return SourceAdmission{}, fmt.Errorf("%w: %v", ErrAdmissionPolicy, err)
	}
	// Prospective admission checks actual creates transactionally. Matching
	// existing records or retaining observations consumes no new allowance.
	if prospective {
		return SourceAdmission{Prospective: true, Allowed: true}, nil
	}
	check, err := s.limits.CheckAssetLimit(tenantID, count)
	if err != nil {
		return SourceAdmission{}, fmt.Errorf("%w: %v", ErrAssetLimit, err)
	}
	if check != nil && !check.Allowed {
		return SourceAdmission{Allowed: false, Message: check.Message, CurrentUsage: check.CurrentUsage,
			Limit: check.Limit, UpgradePrompt: check.UpgradePrompt}, nil
	}
	return SourceAdmission{Allowed: true}, nil
}

// ResolveAssets runs each observation through the identification engine, in
// order, exactly as CreateAssetFromSource does for one: admission, identity
// evidence, classification and the approval policy all apply. Two items for the
// same host resolve to one asset (the second MATCHES the first), because each
// is resolved after the one before it has been written.
//
// On a resolved asset it then claims the discovery source (only where nothing
// has) and writes the item's facts under the request's source.
func (s *SourceImportService) ResolveAssets(ctx context.Context, tenantID uuid.UUID,
	source identity.Source, items []SourceAssetItem) []SourceAssetResult {

	out := make([]SourceAssetResult, 0, len(items))
	for _, item := range items {
		out = append(out, s.resolveAsset(ctx, tenantID, source, item))
	}
	return out
}

func (s *SourceImportService) resolveAsset(ctx context.Context, tenantID uuid.UUID,
	source identity.Source, item SourceAssetItem) SourceAssetResult {

	asset, outcome, err := s.assets.CreateAssetFromSource(tenantID, item.Input, source)
	if err != nil {
		var retained *identity.RetainedObservation
		if errors.As(err, &retained) && retained.Result.ObservationID != "" {
			return SourceAssetResult{
				Outcome:       SourceOutcomeRetained,
				ObservationID: retained.Result.ObservationID,
				Proposed:      retained.Result.Outcome == string(identity.OutcomeConflict),
			}
		}
		return SourceAssetResult{Outcome: SourceOutcomeError, Error: err.Error()}
	}
	res := SourceAssetResult{Outcome: string(outcome)}
	if res.Outcome == "" {
		res.Outcome = string(identity.OutcomeCreated)
	}
	if asset == nil {
		return res
	}
	id := asset.ID
	res.AssetID = &id
	if claim := strings.TrimSpace(item.ClaimDiscoverySource); claim != "" {
		if err := s.claimDiscoverySource(ctx, tenantID, asset.ID, claim); err != nil {
			res.DiscoverySourceError = err.Error()
		}
	}
	observedAt := item.Input.ObservationTime
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	if err := s.writeFacts(ctx, tenantID, asset.ID, source, item.Facts, observedAt); err != nil {
		res.FactsError = err.Error()
	}
	return res
}

// claimDiscoverySource stamps `metadata.discovery_source` on an asset that has
// NO discovery source yet, and leaves every other asset alone.
//
// `discovery_source` is a single string (the Approvals filter and the
// auto-approval rules compare it with `->>`), so the only choice is whether a
// source may displace the first one, and it may not: an asset a sensor
// discovered and a source later matched is still a sensor discovery. The
// source's part is not lost — the engine records the observation under the
// source ref (identifiers, facts and history all carry it).
func (s *SourceImportService) claimDiscoverySource(ctx context.Context, tenantID, assetID uuid.UUID, value string) error {
	claim, err := json.Marshal(map[string]string{"discovery_source": value})
	if err != nil {
		return err
	}
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE assets
			   SET metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb
			 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
			   AND (metadata IS NULL
			        OR NOT (metadata ? 'discovery_source')
			        OR COALESCE(metadata->>'discovery_source', '') = '')`, tenantID, assetID, string(claim))
		return err
	})
}

// writeFacts records a source's facts as statements with provenance (ADR-0005
// D2): a later interrogation that measures the same key writes it under its own
// source_ref, and the identity ladder decides which is displayed. Keys are
// validated against the fact registry for the `connector` producer.
func (s *SourceImportService) writeFacts(ctx context.Context, tenantID, assetID uuid.UUID,
	source identity.Source, in []SourceFact, observedAt time.Time) error {

	var fs []pgidentity.Fact
	for _, f := range in {
		if str, ok := f.Value.(string); ok && strings.TrimSpace(str) == "" {
			continue
		}
		if f.Value == nil {
			continue
		}
		fs = append(fs, pgidentity.Fact{
			Key:        f.Key,
			Value:      f.Value,
			SourceKind: source.Kind,
			SourceRef:  source.Ref,
			ObservedAt: observedAt,
		})
	}
	if len(fs) == 0 {
		return nil
	}
	ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	return s.identity.UpsertFacts(ctx, ref, facts.ProducerConnector, fs)
}

// ---------------------------------------------------------------------------
// Link identifiers and source presence (platform ADR-0002 D11 items 2–3)
// ---------------------------------------------------------------------------

// sourceLinkKinds are the identifier kinds a source may attach to an asset it
// did not just resolve: the scoped link to ITS OWN record for the asset (a
// CMDB sys_id, scoped to the profile). That link is what makes the source's
// next pull of the record resolve to the same asset instead of a duplicate
// (echo suppression). Evidence kinds — serials, MACs, cloud ids — arrive only
// with an observation, through the identity engine.
var sourceLinkKinds = map[string]bool{string(identity.KindCMDBSysID): true}

// SourceLink is one link identifier a source attaches to an asset.
type SourceLink struct {
	AssetID uuid.UUID `json:"asset_id"`
	Kind    string    `json:"kind"`
	Value   string    `json:"value"`
	// Scope is REQUIRED: a record id is unique only within one source
	// instance, and an unscoped one would join two instances' records.
	Scope string `json:"scope"`
}

// SourcePresence is one change of an asset's presence in a source.
type SourcePresence struct {
	AssetID uuid.UUID `json:"asset_id"`
	// Presence is "present" or "absent".
	Presence string `json:"presence"`
	// Reason is the sentence the timeline shows ("retired in ServiceNow").
	Reason string `json:"reason"`
}

// SourceItemResult is what happened to one link or presence item.
type SourceItemResult struct {
	// Outcome is "recorded", "not_found" (no asset of this tenant has that
	// id) or "error".
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

// Outcomes of SourceItemResult.
const (
	SourceItemRecorded = "recorded"
	SourceItemNotFound = "not_found"
)

// tenantAssets returns which of ids are assets of this tenant (live or not:
// a presence change on an asset we archived is still worth recording).
func (s *SourceImportService) tenantAssets(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	raw := make([]string, 0, len(ids))
	for _, id := range ids {
		raw = append(raw, id.String())
	}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
			tenantID, pq.Array(raw))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out, err
}

// AttachLinks attaches a source's link identifiers to assets of this tenant.
//
// The asset must be this tenant's: the ownership check is explicit here rather
// than left to the identity repository, because an asset id is a caller's
// claim and this route exists for callers outside the service.
func (s *SourceImportService) AttachLinks(ctx context.Context, tenantID uuid.UUID, source identity.Source, items []SourceLink) ([]SourceItemResult, error) {
	ids := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.AssetID)
	}
	owned, err := s.tenantAssets(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("could not read the tenant's assets: %w", err)
	}
	out := make([]SourceItemResult, 0, len(items))
	for _, it := range items {
		switch {
		case !sourceLinkKinds[it.Kind]:
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: fmt.Sprintf("identifier kind %q is not a source link", it.Kind)})
			continue
		case strings.TrimSpace(it.Scope) == "":
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: "a source link needs its scope"})
			continue
		case strings.TrimSpace(it.Value) == "":
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: "a source link needs a value"})
			continue
		case !owned[it.AssetID]:
			out = append(out, SourceItemResult{Outcome: SourceItemNotFound})
			continue
		}
		// A declaration about THIS asset, from the source's own system of
		// record: an `api` sighting carrying the link, scoped by its sync
		// profile, attached by the engine (Engine.ResolveDeclaredFor). One
		// another asset already holds is refused and reported, never moved.
		_, err := s.assets.DeclareFor(ctx, tenantID, it.AssetID, identity.Sighting{
			Source: source, Channel: identity.ChannelAPI, ObservedAt: time.Now().UTC(),
			Identifiers: []identity.SightedIdentifier{{Kind: identity.Kind(it.Kind), Value: it.Value, Profile: it.Scope}},
		})
		if err != nil {
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: err.Error()})
			continue
		}
		out = append(out, SourceItemResult{Outcome: SourceItemRecorded})
	}
	return out, nil
}

// RecordPresence writes source-presence changes on assets' timelines — an
// `updated` history entry naming the source, and NOTHING about the asset
// itself: the source's lifecycle and ours decide the rest (D11 item 2).
func (s *SourceImportService) RecordPresence(ctx context.Context, tenantID uuid.UUID, source identity.Source, platform string, items []SourcePresence) ([]SourceItemResult, error) {
	ids := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.AssetID)
	}
	owned, err := s.tenantAssets(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("could not read the tenant's assets: %w", err)
	}
	out := make([]SourceItemResult, 0, len(items))
	for _, it := range items {
		if it.Presence != "present" && it.Presence != "absent" {
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: fmt.Sprintf("presence %q is not present or absent", it.Presence)})
			continue
		}
		if !owned[it.AssetID] {
			out = append(out, SourceItemResult{Outcome: SourceItemNotFound})
			continue
		}
		reason := it.Reason
		if len(reason) > 500 {
			reason = reason[:500]
		}
		err := s.identity.RecordHistory(ctx, identity.HistoryEntry{
			TenantID: tenantID.String(), AssetID: it.AssetID.String(), Action: identity.ActionUpdated,
			Source: source,
			Changes: map[string]any{"source_presence": map[string]any{
				"source": source.Ref, "platform": platform,
				"presence": it.Presence, "reason": reason,
			}},
			At: time.Now().UTC(),
		})
		if err != nil {
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: err.Error()})
			continue
		}
		out = append(out, SourceItemResult{Outcome: SourceItemRecorded})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// ClassKeyExists reports whether key names an asset class this tenant may use:
// the compiled hierarchy (standards/asset-classes.yaml) or one of the tenant's
// own leaf subclasses. Checking only the first would reject a correct setup.
func (s *SourceImportService) ClassKeyExists(ctx context.Context, tenantID uuid.UUID, key string) (bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return false, nil
	}
	if _, ok := assetclass.Get(key); ok {
		return true, nil
	}
	var exists bool
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM asset_classes
				WHERE key = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
			)`, key, tenantID).Scan(&exists)
	})
	return exists, err
}

// HardwareAssets reads, a page at a time in id order, the assets a source of
// physical and virtual infrastructure could be expected to list: live
// (monitoring or pending approval) assets in the hardware subtree, plus unknown
// hosts, each with its first serial number.
//
// The class filter matters for the reconciliation this feeds: a Lambda
// function or an S3 bucket is absent from a DCIM because it does not belong
// there, and listing it as "missing" would bury the real findings.
func (s *SourceImportService) HardwareAssets(ctx context.Context, tenantID uuid.UUID,
	after uuid.UUID, limit int) ([]SourceHardwareAsset, error) {

	if limit <= 0 || limit > MaxSourceHardwarePage {
		limit = MaxSourceHardwarePage
	}
	out := []SourceHardwareAsset{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id,
			       COALESCE(a.display_name, ''),
			       COALESCE(a.hostname, ''),
			       COALESCE(host(a.primary_address), ''),
			       a.class_key,
			       a.asset_status,
			       COALESCE(`+assetSiteNameSQL+`, ''),
			       COALESCE((
			         SELECT ai.value FROM asset_identifiers ai
			         WHERE ai.tenant_id = a.tenant_id AND ai.asset_id = a.id
			           AND ai.kind = 'serial_number'
			         ORDER BY ai.created_at ASC LIMIT 1), '')
			FROM assets a
			WHERE a.tenant_id = $1
			  AND a.deleted_at IS NULL
			  AND a.asset_status IN ('monitoring', 'pending_approval')
			  AND (a.class_path LIKE 'hardware%' OR a.class_key = 'unknown_host')
			  AND a.id > $2
			ORDER BY a.id
			LIMIT $3`, tenantID, after, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a SourceHardwareAsset
			if err := rows.Scan(&a.ID, &a.DisplayName, &a.Hostname, &a.Address,
				&a.ClassKey, &a.AssetStatus, &a.Site, &a.Serial); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// sourceJSON marshals a map for a ::jsonb parameter; nil becomes {}.
func sourceJSON(v map[string]any) string {
	if len(v) == 0 {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
