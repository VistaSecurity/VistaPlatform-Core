package producers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// HygieneProducer is the `hygiene` finding producer (ADR-0005 D3, workstream
// 3.5).
//
// It judges the inventory RECORD rather than the thing the record describes:
// is it owned, classified, located, recently seen, unique, and do its edges
// point anywhere. Six kinds:
//
//	no_owner              asset            neither owner_email nor support_group
//	no_class              asset            still on the unknown_host placeholder
//	no_location           asset            no site, region, zone or location row
//	duplicate_suspected   asset            a PENDING merge proposal names it
//	stale                 asset/endpoint/  nothing has observed it for 30/90/180
//	                      software_install days (ladder)
//	orphan_relationship   relationship     an edge whose other end is gone
//
// # Nothing here feeds risk, and that is enforced three times
//
// Every kind's `feeds_risk` is false and every score is 0. A missing owner does
// not make a host less secure; it makes the inventory worse, which is a
// different problem with a different audience. The writer REFUSES a non-zero
// score on a feeds_risk-false kind, so a hygiene finding that tried to
// contribute to the risk rollup would fail loudly rather than quietly inflate a
// security number.
//
// The same reasoning decides WHERE its coverage claim goes. The pass records
// every live asset it evaluated in `producer_assessments` (workstream 3.2),
// which is the full record of who has looked; it must never reach
// `assets.risk_assessed_by`, the RISK-feeding subset the rollup derives, because
// the inventory UI reads a non-empty array there as "the risk score is a real
// answer" and an asset whose only evaluation was a missing owner has not had its
// risk assessed. The compliance `finding` shape reads the full record, which is
// what turns Inventory Hygiene's IH-005 and IH-006 from NOT ASSESSED into a
// number.
//
// # Which assets it evaluates, and the one split
//
// All live assets — not soft-deleted, not archived — exactly like the eol
// producer. An archived asset is one the tenant decided to stop tracking.
//
// Within that population there is ONE split, and it matters:
//
//   - `no_owner`, `no_class`, `no_location` and `stale` fire only on assets
//     whose status is `monitoring`. That is what the Inventory Hygiene
//     framework's four asset-shape measurements already scope themselves to
//     (`where: status:monitoring`), and asking for the owner of something still
//     sitting in Approvals is asking about a record nobody has accepted yet.
//   - `duplicate_suspected` fires on ANY live asset, because the observation
//     asset in a merge proposal is by construction `pending_approval` — it is
//     the newly-seen record the engine would not merge. Restricting this kind
//     to `monitoring` would raise the finding on the long-standing half of the
//     pair and never on the half that is actually in question.
type HygieneProducer struct {
	repo   *pgidentity.Repository
	writer *producer.Writer

	now func() time.Time
}

// NewHygieneProducer builds the producer over the RLS-subject handle.
func NewHygieneProducer(appDB *sql.DB) (*HygieneProducer, error) {
	w, err := producer.New(findings.ProducerHygiene)
	if err != nil {
		return nil, err
	}
	return &HygieneProducer{
		repo:   pgidentity.New(appDB),
		writer: w,
		now:    time.Now,
	}, nil
}

// HygieneRun is one full pass over one tenant.
type HygieneRun struct {
	// Raised is how many findings were upserted (created or re-observed).
	Raised int
	// Resolved is how many the sweep moved to INACTIVE.
	Resolved int
	// Assets, Endpoints, Installs and Relationships are how many of each the
	// pass read. Reported even at zero findings: "the inventory is tidy" and
	// "there is nothing in the inventory" are different answers.
	Assets        int
	Endpoints     int
	Installs      int
	Relationships int
	// Proposals is how many PENDING merge proposals the pass saw.
	Proposals int
	// Assessed is how many assets this pass claimed coverage of in
	// `producer_assessments` — every live asset it evaluated, which for this
	// producer is every live asset it read. Reported beside Raised because
	// "the inventory is tidy" is only readable next to "and this many records
	// were looked at".
	Assessed int

	// EndpointsMarkedStale / EndpointsMarkedActive are the endpoint status
	// transitions this pass wrote (see markEndpointStatus). Reported rather
	// than silent: a pass that moved four hundred endpoints to stale is either
	// a collector that stopped or a threshold somebody changed, and both are
	// things an operator should see in the run log rather than discover in a
	// filter.
	EndpointsMarkedStale  int
	EndpointsMarkedActive int
}

// hygieneAsset is one asset and everything the producer judges about it.
type hygieneAsset struct {
	id     uuid.UUID
	label  string
	status string

	classKey        string
	ownerPresent    bool
	locationPresent bool
	lastSeenAt      time.Time

	endpoints []hygieneChild
	installs  []hygieneChild
}

// hygieneChild is an endpoint or a software install, reduced to what the stale
// ladder needs.
type hygieneChild struct {
	id         uuid.UUID
	label      string
	lastSeenAt time.Time
	// status is the endpoint's stored `asset_endpoints.status`. Empty for a
	// software install, which has no such column on this path. It is read so
	// the status writer only writes rows that actually change state.
	status string
}

// hygieneEdge is one relationship whose other end has gone.
type hygieneEdge struct {
	id    uuid.UUID
	label string

	relType string
	// survivingID is the end that still exists, and is what the finding's
	// `evidence.asset_id` points at so the Findings drawer has somewhere to go.
	// Zero when BOTH ends are gone, which is possible and is recorded rather
	// than guessed at.
	survivingID    uuid.UUID
	survivingLabel string
	missingID      uuid.UUID
	missingLabel   string
	// missingReason is "archived" or "deleted".
	missingReason string
}

// hygieneProposal is one pending merge proposal, reduced to the assets it puts
// in question.
type hygieneProposal struct {
	id uuid.UUID
	// assetIDs is every asset the proposal names — the observation and every
	// candidate. Each gets a finding, because a suspected duplicate is a
	// statement about a PAIR and showing it on only one of them means the other
	// record looks fine from its own page.
	assetIDs []uuid.UUID
	reason   string
	at       time.Time
}

// Run executes the pass for one tenant.
//
// Read, plan, write. An error from the read phase returns WITHOUT sweeping: a
// pass that failed part way has not made a full statement about what it sees,
// and sweeping on a partial answer inactivates live findings and re-raises them
// tomorrow with their workflow status reset.
func (p *HygieneProducer) Run(ctx context.Context, tenantID uuid.UUID) (HygieneRun, error) {
	var run HygieneRun

	inv, err := p.read(ctx, tenantID, &run)
	if err != nil {
		return HygieneRun{}, fmt.Errorf("hygiene producer: reading tenant %s: %w", tenantID, err)
	}

	planned, err := p.plan(inv, &run)
	if err != nil {
		return HygieneRun{}, fmt.Errorf("hygiene producer: planning tenant %s: %w", tenantID, err)
	}

	if err := p.write(ctx, tenantID, inv, planned, &run); err != nil {
		return HygieneRun{}, fmt.Errorf("hygiene producer: writing tenant %s: %w", tenantID, err)
	}
	return run, nil
}

// hygieneInventory is everything one pass reads.
type hygieneInventory struct {
	assets    []hygieneAsset
	edges     []hygieneEdge
	proposals []hygieneProposal
}

// read loads the tenant's live inventory in one transaction.
func (p *HygieneProducer) read(ctx context.Context, tenantID uuid.UUID, run *HygieneRun) (*hygieneInventory, error) {
	inv := &hygieneInventory{}
	byID := map[uuid.UUID]*hygieneAsset{}
	var order []uuid.UUID

	err := p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		// The four asset-shape expressions are spelled here EXACTLY as
		// measurement_shapes.go's `asset` shape spells them — owner_present,
		// location_present, class_key, last_seen_at. They have to agree: the
		// Inventory Hygiene framework's IH-001..003 read those selectables and
		// this producer raises the findings beside them, and a control that
		// passes while the finding beside it is open is the kind of
		// disagreement nobody can debug from either end.
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id,
			       coalesce(nullif(a.display_name, ''), nullif(a.hostname, ''), host(a.primary_address), ''),
			       a.asset_status,
			       a.class_key,
			       (COALESCE(NULLIF(btrim(a.owner_email), ''), NULLIF(btrim(a.support_group), '')) IS NOT NULL),
			       (COALESCE(NULLIF(btrim(a.site), ''), NULLIF(btrim(a.region), ''), NULLIF(btrim(a.zone), ''), a.location_id::text) IS NOT NULL),
			       a.last_seen_at
			FROM assets a
			WHERE a.tenant_id = $1
			  AND a.deleted_at IS NULL
			  AND a.asset_status <> 'archived'`, tenantID)
		if err != nil {
			return fmt.Errorf("query assets: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a hygieneAsset
			if err := rows.Scan(&a.id, &a.label, &a.status, &a.classKey,
				&a.ownerPresent, &a.locationPresent, &a.lastSeenAt); err != nil {
				return fmt.Errorf("scan asset: %w", err)
			}
			cp := a
			byID[a.id] = &cp
			order = append(order, a.id)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// `status <> 'closed'`, not `status = 'active'`.
		//
		// This producer is what MOVES an endpoint between active and stale (see
		// markEndpointStatus), so reading only the active ones would make the
		// transition eat its own finding: the endpoint goes stale, disappears
		// from the next pass's read, is not re-upserted, and the sweep resolves
		// the very finding that described it. `closed` is excluded because it is
		// an authoritative statement from a host inventory that the socket is
		// gone — a closed endpoint is not a record that went quiet, it is one
		// somebody answered about.
		eRows, err := tx.QueryContext(ctx, `
			SELECT e.id, e.asset_id,
			       coalesce(host(e.address), ''), coalesce(e.fqdn, ''),
			       coalesce(e.port, 0), e.transport, e.last_seen_at, e.status
			FROM asset_endpoints e
			WHERE e.tenant_id = $1 AND e.status <> 'closed'`, tenantID)
		if err != nil {
			return fmt.Errorf("query endpoints: %w", err)
		}
		defer func() { _ = eRows.Close() }()
		for eRows.Next() {
			var assetID uuid.UUID
			var c hygieneChild
			var addr, fqdn, transport string
			var port int
			if err := eRows.Scan(&c.id, &assetID, &addr, &fqdn, &port, &transport,
				&c.lastSeenAt, &c.status); err != nil {
				return fmt.Errorf("scan endpoint: %w", err)
			}
			c.label = endpointLabel(addr, fqdn, port, transport)
			if a, ok := byID[assetID]; ok {
				a.endpoints = append(a.endpoints, c)
			}
		}
		if err := eRows.Err(); err != nil {
			return err
		}

		iRows, err := tx.QueryContext(ctx, `
			SELECT si.id, si.asset_id, sp.name, coalesce(sp.version, ''), si.last_seen_at
			FROM software_installs si
			JOIN software_products sp ON sp.tenant_id = si.tenant_id AND sp.id = si.product_id
			WHERE si.tenant_id = $1 AND si.status = 'active'`, tenantID)
		if err != nil {
			return fmt.Errorf("query software installs: %w", err)
		}
		defer func() { _ = iRows.Close() }()
		for iRows.Next() {
			var assetID uuid.UUID
			var c hygieneChild
			var name, version string
			if err := iRows.Scan(&c.id, &assetID, &name, &version, &c.lastSeenAt); err != nil {
				return fmt.Errorf("scan software install: %w", err)
			}
			c.label = strings.TrimSpace(name + " " + version)
			if a, ok := byID[assetID]; ok {
				a.installs = append(a.installs, c)
			}
		}
		if err := iRows.Err(); err != nil {
			return err
		}

		edges, err := readOrphanEdges(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		inv.edges = edges

		proposals, err := readPendingProposals(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		inv.proposals = proposals
		return nil
	})
	if err != nil {
		return nil, err
	}

	inv.assets = make([]hygieneAsset, 0, len(order))
	for _, id := range order {
		a := *byID[id]
		run.Assets++
		run.Endpoints += len(a.endpoints)
		run.Installs += len(a.installs)
		inv.assets = append(inv.assets, a)
	}
	run.Relationships = len(inv.edges)
	run.Proposals = len(inv.proposals)
	return inv, nil
}

// readOrphanEdges finds relationships whose other end is archived or deleted.
//
// A LEFT JOIN on both ends, because the row can be orphaned three ways: the
// asset is soft-deleted, the asset is archived, or (in principle) the join
// finds nothing at all. The foreign keys cascade on a HARD delete, so the third
// case should be unreachable — it is still handled rather than assumed away,
// because an edge pointing at nothing is precisely what this kind is for and an
// unreachable case that happens is one nobody would see.
//
// Rejected edges are excluded: a relationship somebody looked at and said no to
// is a decision, not a dangling pointer.
func readOrphanEdges(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) ([]hygieneEdge, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.id, r.type, r.from_asset_id, r.to_asset_id,
		       coalesce(nullif(fa.display_name, ''), nullif(fa.hostname, ''), ''),
		       (fa.id IS NULL), (fa.deleted_at IS NOT NULL), coalesce(fa.asset_status, ''),
		       coalesce(nullif(ta.display_name, ''), nullif(ta.hostname, ''), ''),
		       (ta.id IS NULL), (ta.deleted_at IS NOT NULL), coalesce(ta.asset_status, '')
		FROM asset_relationships r
		LEFT JOIN assets fa ON fa.tenant_id = r.tenant_id AND fa.id = r.from_asset_id
		LEFT JOIN assets ta ON ta.tenant_id = r.tenant_id AND ta.id = r.to_asset_id
		WHERE r.tenant_id = $1
		  AND r.status <> 'rejected'
		  AND (fa.id IS NULL OR fa.deleted_at IS NOT NULL OR fa.asset_status = 'archived'
		    OR ta.id IS NULL OR ta.deleted_at IS NOT NULL OR ta.asset_status = 'archived')`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query relationships: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []hygieneEdge
	for rows.Next() {
		var e hygieneEdge
		var fromID, toID uuid.UUID
		var fromLabel, toLabel, fromStatus, toStatus string
		var fromAbsent, fromDeleted, toAbsent, toDeleted bool
		if err := rows.Scan(&e.id, &e.relType, &fromID, &toID,
			&fromLabel, &fromAbsent, &fromDeleted, &fromStatus,
			&toLabel, &toAbsent, &toDeleted, &toStatus); err != nil {
			return nil, fmt.Errorf("scan relationship: %w", err)
		}

		fromGone, fromWhy := edgeEndGone(fromAbsent, fromDeleted, fromStatus)
		toGone, toWhy := edgeEndGone(toAbsent, toDeleted, toStatus)

		// Name the MISSING end and the SURVIVING one. When both are gone the
		// surviving id stays zero: the finding then says so instead of linking
		// to something that is not there either.
		switch {
		case toGone:
			e.missingID, e.missingLabel, e.missingReason = toID, orLabel(toLabel, toID), toWhy
			if !fromGone {
				e.survivingID, e.survivingLabel = fromID, orLabel(fromLabel, fromID)
			}
		case fromGone:
			e.missingID, e.missingLabel, e.missingReason = fromID, orLabel(fromLabel, fromID), fromWhy
			e.survivingID, e.survivingLabel = toID, orLabel(toLabel, toID)
		default:
			// The WHERE clause put this row here, so one end must be gone. If
			// neither is, the predicate and this reader disagree and the safe
			// answer is to say nothing rather than to raise a finding whose
			// content we cannot fill in.
			continue
		}
		e.label = orLabel(fromLabel, fromID) + " " + e.relType + " " + orLabel(toLabel, toID)
		out = append(out, e)
	}
	return out, rows.Err()
}

// edgeEndGone reads one end's three columns into "is it gone, and why".
func edgeEndGone(absent, deleted bool, status string) (bool, string) {
	switch {
	case absent:
		return true, "missing"
	case deleted:
		return true, "deleted"
	case status == "archived":
		return true, "archived"
	default:
		return false, ""
	}
}

// readPendingProposals reads the merge proposals still awaiting a decision.
//
// A merge proposal is an `asset_history` row, not a table (see
// services/merge_proposal_service.go): action `merge_proposed`,
// `changes_json.kind = 'merge_proposal'`, status pending. This reader uses the
// SAME predicate the Approvals queue counts with, so the finding and the queue
// can never disagree about how many there are.
//
// Newest first, which is what makes the per-asset dedupe below deterministic:
// an asset named by two proposals carries the finding for the newer one.
func readPendingProposals(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) ([]hygieneProposal, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, asset_id, changes_json::text, created_at
		FROM asset_history
		WHERE tenant_id = $1
		  AND action = $2
		  AND changes_json->>'kind' = 'merge_proposal'
		  AND COALESCE(changes_json->>'status', 'pending') = 'pending'
		ORDER BY created_at DESC, seq DESC`,
		tenantID, string(identity.ActionMergeProposed))
	if err != nil {
		return nil, fmt.Errorf("query merge proposals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []hygieneProposal
	for rows.Next() {
		var (
			id       uuid.UUID
			subject  uuid.UUID
			payload  string
			proposed time.Time
		)
		if err := rows.Scan(&id, &subject, &payload, &proposed); err != nil {
			return nil, fmt.Errorf("scan merge proposal: %w", err)
		}
		var body struct {
			Reason             string `json:"reason"`
			ObservationAssetID string `json:"observation_asset_id"`
			Candidates         []struct {
				AssetID string `json:"asset_id"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal([]byte(payload), &body); err != nil {
			// A corrupt payload is not a reason to fail the pass: the row is
			// somebody else's to fix, and losing every hygiene finding in the
			// tenant over one unparseable history entry would be a far worse
			// outcome than one missing duplicate warning.
			continue
		}

		prop := hygieneProposal{id: id, reason: body.Reason, at: proposed}
		seen := map[uuid.UUID]bool{}
		add := func(raw string) {
			parsed, err := uuid.Parse(raw)
			if err != nil || parsed == uuid.Nil || seen[parsed] {
				return
			}
			seen[parsed] = true
			prop.assetIDs = append(prop.assetIDs, parsed)
		}
		// The history row's own asset_id is the subject the engine hung the
		// proposal off — the observation asset when there is one, otherwise the
		// first candidate. It is included because a proposal opened without
		// creating an asset records the observation nowhere else.
		add(subject.String())
		add(body.ObservationAssetID)
		for _, c := range body.Candidates {
			add(c.AssetID)
		}
		if len(prop.assetIDs) < 2 {
			// One asset is not a duplicate of anything. A proposal that names
			// only one live asset has already been half-resolved elsewhere; the
			// finding would have no `{detail}` to render.
			continue
		}
		out = append(out, prop)
	}
	return out, rows.Err()
}

// plannedHygiene is one finding the plan phase decided on.
type plannedHygiene struct {
	finding producer.Finding
}

// plan turns the read inventory into findings. No I/O.
func (p *HygieneProducer) plan(inv *hygieneInventory, run *HygieneRun) ([]plannedHygiene, error) {
	var planned []plannedHygiene
	now := p.now().UTC()

	labels := make(map[uuid.UUID]string, len(inv.assets))
	live := make(map[uuid.UUID]bool, len(inv.assets))
	for _, a := range inv.assets {
		labels[a.id] = orLabel(a.label, a.id)
		live[a.id] = true
	}

	for _, a := range inv.assets {
		label := labels[a.id]
		subject := producer.Subject{Type: findings.SubjectAsset, ID: a.id}

		// The four record-quality kinds are for accepted inventory only. See
		// the type comment: a record still in Approvals has not been taken into
		// the estate, and the Inventory Hygiene controls scope themselves the
		// same way.
		if a.status == assetStatusMonitoring {
			if !a.ownerPresent {
				f, err := p.fixed(findings.KindNoOwner, subject, label, "", map[string]any{
					"owner_email_present":   false,
					"support_group_present": false,
				})
				if err != nil {
					return nil, err
				}
				planned = append(planned, plannedHygiene{finding: f})
			}
			if isPlaceholderClass(a.classKey) {
				f, err := p.fixed(findings.KindNoClass, subject, label, "", map[string]any{
					"class_key": a.classKey,
				})
				if err != nil {
					return nil, err
				}
				planned = append(planned, plannedHygiene{finding: f})
			}
			if !a.locationPresent {
				f, err := p.fixed(findings.KindNoLocation, subject, label, "", map[string]any{
					"site_present":     false,
					"region_present":   false,
					"zone_present":     false,
					"location_present": false,
				})
				if err != nil {
					return nil, err
				}
				planned = append(planned, plannedHygiene{finding: f})
			}

			if f, ok, err := p.stale(now, findings.SubjectAsset, a.id, label, a.lastSeenAt, nil); err != nil {
				return nil, err
			} else if ok {
				planned = append(planned, plannedHygiene{finding: f})
			}
			for _, c := range a.endpoints {
				if f, ok, err := p.stale(now, findings.SubjectEndpoint, c.id, c.label, c.lastSeenAt, &a); err != nil {
					return nil, err
				} else if ok {
					planned = append(planned, plannedHygiene{finding: f})
				}
			}
			for _, c := range a.installs {
				if f, ok, err := p.stale(now, findings.SubjectSoftwareInstall, c.id, c.label, c.lastSeenAt, &a); err != nil {
					return nil, err
				} else if ok {
					planned = append(planned, plannedHygiene{finding: f})
				}
			}
		}
	}

	// One finding per asset per PENDING proposal, newest proposal winning where
	// an asset is named by several. The unique index allows one open row per
	// (producer, kind, subject), so the dedupe is not an optimisation — without
	// it the second upsert would overwrite the first and the surviving evidence
	// would depend on iteration order.
	claimed := map[uuid.UUID]bool{}
	for _, prop := range inv.proposals {
		for _, id := range prop.assetIDs {
			if !live[id] || claimed[id] {
				continue
			}
			others := make([]string, 0, len(prop.assetIDs)-1)
			otherLabel := ""
			for _, other := range prop.assetIDs {
				if other == id {
					continue
				}
				others = append(others, other.String())
				if otherLabel == "" {
					if l, ok := labels[other]; ok {
						otherLabel = l
					} else {
						otherLabel = shortID(other)
					}
				}
			}
			claimed[id] = true

			f, err := p.fixed(findings.KindDuplicateSuspected,
				producer.Subject{Type: findings.SubjectAsset, ID: id}, labels[id], otherLabel,
				map[string]any{
					"proposal_id":     prop.id.String(),
					"other_asset_ids": others,
					"reason":          prop.reason,
					"proposed_at":     prop.at.UTC().Format(time.RFC3339),
				})
			if err != nil {
				return nil, err
			}
			planned = append(planned, plannedHygiene{finding: f})
		}
	}

	for _, e := range inv.edges {
		evidence := map[string]any{
			"relationship_type":   e.relType,
			"missing_asset_id":    e.missingID.String(),
			"missing_asset_label": e.missingLabel,
			"missing_reason":      e.missingReason,
		}
		if e.survivingID != uuid.Nil {
			evidence["surviving_asset_id"] = e.survivingID.String()
			evidence["surviving_asset_label"] = e.survivingLabel
			// `asset_id` is what the Findings drawer and the ticket mapping
			// read to find somewhere to go from a subject that has no page of
			// its own. A relationship is one of those.
			evidence["asset_id"] = e.survivingID.String()
		}
		f, err := p.fixed(findings.KindOrphanRelationship,
			producer.Subject{Type: findings.SubjectRelationship, ID: e.id}, e.label, "", evidence)
		if err != nil {
			return nil, err
		}
		planned = append(planned, plannedHygiene{finding: f})
	}

	return planned, nil
}

// assetStatusMonitoring is the one `assets.asset_status` value that means "in
// the estate, accepted". Spelled once here so the split described on
// [HygieneProducer] is one string and not four.
const assetStatusMonitoring = "monitoring"

// fixed builds a finding at the registry's severity and score for a fixed kind.
func (p *HygieneProducer) fixed(kind string, subject producer.Subject, label, detail string, evidence map[string]any) (producer.Finding, error) {
	k, ok := findings.Get(findings.ProducerHygiene, kind)
	if !ok {
		return producer.Finding{}, fmt.Errorf("hygiene producer: %q is not in the findings registry", kind)
	}
	return producer.Finding{
		Kind:         kind,
		Subject:      subject,
		SubjectLabel: label,
		Severity:     k.DefaultSeverity,
		Score:        k.Score,
		Summary:      renderTemplate(k.TitleTemplate, label, detail),
		Evidence:     evidence,
		// measured: every one of these is read straight off the inventory row.
		// Nothing was imported and nothing was inferred.
		SourceKind: producer.SourceMeasured,
	}, nil
}

// stale builds the ladder finding for one subject, or reports that there is
// none.
//
// `parent` is the asset an endpoint or install belongs to, and is nil for the
// asset itself. It is what puts `evidence.asset_id` on a child's finding, so
// the drawer can reach the host: neither an endpoint nor a software install has
// a page of its own.
func (p *HygieneProducer) stale(now time.Time, subjectType string, id uuid.UUID, label string, lastSeen time.Time, parent *hygieneAsset) (producer.Finding, bool, error) {
	if lastSeen.IsZero() {
		// Never observed at all. That is not staleness — it is an absence of
		// the measurement staleness is computed FROM, and dating it to the Unix
		// epoch would report a record created this morning as 20,000 days
		// stale. The column is NOT NULL with a now() default, so this should be
		// unreachable; it is handled because the alternative failure is loud,
		// wrong and in front of a customer.
		return producer.Finding{}, false, nil
	}
	days := daysBetween(lastSeen, now)
	rung, idx, ok := staleRungFor(days)
	if !ok {
		return producer.Finding{}, false, nil
	}
	r, err := producer.Rung(findings.ProducerHygiene, findings.KindStale, idx)
	if err != nil {
		return producer.Finding{}, false, err
	}

	evidence := map[string]any{
		"days_unseen":  days,
		"last_seen_at": lastSeen.UTC().Format(time.RFC3339),
		"rung_days":    rung,
		"subject_type": subjectType,
	}
	if parent != nil {
		evidence["asset_id"] = parent.id.String()
		evidence["asset_label"] = orLabel(parent.label, parent.id)
	}

	k, _ := findings.Get(findings.ProducerHygiene, findings.KindStale)
	return producer.Finding{
		Kind:         findings.KindStale,
		Subject:      producer.Subject{Type: subjectType, ID: id},
		SubjectLabel: label,
		Severity:     r.Severity,
		Score:        r.Score,
		Summary:      renderTemplate(k.TitleTemplate, label, staleDetail(rung)),
		Evidence:     evidence,
		SourceKind:   producer.SourceMeasured,
	}, true, nil
}

// write commits the run: every finding, the coverage claim, then the sweep —
// one transaction, because a sweep that lands without its upserts inactivates
// live findings, and a coverage claim that outlives the rollback of the
// findings justifying it reads "assessed, nothing found" forever.
//
// It writes nothing to `assets`. `assets.risk_assessed_by` is the RISK-feeding
// subset of the coverage record, derived by the rollup; every hygiene kind is
// `feeds_risk: false`, so this producer must never appear there — the inventory
// UI reads a non-empty array as "the risk score is a real answer"
// (`assetRisk` in asset-shape.ts, and the `not_assessed` facet arm in
// asset_facets_queries.go), and an asset whose only evaluation was a missing
// owner has not had its risk assessed. `producer_assessments` is the full
// record and is where this claim belongs; the compliance `finding` shape reads
// THAT, which is what makes IH-005 and IH-006 answerable.
func (p *HygieneProducer) write(ctx context.Context, tenantID uuid.UUID, inv *hygieneInventory, planned []plannedHygiene, run *HygieneRun) error {
	seen := map[string][]producer.Subject{}
	for _, kind := range hygieneKinds {
		seen[kind] = nil
	}

	return p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		for _, plan := range planned {
			if _, err := p.writer.Upsert(ctx, tx, tenantID, plan.finding); err != nil {
				return err
			}
			run.Raised++
			seen[plan.finding.Kind] = append(seen[plan.finding.Kind], plan.finding.Subject)
		}

		// The coverage claim. EVERY live asset the pass read, because this
		// producer forms an opinion about all of them: the questions it asks —
		// is the record owned, classified, located, recently seen, unique, are
		// its edges intact — are answerable from the row itself, so there is no
		// "nothing to look up" case the way there is for a catalogue producer.
		// An archived or soft-deleted asset is not read at all and so is not
		// claimed.
		ids := make([]uuid.UUID, 0, len(inv.assets))
		for _, a := range inv.assets {
			ids = append(ids, a.id)
		}
		assessed, err := p.writer.MarkAssessed(ctx, tx, tenantID, ids)
		if err != nil {
			return err
		}
		run.Assessed = assessed

		if err := p.markEndpointStatus(ctx, tx, tenantID, inv, run); err != nil {
			return err
		}

		for _, kind := range hygieneKinds {
			n, err := p.writer.Sweep(ctx, tx, tenantID, kind, seen[kind])
			if err != nil {
				return err
			}
			run.Resolved += n
		}

		return nil
	})
}

// endpoint status values, mirroring asset_endpoints_status_check.
const (
	endpointActive = "active"
	endpointStale  = "stale"
)

// markEndpointStatus is the writer for `asset_endpoints.status = 'stale'`.
//
// # Why it is here
//
// The CHECK constraint has allowed three values since the table was written and
// only two of them were ever written: `active` on every observation, `closed`
// by the host-inventory intake when an agent's collection stops reporting a
// socket it previously reported. `stale` had NO writer at all, so a query
// filtering on it returned nothing and a reader of the column could not tell
// "this endpoint went quiet" from "this endpoint is fine" — the same
// three-valued collapse the findings rail exists to prevent, one table down.
//
// It belongs to this producer because this producer already owns the question:
// it reads every endpoint's `last_seen_at` in order to raise the `stale` ladder
// finding, and the column is that ladder's FIRST RUNG expressed as state. One
// definition, two renderings — a status a query can filter on and a finding a
// person can triage. A separate sweep job would be a second opinion about
// staleness, which is exactly how the Inventory lens and the ladder came to
// disagree in the first place (see staleLadderDays).
//
// # The state machine
//
//	active to stale   nothing has observed the endpoint for staleLadderDays[0]
//	                  days. Not a claim that the socket is gone; a claim that
//	                  nothing has looked recently.
//	stale to active   something observed it again inside the window. Staleness
//	                  is a property of the last observation, not a flag that
//	                  sticks.
//	anything to closed — NEVER from here. `closed` is an authoritative negative:
//	                  a host said the socket is not listening. A time-based rule
//	                  overruling a measurement is the port-heuristic mistake
//	                  wearing different clothes. Only the host-inventory intake
//	                  writes it, and this pass does not even read those rows.
//
// Both UPDATEs are guarded on the CURRENT status as well as on the date, so a
// converged pass writes no rows at all rather than bumping `updated_at` across
// the whole table every night.
func (p *HygieneProducer) markEndpointStatus(ctx context.Context, tx *sql.Tx,
	tenantID uuid.UUID, inv *hygieneInventory, run *HygieneRun) error {
	cutoff := p.now().UTC().AddDate(0, 0, -staleLadderDays[0])

	var toStale, toActive []uuid.UUID
	for _, a := range inv.assets {
		for _, c := range a.endpoints {
			if c.lastSeenAt.IsZero() {
				// Never observed. Not staleness — it is the absence of the
				// measurement staleness is computed FROM. Same reasoning as
				// [HygieneProducer.stale].
				continue
			}
			switch {
			case c.status == endpointActive && c.lastSeenAt.Before(cutoff):
				toStale = append(toStale, c.id)
			case c.status == endpointStale && !c.lastSeenAt.Before(cutoff):
				toActive = append(toActive, c.id)
			}
		}
	}

	for _, step := range []struct {
		ids  []uuid.UUID
		to   string
		from string
	}{
		{toStale, endpointStale, endpointActive},
		{toActive, endpointActive, endpointStale},
	} {
		if len(step.ids) == 0 {
			continue
		}
		ids := make([]string, 0, len(step.ids))
		for _, id := range step.ids {
			ids = append(ids, id.String())
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE asset_endpoints
			   SET status = $3, updated_at = now()
			 WHERE tenant_id = $1
			   AND id = ANY($2::uuid[])
			   AND status = $4`,
			tenantID, pq.Array(ids), step.to, step.from)
		if err != nil {
			return fmt.Errorf("mark endpoints %s: %w", step.to, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("mark endpoints %s: %w", step.to, err)
		}
		if step.to == endpointStale {
			run.EndpointsMarkedStale = int(n)
		} else {
			run.EndpointsMarkedActive = int(n)
		}
	}
	return nil
}

// hygieneKinds is every kind this producer emits, which is also every kind it
// sweeps. Derived from the registry rather than listed, so a kind added to the
// `hygiene` producer without a sweep here is impossible.
var hygieneKinds = func() []string {
	var out []string
	for _, k := range findings.All {
		if k.Producer == findings.ProducerHygiene {
			out = append(out, k.Key)
		}
	}
	return out
}()

// ---------------------------------------------------------------- the ladder

// The stale ladder, in days.
//
// Same division of labour as the end-of-life ladder in ladder.go: the REGISTRY
// owns what a rung means (its severity and its 0-100 score) and the writer
// refuses any pair that is not one of its rungs verbatim; the PRODUCER owns
// where the boundaries fall, because `threshold` is free text in the producer's
// own units and parsing an integer back out of an English sentence would make a
// typo in the YAML a silent change of behaviour.
//
// [TestStaleLadderMatchesRegistry] asserts the two still describe the same
// ladder — rung count, severities, scores and threshold wording.
//
// 30 is also IH-004's threshold in the seeded Inventory Hygiene framework
// (`last_seen_days <= 30`), deliberately: the control and the finding beside it
// must agree about when a record has gone quiet.
//
// Note what these are NOT. The Inventory page's Stale lens cuts at 14 days,
// which is a BROWSING default — "show me what has gone quiet lately" — not a
// judgement that 14 days is a problem. A finding is a judgement, and it starts
// where the framework says it starts.
var staleLadderDays = []int{30, 90, 180}

// staleRungFor picks the rung for a subject unseen for `days`, returning the
// rung's day boundary and its index.
//
// Worst-last, and searched from the worst end: a subject unseen for 200 days is
// on the 180 rung, not on all three.
func staleRungFor(days int) (int, int, bool) {
	for i := len(staleLadderDays) - 1; i >= 0; i-- {
		if days >= staleLadderDays[i] {
			return staleLadderDays[i], i, true
		}
	}
	return 0, 0, false
}

// staleDetail is the `{detail}` the registry's title_template substitutes.
//
// The RUNG's boundary, not the exact day count, and that is deliberate: the
// exact count changes every night, so a summary built from it would rewrite
// every open stale finding's text on every pass and make the history unreadable
// for no information gain. The exact number is in `evidence.days_unseen`, where
// a reader who wants it can have it.
func staleDetail(rungDays int) string {
	return "more than " + strconv.Itoa(rungDays) + " days"
}

// daysBetween is whole days from `from` to `to`, counting CALENDAR days in UTC
// rather than 24-hour periods — the same rule daysUntil uses for end-of-life
// dates, and for the same reason: a record does not become stale eleven hours
// early because the pass started in the afternoon.
func daysBetween(from, to time.Time) int {
	f := time.Date(from.UTC().Year(), from.UTC().Month(), from.UTC().Day(), 0, 0, 0, 0, time.UTC)
	t := time.Date(to.UTC().Year(), to.UTC().Month(), to.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return int(t.Sub(f).Hours() / 24)
}

// ------------------------------------------------------------------ classes

// placeholderClasses are the class keys that mean "nothing has decided what
// this is".
//
// There is exactly one, and the taxonomy is where that is decided:
// standards/asset-classes.yaml carries no `placeholder` flag, and its model
// section says every class is assignable — "classifying a box as `hardware`
// when we know no more than that is the honest answer; the class is what tells
// the user how much is known". So an asset on `hardware` is classified, coarsely
// and truthfully, and is NOT a hygiene finding.
//
// `unknown_host` is the exception the taxonomy itself describes as "a real asset
// with a real gap" — and it is the class the seeded IH-002 control already
// matches on (`^unknown_host$`). The two must agree, which is what
// [TestPlaceholderClassesAreRealClasses] and the IH-002 integration test check
// from both ends.
var placeholderClasses = map[string]bool{
	assetclass.KeyUnknownHost: true,
}

// isPlaceholderClass reports whether a class key means "unclassified".
//
// An EMPTY key counts. The column is NOT NULL, so it should be unreachable —
// but an empty string is the one value that is neither a real class nor
// unknown_host, and letting it fall through would make the least-classified
// asset in the estate the only one with no finding.
func isPlaceholderClass(key string) bool {
	k := strings.TrimSpace(key)
	return k == "" || placeholderClasses[k]
}

// ------------------------------------------------------------------ helpers

// orLabel falls back to a short id when nothing names a row.
//
// A finding whose subject_label is blank renders as a blank in the Findings
// list, which reads as a bug rather than as an unnamed asset. Eight hex
// characters is enough to tell two rows apart on screen and to paste into a
// search.
func orLabel(label string, id uuid.UUID) string {
	if s := strings.TrimSpace(label); s != "" {
		return s
	}
	return shortID(id)
}

func shortID(id uuid.UUID) string {
	s := id.String()
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
