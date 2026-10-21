package producers

// The DCIM half of the hygiene producer (DCIM gap 6).
//
// The DCIM model added placement, cabling, interfaces, addressing and the
// commercial lifecycle to the asset record, and none of it was measured. These
// nine kinds ask whether that part of the record is sound, in the same pass and
// under the same rules as the six record-quality kinds in hygiene.go:
//
//	not_racked            a rack-mountable hardware asset with no rack
//	no_rack_position      a rack but no unit position
//	planned_cable_stale   a cable still planned 90 days after it was created
//	cable_unconfirmed     a declared cable LLDP/CDP has not confirmed in 30
//	                      days, on an asset that DID report neighbours
//	interface_no_type     an active interface typed `other` or not at all
//	duplicate_address     an address shared with another asset in one VRF
//	warranty_expired      warranty_end is in the past
//	past_end_of_support   the effective end of support is in the past
//	end_of_support_soon   it falls within the next 12 months
//
// Every one is raised on the ASSET — even the cable and interface kinds, whose
// evidence lists the cables or interfaces — because the Inventory Hygiene
// framework's `finding`-shape measurements (IH-007 to IH-015) count findings
// per asset, and `findings_open_subject_uniq` allows one open row per
// (producer, kind, subject): one finding per asset per kind, whatever the
// number of offending rows under it.
//
// # Three-valued, on both sides
//
// Each question is asked only where the record holds the data it is about. A
// missing warranty date is not an expired warranty; a device type nobody set
// is not a rack-mountable device; a port nobody hears a neighbour on is not a
// contradicted cable. None of those raises anything here, and the matching
// measurement's `subject_where` in standards/measurement-types.yaml narrows
// the control to the same population, so the control reads NOT ASSESSED for
// those assets rather than compliant.
//
// # One lifecycle rule
//
// Warranty and end-of-support states are decided by
// services.ComputeAssetLifecycle — the function the asset reads and the
// Hardware tab's Lifecycle card use — from the same five inputs. This file
// only reads the inputs; it never re-decides what "expired" or "within 12
// months" means.
//
// Scope matches the record-quality kinds: monitored (accepted), live assets,
// minus any whose decommissioned_at has arrived — an asset that has left
// service is not a hygiene problem for its rack or its warranty.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// plannedCableStaleDays is how long a cable may stay planned before IH-009
// calls the plan abandoned.
const plannedCableStaleDays = 90

// neighbourWindowDays is IH-010's window: both how recently the asset must
// have reported neighbours for the question to be asked, and how long a
// declared cable may go unconfirmed.
const neighbourWindowDays = 30

// dcimEvidenceCap bounds the rows one finding's evidence lists. The count is
// always exact; the list is for a person to start from, and a switch with
// four hundred untyped ports does not need four hundred names in a jsonb.
const dcimEvidenceCap = 50

// nonUniqueAddressRoles are the address roles that may be shared between
// devices on purpose — NetBox's IPADDRESS_ROLES_NONUNIQUE, a subset of
// standards/netbox-choices.v4.3.5.json's ipaddress role set (and of
// ip_addresses_role_check).
var nonUniqueAddressRoles = []string{"anycast", "vip", "vrrp", "hsrp", "glbp", "carp"}

// dcimHit is one finding the DCIM reads decided on, before it is built.
type dcimHit struct {
	kind     string
	assetID  uuid.UUID
	detail   string
	evidence map[string]any
}

// dcimAssetScope is the asset predicate every DCIM read shares: $1 is the
// tenant, $2 today's date. Spelled once so the nine reads cannot disagree
// about which assets are in scope.
const dcimAssetScope = `a.tenant_id = $1
		  AND a.deleted_at IS NULL
		  AND a.asset_status = 'monitoring'
		  AND (a.decommissioned_at IS NULL OR a.decommissioned_at > $2::date)`

// readDCIMHygiene runs the nine DCIM questions in the pass's read
// transaction. Each is one set-based statement.
func readDCIMHygiene(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, now time.Time) ([]dcimHit, error) {
	today := now.UTC().Format("2006-01-02")
	var out []dcimHit
	for _, read := range []func(context.Context, *sql.Tx, uuid.UUID, string, time.Time) ([]dcimHit, error){
		readNotRacked,
		readNoRackPosition,
		readPlannedCableStale,
		readCableUnconfirmed,
		readInterfaceNoType,
		readDuplicateAddress,
		readCommercialLifecycle,
	} {
		hits, err := read(ctx, tx, tenantID, today, now)
		if err != nil {
			return nil, err
		}
		out = append(out, hits...)
	}
	return out, nil
}

// readNotRacked: hardware, a device type taller than 0 U, not a child in a
// parent's bay (a blade occupies no units), and no rack.
func readNotRacked(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, _ time.Time) ([]dcimHit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, dt.id, dt.model, dt.u_height::float8
		FROM assets a
		JOIN device_types dt ON dt.id = a.device_type_id
		WHERE `+dcimAssetScope+`
		  AND dt.u_height > 0
		  AND (a.class_path = 'hardware' OR a.class_path LIKE 'hardware.%')
		  AND a.rack_id IS NULL
		  AND a.parent_asset_id IS NULL
		ORDER BY a.id`, tenantID, today)
	if err != nil {
		return nil, fmt.Errorf("query unracked assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []dcimHit
	for rows.Next() {
		var assetID, dtID uuid.UUID
		var model string
		var height float64
		if err := rows.Scan(&assetID, &dtID, &model, &height); err != nil {
			return nil, fmt.Errorf("scan unracked asset: %w", err)
		}
		u := strconv.FormatFloat(height, 'f', -1, 64) + " U"
		out = append(out, dcimHit{
			kind: findings.KindNotRacked, assetID: assetID,
			detail: model + ", " + u,
			evidence: map[string]any{
				"device_type_id": dtID.String(),
				"device_type":    model,
				"u_height":       height,
			},
		})
	}
	return out, rows.Err()
}

// readNoRackPosition: a rack and no position. A 0 U device type (a vertical
// PDU, a cable manager) and a child in a bay have no position by design — the
// same rule NetBox applies — so they are not reported. An asset with NO
// device type is reported: nothing says it is 0 U.
func readNoRackPosition(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, _ time.Time) ([]dcimHit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, r.id, r.name
		FROM assets a
		JOIN racks r ON r.tenant_id = a.tenant_id AND r.id = a.rack_id
		LEFT JOIN device_types dt ON dt.id = a.device_type_id
		WHERE `+dcimAssetScope+`
		  AND a.position IS NULL
		  AND a.parent_asset_id IS NULL
		  AND (dt.id IS NULL OR dt.u_height > 0)
		ORDER BY a.id`, tenantID, today)
	if err != nil {
		return nil, fmt.Errorf("query unpositioned assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []dcimHit
	for rows.Next() {
		var assetID, rackID uuid.UUID
		var rack string
		if err := rows.Scan(&assetID, &rackID, &rack); err != nil {
			return nil, fmt.Errorf("scan unpositioned asset: %w", err)
		}
		out = append(out, dcimHit{
			kind: findings.KindNoRackPosition, assetID: assetID, detail: rack,
			evidence: map[string]any{"rack_id": rackID.String(), "rack": rack},
		})
	}
	return out, rows.Err()
}

// readPlannedCableStale: planned cables created more than 90 days ago, on the
// asset at the cable's A end — the B end when the A end is not an asset (a
// circuit termination) — so each lands on exactly one asset.
func readPlannedCableStale(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, now time.Time) ([]dcimHit, error) {
	cutoff := now.UTC().AddDate(0, 0, -plannedCableStaleDays)
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, c.id, COALESCE(c.label, ''), c.created_at
		FROM cables c
		CROSS JOIN LATERAL (
			SELECT t.asset_id
			FROM cable_terminations t
			WHERE t.tenant_id = c.tenant_id AND t.cable_id = c.id AND t.asset_id IS NOT NULL
			ORDER BY t.cable_end, t.created_at, t.id
			LIMIT 1) owner_end
		JOIN assets a ON a.tenant_id = c.tenant_id AND a.id = owner_end.asset_id
		WHERE c.tenant_id = $1
		  AND c.operational_status = 'planned'
		  AND c.status NOT IN ('rejected', 'archived')
		  AND c.created_at < $3
		  AND `+dcimAssetScope+`
		ORDER BY a.id, c.created_at, c.id`, tenantID, today, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query stale planned cables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	g := newAssetGroups()
	for rows.Next() {
		var assetID, cableID uuid.UUID
		var label string
		var created time.Time
		if err := rows.Scan(&assetID, &cableID, &label, &created); err != nil {
			return nil, fmt.Errorf("scan stale planned cable: %w", err)
		}
		g.add(assetID, map[string]any{
			"cable_id":   cableID.String(),
			"label":      label,
			"created_at": created.UTC().Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.hits(findings.KindPlannedCableStale, "planned cable", "planned cables", "cables"), nil
}

// readCableUnconfirmed: a declared (or imported), connected cable on one of
// the asset's interfaces that has existed for 30 days with no LLDP or CDP
// confirmation in that time — asked ONLY of an asset that reported neighbour
// data in the same 30 days.
//
// The neighbour table itself is not stored; what an LLDP/CDP observation
// leaves behind is (services/cable_intake.go): a cable it confirmed
// (`lldp_confirmed_at`), a measured cable it proposed or keeps confirming
// (`last_seen_at`), a parked unresolved termination from producer lldp/cdp,
// or the asset's topology cable_drift finding. Any of the four within the
// window is "this asset reports neighbours". None of them is "no data", and a
// cable on such an asset is not judged at all.
func readCableUnconfirmed(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, now time.Time) ([]dcimHit, error) {
	since := now.UTC().AddDate(0, 0, -neighbourWindowDays)
	rows, err := tx.QueryContext(ctx, `
		WITH heard AS (
			SELECT t.asset_id
			FROM cable_terminations t
			JOIN cables c ON c.tenant_id = t.tenant_id AND c.id = t.cable_id
			WHERE t.tenant_id = $1 AND t.asset_id IS NOT NULL AND t.termination_kind = 'interface'
			  AND (c.lldp_confirmed_at >= $3 OR (c.source_kind = 'measured' AND c.last_seen_at >= $3))
			UNION
			SELECT i.asset_id
			FROM unresolved_terminations u
			JOIN interfaces i ON i.tenant_id = u.tenant_id AND i.id = u.origin_id
			WHERE u.tenant_id = $1 AND u.origin_kind = 'interface'
			  AND u.producer = ANY($4) AND u.last_seen_at >= $3
			UNION
			SELECT f.subject_id
			FROM findings f
			WHERE f.tenant_id = $1 AND f.producer = $5 AND f.kind = $6
			  AND f.subject_type = 'asset' AND f.last_seen >= $3
		)
		SELECT a.id, c.id, COALESCE(c.label, ''), i.id, i.name, c.lldp_confirmed_at
		FROM cables c
		JOIN cable_terminations t ON t.tenant_id = c.tenant_id AND t.cable_id = c.id
		                         AND t.termination_kind = 'interface'
		JOIN interfaces i ON i.tenant_id = t.tenant_id AND i.id = t.termination_id
		JOIN assets a ON a.tenant_id = t.tenant_id AND a.id = t.asset_id
		WHERE c.tenant_id = $1
		  AND c.status = 'active'
		  AND c.operational_status = 'connected'
		  AND c.source_kind IN ('declared', 'imported')
		  AND c.created_at < $3
		  AND (c.lldp_confirmed_at IS NULL OR c.lldp_confirmed_at < $3)
		  AND a.id IN (SELECT asset_id FROM heard)
		  AND `+dcimAssetScope+`
		ORDER BY a.id, i.name, c.id`,
		tenantID, today, since,
		pq.Array([]string{identity.NeighborProtocolLLDP, identity.NeighborProtocolCDP}),
		findings.ProducerTopology, findings.KindCableDrift)
	if err != nil {
		return nil, fmt.Errorf("query unconfirmed cables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	g := newAssetGroups()
	for rows.Next() {
		var assetID, cableID, ifaceID uuid.UUID
		var label, iface string
		var confirmed sql.NullTime
		if err := rows.Scan(&assetID, &cableID, &label, &ifaceID, &iface, &confirmed); err != nil {
			return nil, fmt.Errorf("scan unconfirmed cable: %w", err)
		}
		row := map[string]any{
			"cable_id":     cableID.String(),
			"label":        label,
			"interface_id": ifaceID.String(),
			"interface":    iface,
		}
		if confirmed.Valid {
			row["lldp_confirmed_at"] = confirmed.Time.UTC().Format(time.RFC3339)
		}
		g.add(assetID, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.hits(findings.KindCableUnconfirmed, "cable", "cables", "cables"), nil
}

// readInterfaceNoType: active interfaces whose type is `other` (the column's
// default, and what a collector writes when it cannot say) or blank.
//
// Not the identity engine's placeholders (`observed-N`, source_ref
// identity.SyntheticInterfaceSourceRef): an address no collector named an
// interface for is filed on one, typed `other` because nothing measured it.
// It stands in for an interface nobody has reported, so there is nothing for
// a person to type; it turns into a real interface, and is checked, when a
// collector names it (the rename takes over its provenance).
func readInterfaceNoType(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, _ time.Time) ([]dcimHit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, i.id, i.name
		FROM interfaces i
		JOIN assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
		WHERE i.tenant_id = $1
		  AND i.status = 'active'
		  AND (i.type IS NULL OR btrim(i.type) = '' OR i.type = 'other')
		  AND i.source_ref IS DISTINCT FROM $3
		  AND `+dcimAssetScope+`
		ORDER BY a.id, i.name, i.id`, tenantID, today, identity.SyntheticInterfaceSourceRef)
	if err != nil {
		return nil, fmt.Errorf("query untyped interfaces: %w", err)
	}
	defer func() { _ = rows.Close() }()

	g := newAssetGroups()
	for rows.Next() {
		var assetID, ifaceID uuid.UUID
		var name string
		if err := rows.Scan(&assetID, &ifaceID, &name); err != nil {
			return nil, fmt.Errorf("scan untyped interface: %w", err)
		}
		g.add(assetID, map[string]any{"interface_id": ifaceID.String(), "interface": name})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.hits(findings.KindInterfaceNoType, "interface", "interfaces", "interfaces"), nil
}

// readDuplicateAddress: two active addresses with the same host part in the
// same VRF (NULL = the global table, compared with IS NOT DISTINCT FROM),
// assigned to interfaces of two different monitored assets, with no role that
// allows sharing. Both assets must be monitored: an address on a record still
// in Approvals is the identification engine's question (duplicate_suspected),
// not this one.
func readDuplicateAddress(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, _ time.Time) ([]dcimHit, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH addr AS (
			SELECT ip.host, ip.vrf_id, a.id AS asset_id
			FROM ip_addresses ip
			JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
			JOIN assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
			WHERE ip.tenant_id = $1
			  AND ip.status = 'active'
			  AND ip.assigned_kind = 'interface'
			  AND (ip.role IS NULL OR NOT (ip.role = ANY($3)))
			  AND i.status = 'active'
			  AND `+dcimAssetScope+`
		)
		SELECT x.asset_id, host(x.host), x.vrf_id, COALESCE(v.name, ''),
		       array_agg(DISTINCT y.asset_id::text ORDER BY y.asset_id::text)
		FROM addr x
		JOIN addr y ON y.host = x.host AND y.vrf_id IS NOT DISTINCT FROM x.vrf_id AND y.asset_id <> x.asset_id
		LEFT JOIN vrfs v ON v.tenant_id = $1 AND v.id = x.vrf_id
		GROUP BY x.asset_id, x.host, x.vrf_id, v.name
		ORDER BY x.asset_id, x.host`, tenantID, today, pq.Array(nonUniqueAddressRoles))
	if err != nil {
		return nil, fmt.Errorf("query duplicate addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	g := newAssetGroups()
	for rows.Next() {
		var assetID uuid.UUID
		var address, vrfName string
		var vrfID uuid.NullUUID
		var others []string
		if err := rows.Scan(&assetID, &address, &vrfID, &vrfName, pq.Array(&others)); err != nil {
			return nil, fmt.Errorf("scan duplicate address: %w", err)
		}
		row := map[string]any{"address": address, "other_asset_ids": others}
		if vrfID.Valid {
			row["vrf_id"] = vrfID.UUID.String()
			row["vrf"] = vrfName
		} else {
			row["vrf"] = nil
		}
		g.add(assetID, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hits := g.hits(findings.KindDuplicateAddress, "address", "addresses", "addresses")
	// The title names the address, not a count: "shares the address 10.0.0.5"
	// is what a person searches the Networks lens for. The first in host
	// order, so the summary is stable from pass to pass.
	for i := range hits {
		list, _ := hits[i].evidence["addresses"].([]map[string]any)
		if len(list) > 0 {
			addr, _ := list[0]["address"].(string)
			hits[i].detail = addr
			if n := hits[i].evidence["count"].(int); n > 1 {
				hits[i].detail = addr + " (and " + strconv.Itoa(n-1) + " more)"
			}
		}
	}
	return hits, nil
}

// readCommercialLifecycle reads the five lifecycle inputs and lets
// services.ComputeAssetLifecycle decide the warranty and end-of-support
// states. warranty_expired, past_end_of_support and end_of_support_soon come
// from those states and nothing else; unknown raises nothing.
func readCommercialLifecycle(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, today string, now time.Time) ([]dcimHit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, a.warranty_end::text,
		       dt.end_of_support::text, dte.eol_date::text,
		       pl.end_of_support::text, ple.eol_date::text
		FROM assets a
		LEFT JOIN device_types dt ON dt.id = a.device_type_id
		LEFT JOIN eol_catalogue dte ON dte.id = dt.eol_catalogue_id
		LEFT JOIN platforms pl ON pl.id = a.platform_id
		LEFT JOIN eol_catalogue ple ON ple.id = pl.eol_catalogue_id
		WHERE `+dcimAssetScope+`
		  AND (a.warranty_end IS NOT NULL OR a.device_type_id IS NOT NULL OR a.platform_id IS NOT NULL)
		ORDER BY a.id`, tenantID, today)
	if err != nil {
		return nil, fmt.Errorf("query commercial lifecycle: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []dcimHit
	for rows.Next() {
		var assetID uuid.UUID
		var warranty, dtDecl, dtCat, plDecl, plCat sql.NullString
		if err := rows.Scan(&assetID, &warranty, &dtDecl, &dtCat, &plDecl, &plCat); err != nil {
			return nil, fmt.Errorf("scan commercial lifecycle: %w", err)
		}
		lc := services.ComputeAssetLifecycle(services.LifecycleInputs{
			WarrantyEnd: lifecycleDate(warranty),
			DeviceType:  services.EOSCandidate{Declared: lifecycleDate(dtDecl), Catalogue: lifecycleDate(dtCat)},
			Platform:    services.EOSCandidate{Declared: lifecycleDate(plDecl), Catalogue: lifecycleDate(plCat)},
		}, now)
		out = append(out, lifecycleHits(assetID, warranty.String, lc)...)
	}
	return out, rows.Err()
}

// lifecycleHits turns one asset's computed lifecycle into findings. Split out
// so the mapping from state to kind is unit-testable without a database.
func lifecycleHits(assetID uuid.UUID, warrantyEnd string, lc models.AssetLifecycle) []dcimHit {
	var out []dcimHit
	if lc.WarrantyState == models.WarrantyExpired {
		out = append(out, dcimHit{
			kind: findings.KindWarrantyExpired, assetID: assetID, detail: warrantyEnd,
			evidence: map[string]any{"warranty_end": warrantyEnd, "warranty_state": lc.WarrantyState},
		})
	}
	var kind string
	switch lc.EOSState {
	case models.EOSPastEOS:
		kind = findings.KindPastEndOfSupport
	case models.EOSWithin12m:
		kind = findings.KindEndOfSupportSoon
	}
	if kind != "" && lc.EffectiveEndOfSupport != nil {
		subject := ""
		if lc.Subject != nil {
			subject = *lc.Subject
		}
		detail := *lc.EffectiveEndOfSupport
		if subject != "" {
			detail += ", " + strings.ReplaceAll(subject, "_", " ")
		}
		out = append(out, dcimHit{
			kind: kind, assetID: assetID, detail: detail,
			evidence: map[string]any{
				"effective_end_of_support": *lc.EffectiveEndOfSupport,
				"eos_state":                lc.EOSState,
				"eos_source":               lc.Source,
				"eos_subject":              subject,
			},
		})
	}
	return out
}

// lifecycleDate reads a date column rendered as text ("").
func lifecycleDate(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s.String)
	if err != nil {
		return nil
	}
	return &t
}

// assetGroups collects per-asset evidence rows in read order, for the kinds
// whose finding summarises several rows (cables, interfaces, addresses) under
// one asset.
type assetGroups struct {
	order []uuid.UUID
	rows  map[uuid.UUID][]map[string]any
	count map[uuid.UUID]int
}

func newAssetGroups() *assetGroups {
	return &assetGroups{rows: map[uuid.UUID][]map[string]any{}, count: map[uuid.UUID]int{}}
}

func (g *assetGroups) add(assetID uuid.UUID, row map[string]any) {
	if _, ok := g.count[assetID]; !ok {
		g.order = append(g.order, assetID)
	}
	g.count[assetID]++
	if len(g.rows[assetID]) < dcimEvidenceCap {
		g.rows[assetID] = append(g.rows[assetID], row)
	}
}

// hits builds one finding per asset. detail is "1 <singular>" / "N <plural>";
// the evidence carries the exact count and the (capped) list under key.
func (g *assetGroups) hits(kind, singular, plural, key string) []dcimHit {
	out := make([]dcimHit, 0, len(g.order))
	for _, id := range g.order {
		n := g.count[id]
		noun := plural
		if n == 1 {
			noun = singular
		}
		out = append(out, dcimHit{
			kind: kind, assetID: id,
			detail: strconv.Itoa(n) + " " + noun,
			evidence: map[string]any{
				"count":     n,
				key:         g.rows[id],
				"truncated": n > len(g.rows[id]),
			},
		})
	}
	return out
}

// dcimHitsSorted orders hits deterministically (kind, asset), so the plan's
// output does not depend on the order the reads ran in.
func dcimHitsSorted(hits []dcimHit) []dcimHit {
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].kind != hits[j].kind {
			return hits[i].kind < hits[j].kind
		}
		return hits[i].assetID.String() < hits[j].assetID.String()
	})
	return hits
}
