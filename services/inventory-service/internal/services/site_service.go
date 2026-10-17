package services

// Regions, site groups, sites and locations (DCIM row 2.1, ADR-0010 D4,
// DATA_MODEL section 1). This replaces location_service.go and the single
// 4.x `locations` tree whose `location_type` enum mixed geography, places,
// cloud regions and positions in a room.
//
// What the database cannot say and this service does:
//
//   - depth: every tree here (regions, site groups, locations) is at most
//     maxSiteTreeDepth levels, and no node is its own ancestor;
//   - a location's parent is in the same site as the location;
//   - an asset's location belongs to the asset's site (ValidateAssetPlacement,
//     ResolveAssetPlacement) — a CHECK cannot join;
//   - a prefix's or VLAN group's scope names an existing region, site group,
//     site or location of the tenant (shared/dcim/sites.CheckScope, called from
//     the IPAM specs);
//   - a site with assets is not deleted unless the caller names a site to move
//     them to (SiteInUseError → 409).
//
// Every write is recorded through shared/dcim/changes on the write's own
// transaction (row 0.3).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/sites"
)

// maxSiteTreeDepth is the deepest a region, site group or location tree may
// go, counting the root as level 1. NetBox sets no cap; one is needed so a
// recursive read is bounded, and eight is deeper than any estate we have seen
// (campus › building › floor › wing › room › row › cage › …).
const maxSiteTreeDepth = 8

// The asset readers' SELECT-list expressions for the placement objects. Each
// reads the asset row as `a`.
const (
	assetSiteSQL     = `(SELECT jsonb_build_object('id', st.id, 'name', st.name, 'slug', st.slug) FROM sites st WHERE st.id = a.site_id)`
	assetLocationSQL = `(SELECT jsonb_build_object('id', lc.id, 'name', lc.name, 'path', public.location_path(lc.id)) FROM locations lc WHERE lc.id = a.location_id)`
	// assetRackSQL is the rack placement (DCIM row 2.3): the rack, the lowest
	// unit and the face; position/face are null for a device in the rack with
	// no position.
	assetRackSQL = `(SELECT jsonb_build_object('id', rk.id, 'name', rk.name, 'position', a.position, 'face', a.face) FROM racks rk WHERE rk.id = a.rack_id)`
	// assetSiteNameSQL is the site's name for readers that want a string
	// (exports, the topology and the facet).
	assetSiteNameSQL = `(SELECT st.name FROM sites st WHERE st.id = a.site_id)`
)

var (
	// ErrSiteNotFound is returned when a region, site group, site or location
	// does not exist for the tenant.
	ErrSiteNotFound = errors.New("not found")
	// ErrSiteInvalid wraps every 4xx-shaped validation failure.
	ErrSiteInvalid = errors.New("invalid")
	// ErrSiteConflict is returned when a name or slug is taken.
	ErrSiteConflict = errors.New("already exists")
)

// SiteInUseError is returned by DeleteSite when assets are in the site and no
// reassignment target was given. The handler maps it to 409.
type SiteInUseError struct{ Assets int }

func (e *SiteInUseError) Error() string {
	return fmt.Sprintf("the site still holds %d asset(s); pass reassign_to to move them to another site", e.Assets)
}

func siteInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSiteInvalid, fmt.Sprintf(format, args...))
}

// SiteService owns regions, site_groups, sites and locations.
type SiteService struct {
	db       *database.DB
	recorder ChangeRecorder
}

// NewSiteService returns a service recording through the DCIM substrate.
func NewSiteService(db *database.DB) *SiteService {
	return &SiteService{db: db, recorder: SubstrateChangeRecorder{}}
}

// SetChangeRecorder replaces the recorder (tests). Nil restores the substrate one.
func (s *SiteService) SetChangeRecorder(r ChangeRecorder) {
	if r == nil {
		r = SubstrateChangeRecorder{}
	}
	s.recorder = r
}

func (s *SiteService) record(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, kind dcim.ObjectKind, action string, id uuid.UUID, before, after map[string]any) error {
	if err := s.recorder.Record(ctx, tx, ObjectChange{
		TenantID: tenantID, ActorID: actor, ObjectKind: kind, ObjectID: id,
		Action: action, Before: before, After: after, Diff: diffSnapshots(before, after),
	}); err != nil {
		return fmt.Errorf("record change: %w", err)
	}
	return nil
}

func uuidStr(u *uuid.UUID) any {
	if u == nil {
		return nil
	}
	return u.String()
}

func trimmedPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := strings.TrimSpace(*p)
	if v == "" {
		return nil
	}
	return &v
}

func mapUnique(err error) error {
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: the name or slug is already used", ErrSiteConflict)
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23514" { // check_violation
		return siteInvalid("%s", pqErr.Message)
	}
	return err
}

var validSiteStatuses = map[string]bool{"planned": true, "staged": true, "active": true, "decommissioning": true, "retired": true}

// ---------------------------------------------------------------------------
// Trees: regions and site groups share one shape.
// ---------------------------------------------------------------------------

type siteTree struct {
	table   string
	kind    dcim.ObjectKind
	label   string
	siteCol string // the sites column that points at this table
}

var (
	regionTree    = siteTree{table: "regions", kind: dcim.ObjectKindRegion, label: "region", siteCol: "region_id"}
	siteGroupTree = siteTree{table: "site_groups", kind: dcim.ObjectKindSiteGroup, label: "site group", siteCol: "group_id"}
)

func (t siteTree) columns() string {
	return `n.id, n.tenant_id, n.name, n.slug, n.parent_id, n.description, n.comments, n.source_kind, n.source_ref,
		n.custom_fields::text, n.created_by, n.created_at, n.updated_at,
		(SELECT COUNT(*) FROM sites s WHERE s.` + t.siteCol + ` = n.id)`
}

func scanTreeNode(r rowScanner) (*models.Region, error) {
	var (
		n             models.Region
		custom        string
		parent, crtdB uuid.NullUUID
	)
	if err := r.Scan(&n.ID, &n.TenantID, &n.Name, &n.Slug, &parent, &n.Description, &n.Comments, &n.SourceKind, &n.SourceRef,
		&custom, &crtdB, &n.CreatedAt, &n.UpdatedAt, &n.SiteCount); err != nil {
		return nil, err
	}
	if parent.Valid {
		n.ParentID = &parent.UUID
	}
	if crtdB.Valid {
		n.CreatedBy = &crtdB.UUID
	}
	n.CustomFields = map[string]interface{}{}
	_ = json.Unmarshal([]byte(custom), &n.CustomFields)
	return &n, nil
}

func treeSnapshot(n *models.Region) map[string]any {
	if n == nil {
		return nil
	}
	return map[string]any{"name": n.Name, "slug": n.Slug, "parent_id": uuidStr(n.ParentID), "description": n.Description, "comments": n.Comments}
}

func (s *SiteService) listTree(ctx context.Context, t siteTree, tenantID uuid.UUID) ([]models.Region, error) {
	out := []models.Region{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+t.columns()+` FROM `+t.table+` n WHERE n.tenant_id = $1 ORDER BY lower(n.name), n.id`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			n, err := scanTreeNode(rows)
			if err != nil {
				return err
			}
			out = append(out, *n)
		}
		return rows.Err()
	})
	return out, err
}

func (s *SiteService) getTreeTx(ctx context.Context, tx *sqlx.Tx, t siteTree, tenantID, id uuid.UUID) (*models.Region, error) {
	n, err := scanTreeNode(tx.QueryRowContext(ctx, `SELECT `+t.columns()+` FROM `+t.table+` n WHERE n.tenant_id = $1 AND n.id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s %w", t.label, ErrSiteNotFound)
	}
	return n, err
}

// treeLevels returns the levels from the root down to id inclusive (up), and
// the levels of the subtree rooted at id, id included (down).
func treeLevels(ctx context.Context, tx *sqlx.Tx, table string, id uuid.UUID) (up, down int, err error) {
	if err = tx.QueryRowContext(ctx, `
		WITH RECURSIVE up(id, parent_id, d) AS (
			SELECT id, parent_id, 1 FROM `+table+` WHERE id = $1
			UNION ALL
			SELECT n.id, n.parent_id, up.d + 1 FROM `+table+` n JOIN up ON n.id = up.parent_id WHERE up.d < 64
		) SELECT COUNT(*) FROM up`, id).Scan(&up); err != nil {
		return
	}
	err = tx.QueryRowContext(ctx, `
		WITH RECURSIVE down(id, d) AS (
			SELECT id, 1 FROM `+table+` WHERE id = $1
			UNION ALL
			SELECT n.id, down.d + 1 FROM `+table+` n JOIN down ON n.parent_id = down.id WHERE down.d < 64
		) SELECT COALESCE(MAX(d), 1) FROM down`, id).Scan(&down)
	return
}

func treeIsDescendant(ctx context.Context, tx *sqlx.Tx, table string, ancestor, candidate uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `
		WITH RECURSIVE down(id, d) AS (
			SELECT id, 0 FROM `+table+` WHERE id = $1
			UNION ALL
			SELECT n.id, down.d + 1 FROM `+table+` n JOIN down ON n.parent_id = down.id WHERE down.d < 64
		) SELECT EXISTS (SELECT 1 FROM down WHERE id = $2)`, ancestor, candidate).Scan(&ok)
	return ok, err
}

// checkParent validates moving node id (uuid.Nil on create) under parent:
// the parent exists, it is not the node or one of its descendants, and the
// resulting tree is no deeper than maxSiteTreeDepth.
func checkParent(ctx context.Context, tx *sqlx.Tx, table, label string, tenantID, id uuid.UUID, parent *uuid.UUID) error {
	if parent == nil {
		if id == uuid.Nil {
			return nil
		}
		_, down, err := treeLevels(ctx, tx, table, id)
		if err != nil {
			return err
		}
		if down > maxSiteTreeDepth {
			return siteInvalid("the %s hierarchy may be at most %d levels deep", label, maxSiteTreeDepth)
		}
		return nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE tenant_id = $1 AND id = $2)`, tenantID, *parent).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return siteInvalid("parent %s not found", label)
	}
	sub := 1
	if id != uuid.Nil {
		if *parent == id {
			return siteInvalid("a %s cannot be its own parent", label)
		}
		cyc, err := treeIsDescendant(ctx, tx, table, id, *parent)
		if err != nil {
			return err
		}
		if cyc {
			return siteInvalid("a %s cannot be moved under one of its own descendants", label)
		}
		if _, sub, err = treeLevels(ctx, tx, table, id); err != nil {
			return err
		}
	}
	up, _, err := treeLevels(ctx, tx, table, *parent)
	if err != nil {
		return err
	}
	if up+sub > maxSiteTreeDepth {
		return siteInvalid("the %s hierarchy may be at most %d levels deep", label, maxSiteTreeDepth)
	}
	return nil
}

// slugFor returns the explicit slug (normalised, must be free) or one derived
// from name and made unique.
func slugFor(ctx context.Context, tx *sqlx.Tx, table string, tenantID uuid.UUID, scopeCol string, scopeID uuid.UUID, explicit *string, name, fallback string, id uuid.UUID) (string, error) {
	if explicit != nil && strings.TrimSpace(*explicit) != "" {
		slug := sites.Slug(*explicit, fallback)
		free, err := sites.UniqueSlug(ctx, tx, table, tenantID, scopeCol, scopeID, slug, id)
		if err != nil {
			return "", err
		}
		if free != slug {
			return "", fmt.Errorf("%w: slug %q is taken", ErrSiteConflict, slug)
		}
		return slug, nil
	}
	return sites.UniqueSlug(ctx, tx, table, tenantID, scopeCol, scopeID, sites.Slug(name, fallback), id)
}

func (s *SiteService) createTree(ctx context.Context, t siteTree, tenantID, actor uuid.UUID, in models.RegionInput) (*models.Region, error) {
	name := trimmedPtr(in.Name)
	if name == nil {
		return nil, siteInvalid("name is required")
	}
	var out *models.Region
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := checkParent(ctx, tx, t.table, t.label, tenantID, uuid.Nil, in.ParentID); err != nil {
			return err
		}
		id := uuid.New()
		slug, err := slugFor(ctx, tx, t.table, tenantID, "", uuid.Nil, in.Slug, *name, strings.ReplaceAll(t.label, " ", "-"), id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+t.table+` (id, tenant_id, name, slug, parent_id, description, comments, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, tenantID, *name, slug, in.ParentID, in.Description, in.Comments, nullActor(actor)); err != nil {
			return mapUnique(err)
		}
		if out, err = s.getTreeTx(ctx, tx, t, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, t.kind, "create", id, nil, treeSnapshot(out))
	})
	return out, err
}

func (s *SiteService) updateTree(ctx context.Context, t siteTree, tenantID, actor, id uuid.UUID, in models.RegionInput) (*models.Region, error) {
	var out *models.Region
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := s.getTreeTx(ctx, tx, t, tenantID, id)
		if err != nil {
			return err
		}
		name, slug, parent, desc, comments := before.Name, before.Slug, before.ParentID, before.Description, before.Comments
		if in.Has("name") {
			n := trimmedPtr(in.Name)
			if n == nil {
				return siteInvalid("name cannot be empty")
			}
			name = *n
		}
		if in.Has("slug") && in.Slug != nil && strings.TrimSpace(*in.Slug) != "" {
			if slug, err = slugFor(ctx, tx, t.table, tenantID, "", uuid.Nil, in.Slug, name, "", id); err != nil {
				return err
			}
		}
		if in.Has("parent_id") {
			parent = in.ParentID
			if err := checkParent(ctx, tx, t.table, t.label, tenantID, id, parent); err != nil {
				return err
			}
		}
		if in.Has("description") {
			desc = in.Description
		}
		if in.Has("comments") {
			comments = in.Comments
		}
		if _, err := tx.ExecContext(ctx, `UPDATE `+t.table+` SET name=$3, slug=$4, parent_id=$5, description=$6, comments=$7, updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, tenantID, id, name, slug, parent, desc, comments); err != nil {
			return mapUnique(err)
		}
		if out, err = s.getTreeTx(ctx, tx, t, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, t.kind, "update", id, treeSnapshot(before), treeSnapshot(out))
	})
	return out, err
}

// deleteTree removes a region or site group. Its children move up to its own
// parent, and so do the sites that pointed at it — nothing is orphaned to the
// top level, and nothing is deleted with it.
func (s *SiteService) deleteTree(ctx context.Context, t siteTree, tenantID, actor, id uuid.UUID) error {
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := s.getTreeTx(ctx, tx, t, tenantID, id)
		if err != nil {
			return err
		}
		kids, err := idsWhere(ctx, tx, `SELECT id FROM `+t.table+` WHERE tenant_id = $1 AND parent_id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		for _, k := range kids {
			kb, err := s.getTreeTx(ctx, tx, t, tenantID, k)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE `+t.table+` SET parent_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`, tenantID, k, before.ParentID); err != nil {
				return err
			}
			ka, err := s.getTreeTx(ctx, tx, t, tenantID, k)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenantID, actor, t.kind, "update", k, treeSnapshot(kb), treeSnapshot(ka)); err != nil {
				return err
			}
		}
		siteIDs, err := idsWhere(ctx, tx, `SELECT id FROM sites WHERE tenant_id = $1 AND `+t.siteCol+` = $2`, tenantID, id)
		if err != nil {
			return err
		}
		for _, sid := range siteIDs {
			sb, err := s.getSiteTx(ctx, tx, tenantID, sid, false)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE sites SET `+t.siteCol+` = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`, tenantID, sid, before.ParentID); err != nil {
				return err
			}
			sa, err := s.getSiteTx(ctx, tx, tenantID, sid, false)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenantID, actor, dcim.ObjectKindSite, "update", sid, siteSnapshot(sb), siteSnapshot(sa)); err != nil {
				return err
			}
		}
		if err := clearScopes(ctx, tx, tenantID, string(t.kind), []uuid.UUID{id}, nil); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t.table+` WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, t.kind, "delete", id, treeSnapshot(before), nil)
	})
}

func idsWhere(ctx context.Context, tx *sqlx.Tx, q string, args ...any) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// clearScopes moves the prefixes and VLAN groups scoped to (kind, ids) to
// (toKind, toID), or clears their scope when toID is nil. The scope columns
// are polymorphic, so no foreign key does this.
func clearScopes(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, kind string, ids []uuid.UUID, to *uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	for _, table := range []string{"prefixes", "vlan_groups"} {
		var err error
		if to == nil {
			_, err = tx.ExecContext(ctx, `UPDATE `+table+` SET scope_kind = NULL, scope_id = NULL, updated_at = now()
				WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = ANY($3)`, tenantID, kind, pq.Array(ids))
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE `+table+` SET scope_kind = 'site', scope_id = $4, updated_at = now()
				WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = ANY($3)`, tenantID, kind, pq.Array(ids), *to)
		}
		if err != nil {
			return mapUnique(err)
		}
	}
	return nil
}

// ListRegions returns every region of the tenant.
func (s *SiteService) ListRegions(ctx context.Context, tenantID uuid.UUID) ([]models.Region, error) {
	return s.listTree(ctx, regionTree, tenantID)
}

// GetRegion returns one region.
func (s *SiteService) GetRegion(ctx context.Context, tenantID, id uuid.UUID) (*models.Region, error) {
	var out *models.Region
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.getTreeTx(ctx, tx, regionTree, tenantID, id)
		return err
	})
	return out, err
}

// CreateRegion adds a region.
func (s *SiteService) CreateRegion(ctx context.Context, tenantID, actor uuid.UUID, in models.RegionInput) (*models.Region, error) {
	return s.createTree(ctx, regionTree, tenantID, actor, in)
}

// UpdateRegion patches a region.
func (s *SiteService) UpdateRegion(ctx context.Context, tenantID, actor, id uuid.UUID, in models.RegionInput) (*models.Region, error) {
	return s.updateTree(ctx, regionTree, tenantID, actor, id, in)
}

// DeleteRegion removes a region (children and sites move to its parent).
func (s *SiteService) DeleteRegion(ctx context.Context, tenantID, actor, id uuid.UUID) error {
	return s.deleteTree(ctx, regionTree, tenantID, actor, id)
}

func toSiteGroups(in []models.Region) []models.SiteGroup {
	out := make([]models.SiteGroup, len(in))
	for i := range in {
		out[i] = models.SiteGroup(in[i])
	}
	return out
}

func toSiteGroup(in *models.Region) *models.SiteGroup {
	if in == nil {
		return nil
	}
	g := models.SiteGroup(*in)
	return &g
}

// ListSiteGroups returns every site group of the tenant.
func (s *SiteService) ListSiteGroups(ctx context.Context, tenantID uuid.UUID) ([]models.SiteGroup, error) {
	l, err := s.listTree(ctx, siteGroupTree, tenantID)
	return toSiteGroups(l), err
}

// GetSiteGroup returns one site group.
func (s *SiteService) GetSiteGroup(ctx context.Context, tenantID, id uuid.UUID) (*models.SiteGroup, error) {
	var out *models.Region
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.getTreeTx(ctx, tx, siteGroupTree, tenantID, id)
		return err
	})
	return toSiteGroup(out), err
}

// CreateSiteGroup adds a site group.
func (s *SiteService) CreateSiteGroup(ctx context.Context, tenantID, actor uuid.UUID, in models.RegionInput) (*models.SiteGroup, error) {
	g, err := s.createTree(ctx, siteGroupTree, tenantID, actor, in)
	return toSiteGroup(g), err
}

// UpdateSiteGroup patches a site group.
func (s *SiteService) UpdateSiteGroup(ctx context.Context, tenantID, actor, id uuid.UUID, in models.RegionInput) (*models.SiteGroup, error) {
	g, err := s.updateTree(ctx, siteGroupTree, tenantID, actor, id, in)
	return toSiteGroup(g), err
}

// DeleteSiteGroup removes a site group (children and sites move to its parent).
func (s *SiteService) DeleteSiteGroup(ctx context.Context, tenantID, actor, id uuid.UUID) error {
	return s.deleteTree(ctx, siteGroupTree, tenantID, actor, id)
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

const siteColumns = `s.id, s.tenant_id, s.name, s.slug, s.operational_status, s.region_id, s.group_id, s.facility, s.time_zone,
	s.physical_address, s.shipping_address, s.latitude::float8, s.longitude::float8, s.business_unit_id, s.asns,
	s.external_ids::text, s.description, s.comments, s.source_kind, s.source_ref, s.custom_fields::text,
	s.created_by, s.created_at, s.updated_at,
	(SELECT r.name FROM regions r WHERE r.id = s.region_id),
	(SELECT g.name FROM site_groups g WHERE g.id = s.group_id),
	(SELECT bu.name FROM business_units bu WHERE bu.id = s.business_unit_id),
	(SELECT COUNT(*) FROM assets a WHERE a.tenant_id = s.tenant_id AND a.site_id = s.id AND a.deleted_at IS NULL)`

func scanSite(r rowScanner) (*models.Site, error) {
	var (
		st                       models.Site
		ext, custom              string
		region, group, bu, crtdB uuid.NullUUID
		asns                     pq.Int64Array
	)
	if err := r.Scan(&st.ID, &st.TenantID, &st.Name, &st.Slug, &st.OperationalStatus, &region, &group, &st.Facility, &st.TimeZone,
		&st.PhysicalAddress, &st.ShippingAddress, &st.Latitude, &st.Longitude, &bu, &asns,
		&ext, &st.Description, &st.Comments, &st.SourceKind, &st.SourceRef, &custom,
		&crtdB, &st.CreatedAt, &st.UpdatedAt, &st.RegionName, &st.GroupName, &st.BusinessUnitName, &st.AssetCount); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		src *uuid.NullUUID
		dst **uuid.UUID
	}{{&region, &st.RegionID}, {&group, &st.GroupID}, {&bu, &st.BusinessUnitID}, {&crtdB, &st.CreatedBy}} {
		if p.src.Valid {
			v := p.src.UUID
			*p.dst = &v
		}
	}
	st.ASNs = []int64(asns)
	if st.ASNs == nil {
		st.ASNs = []int64{}
	}
	st.ExternalIDs, st.CustomFields = map[string]interface{}{}, map[string]interface{}{}
	_ = json.Unmarshal([]byte(ext), &st.ExternalIDs)
	_ = json.Unmarshal([]byte(custom), &st.CustomFields)
	return &st, nil
}

func siteSnapshot(st *models.Site) map[string]any {
	if st == nil {
		return nil
	}
	return map[string]any{
		"name": st.Name, "slug": st.Slug, "operational_status": st.OperationalStatus,
		"region_id": uuidStr(st.RegionID), "group_id": uuidStr(st.GroupID), "facility": st.Facility, "time_zone": st.TimeZone,
		"physical_address": st.PhysicalAddress, "shipping_address": st.ShippingAddress,
		"latitude": st.Latitude, "longitude": st.Longitude, "business_unit_id": uuidStr(st.BusinessUnitID),
		"asns": st.ASNs, "external_ids": st.ExternalIDs, "description": st.Description, "comments": st.Comments,
	}
}

func (s *SiteService) getSiteTx(ctx context.Context, tx *sqlx.Tx, tenantID, id uuid.UUID, counts bool) (*models.Site, error) {
	st, err := scanSite(tx.QueryRowContext(ctx, `SELECT `+siteColumns+` FROM sites s WHERE s.tenant_id = $1 AND s.id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("site %w", ErrSiteNotFound)
	}
	if err != nil || !counts {
		return st, err
	}
	c := models.SiteCounts{Assets: st.AssetCount}
	// Prefixes scoped to the site or to any of its locations; VLANs whose site
	// is this one; racks in the site (row 2.3).
	if err := tx.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM locations l WHERE l.tenant_id = $1 AND l.site_id = $2),
		       (SELECT COUNT(*) FROM racks r WHERE r.tenant_id = $1 AND r.site_id = $2),
		       (SELECT COUNT(*) FROM prefixes p WHERE p.tenant_id = $1 AND p.status <> 'rejected' AND (
		            (p.scope_kind = 'site' AND p.scope_id = $2) OR
		            (p.scope_kind = 'location' AND p.scope_id IN (SELECT l.id FROM locations l WHERE l.tenant_id = $1 AND l.site_id = $2)))),
		       (SELECT COUNT(*) FROM vlans v WHERE v.tenant_id = $1 AND v.site_id = $2 AND v.status <> 'rejected')`,
		tenantID, id).Scan(&c.Locations, &c.Racks, &c.Prefixes, &c.VLANs); err != nil {
		return nil, err
	}
	st.Counts = &c
	return st, nil
}

// ListSites returns the tenant's sites, by name.
func (s *SiteService) ListSites(ctx context.Context, tenantID uuid.UUID, f models.SiteFilters) ([]models.Site, error) {
	out := []models.Site{}
	q := `SELECT ` + siteColumns + ` FROM sites s WHERE s.tenant_id = $1`
	args := []any{tenantID}
	if f.RegionID != nil {
		args = append(args, *f.RegionID)
		q += fmt.Sprintf(` AND s.region_id = $%d`, len(args))
	}
	if f.GroupID != nil {
		args = append(args, *f.GroupID)
		q += fmt.Sprintf(` AND s.group_id = $%d`, len(args))
	}
	if strings.TrimSpace(f.Q) != "" {
		args = append(args, "%"+escapeLike(strings.TrimSpace(f.Q))+"%")
		q += fmt.Sprintf(` AND (s.name ILIKE $%[1]d OR s.slug ILIKE $%[1]d OR s.facility ILIKE $%[1]d)`, len(args))
	}
	q += ` ORDER BY lower(s.name), s.id`
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			st, err := scanSite(rows)
			if err != nil {
				return err
			}
			out = append(out, *st)
		}
		return rows.Err()
	})
	return out, err
}

// GetSite returns one site with its counts.
func (s *SiteService) GetSite(ctx context.Context, tenantID, id uuid.UUID) (*models.Site, error) {
	var out *models.Site
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.getSiteTx(ctx, tx, tenantID, id, true)
		return err
	})
	return out, err
}

// applySiteInput merges in over st (a patch; st is a zero Site on create) and
// validates the references.
func applySiteInput(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, st *models.Site, in models.SiteInput, create bool) error {
	has := func(k string) bool { return create || in.Has(k) }
	if has("name") {
		n := trimmedPtr(in.Name)
		if n == nil {
			return siteInvalid("name is required")
		}
		st.Name = *n
	}
	if has("operational_status") && in.OperationalStatus != nil {
		v := strings.TrimSpace(*in.OperationalStatus)
		if !validSiteStatuses[v] {
			return siteInvalid("operational_status must be one of planned, staged, active, decommissioning, retired")
		}
		st.OperationalStatus = v
	}
	if has("region_id") {
		st.RegionID = in.RegionID
		if err := visibleIn(ctx, tx, "regions", "region", st.RegionID); err != nil {
			return err
		}
	}
	if has("group_id") {
		st.GroupID = in.GroupID
		if err := visibleIn(ctx, tx, "site_groups", "site group", st.GroupID); err != nil {
			return err
		}
	}
	if has("business_unit_id") {
		st.BusinessUnitID = in.BusinessUnitID
		if err := visibleIn(ctx, tx, "business_units", "business unit", st.BusinessUnitID); err != nil {
			return err
		}
	}
	for k, p := range map[string]struct {
		src *string
		dst **string
	}{
		"facility": {in.Facility, &st.Facility}, "time_zone": {in.TimeZone, &st.TimeZone},
		"physical_address": {in.PhysicalAddress, &st.PhysicalAddress}, "shipping_address": {in.ShippingAddress, &st.ShippingAddress},
		"description": {in.Description, &st.Description}, "comments": {in.Comments, &st.Comments},
	} {
		if has(k) {
			*p.dst = trimmedPtr(p.src)
		}
	}
	if has("latitude") {
		st.Latitude = in.Latitude
		if st.Latitude != nil && (*st.Latitude < -90 || *st.Latitude > 90) {
			return siteInvalid("latitude must be between -90 and 90")
		}
	}
	if has("longitude") {
		st.Longitude = in.Longitude
		if st.Longitude != nil && (*st.Longitude < -180 || *st.Longitude > 180) {
			return siteInvalid("longitude must be between -180 and 180")
		}
	}
	if has("asns") {
		st.ASNs = []int64{}
		for _, a := range in.ASNs {
			if a < 1 || a > 4294967295 {
				return siteInvalid("ASN %d is outside 1-4294967295", a)
			}
			st.ASNs = append(st.ASNs, a)
		}
	}
	if has("external_ids") && in.ExternalIDs != nil {
		st.ExternalIDs = in.ExternalIDs
	}
	if tz := st.TimeZone; tz != nil && len(*tz) > 63 {
		return siteInvalid("time_zone is not an IANA zone name")
	}
	return nil
}

// visibleIn checks that a referenced row exists for the tenant (RLS decides
// whose rows are visible).
func visibleIn(ctx context.Context, tx *sqlx.Tx, table, label string, id *uuid.UUID) error {
	if id == nil {
		return nil
	}
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE id = $1)`, *id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return siteInvalid("%s %s not found", label, id)
	}
	return nil
}

func writeSite(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, st *models.Site, insert bool, actor uuid.UUID) error {
	ext := st.ExternalIDs
	if ext == nil {
		ext = map[string]interface{}{}
	}
	extJSON, _ := json.Marshal(ext)
	asns := st.ASNs
	if asns == nil {
		asns = []int64{}
	}
	var err error
	if insert {
		_, err = tx.ExecContext(ctx, `INSERT INTO sites (id, tenant_id, name, slug, operational_status, region_id, group_id, facility, time_zone,
			physical_address, shipping_address, latitude, longitude, business_unit_id, asns, external_ids, description, comments, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18,$19)`,
			st.ID, tenantID, st.Name, st.Slug, st.OperationalStatus, st.RegionID, st.GroupID, st.Facility, st.TimeZone,
			st.PhysicalAddress, st.ShippingAddress, st.Latitude, st.Longitude, st.BusinessUnitID, pq.Int64Array(asns), string(extJSON),
			st.Description, st.Comments, nullActor(actor))
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE sites SET name=$3, slug=$4, operational_status=$5, region_id=$6, group_id=$7, facility=$8, time_zone=$9,
			physical_address=$10, shipping_address=$11, latitude=$12, longitude=$13, business_unit_id=$14, asns=$15, external_ids=$16::jsonb,
			description=$17, comments=$18, updated_at=now() WHERE tenant_id=$1 AND id=$2`,
			tenantID, st.ID, st.Name, st.Slug, st.OperationalStatus, st.RegionID, st.GroupID, st.Facility, st.TimeZone,
			st.PhysicalAddress, st.ShippingAddress, st.Latitude, st.Longitude, st.BusinessUnitID, pq.Int64Array(asns), string(extJSON),
			st.Description, st.Comments)
	}
	return mapUnique(err)
}

// CreateSite adds a site. Without an explicit slug one is derived from the name.
func (s *SiteService) CreateSite(ctx context.Context, tenantID, actor uuid.UUID, in models.SiteInput) (*models.Site, error) {
	var out *models.Site
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		st := &models.Site{ID: uuid.New(), OperationalStatus: "active"}
		if err := applySiteInput(ctx, tx, tenantID, st, in, true); err != nil {
			return err
		}
		var err error
		if st.Slug, err = slugFor(ctx, tx, "sites", tenantID, "", uuid.Nil, in.Slug, st.Name, "site", st.ID); err != nil {
			return err
		}
		if err := writeSite(ctx, tx, tenantID, st, true, actor); err != nil {
			return err
		}
		if out, err = s.getSiteTx(ctx, tx, tenantID, st.ID, true); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindSite, "create", st.ID, nil, siteSnapshot(out))
	})
	return out, err
}

// UpdateSite patches a site. A rename keeps the slug unless one is supplied.
func (s *SiteService) UpdateSite(ctx context.Context, tenantID, actor, id uuid.UUID, in models.SiteInput) (*models.Site, error) {
	var out *models.Site
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := s.getSiteTx(ctx, tx, tenantID, id, false)
		if err != nil {
			return err
		}
		st := *before
		if err := applySiteInput(ctx, tx, tenantID, &st, in, false); err != nil {
			return err
		}
		if in.Has("slug") && in.Slug != nil && strings.TrimSpace(*in.Slug) != "" {
			if st.Slug, err = slugFor(ctx, tx, "sites", tenantID, "", uuid.Nil, in.Slug, st.Name, "site", id); err != nil {
				return err
			}
		}
		if err := writeSite(ctx, tx, tenantID, &st, false, actor); err != nil {
			return err
		}
		if out, err = s.getSiteTx(ctx, tx, tenantID, id, true); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindSite, "update", id, siteSnapshot(before), siteSnapshot(out))
	})
	return out, err
}

// DeleteSite removes a site and, with it, its locations (CASCADE). When live
// assets are in the site the delete is refused (SiteInUseError) unless
// reassignTo names another site: the assets move there and lose their
// location (the locations are going), VLANs move there, and prefixes and VLAN
// groups scoped to the site or its locations are re-scoped to it. Without
// assets, scopes naming the site or its locations are cleared.
func (s *SiteService) DeleteSite(ctx context.Context, tenantID, actor, id uuid.UUID, reassignTo *uuid.UUID) error {
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := s.getSiteTx(ctx, tx, tenantID, id, false)
		if err != nil {
			return err
		}
		if before.AssetCount > 0 && reassignTo == nil {
			return &SiteInUseError{Assets: before.AssetCount}
		}
		if reassignTo != nil {
			if *reassignTo == id {
				return siteInvalid("reassign_to must be a different site")
			}
			if _, err := s.getSiteTx(ctx, tx, tenantID, *reassignTo, false); err != nil {
				if errors.Is(err, ErrSiteNotFound) {
					return siteInvalid("reassign_to site not found")
				}
				return err
			}
			// Soft-deleted assets keep the FK too, so they move with the rest.
			// The site's racks are going (CASCADE), so the moved assets leave
			// them (DCIM row 2.3): a position never outlives its rack.
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET site_id = $3, location_id = NULL, rack_id = NULL, position = NULL, face = NULL, updated_at = now() WHERE tenant_id = $1 AND site_id = $2`, tenantID, id, *reassignTo); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE vlans SET site_id = $3, updated_at = now() WHERE tenant_id = $1 AND site_id = $2`, tenantID, id, *reassignTo); err != nil {
				return mapUnique(err)
			}
		}
		// Assets left in the site's racks (soft-deleted ones: the live ones
		// were reassigned above or there are none) leave them before the
		// racks cascade away.
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET rack_id = NULL, position = NULL, face = NULL, updated_at = now()
			WHERE tenant_id = $1 AND rack_id IN (SELECT r.id FROM racks r WHERE r.tenant_id = $1 AND r.site_id = $2)`, tenantID, id); err != nil {
			return err
		}
		locs, err := idsWhere(ctx, tx, `SELECT id FROM locations WHERE tenant_id = $1 AND site_id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		if err := clearScopes(ctx, tx, tenantID, string(dcim.ObjectKindSite), []uuid.UUID{id}, reassignTo); err != nil {
			return err
		}
		if err := clearScopes(ctx, tx, tenantID, string(dcim.ObjectKindLocation), locs, reassignTo); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sites WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindSite, "delete", id, siteSnapshot(before), nil)
	})
}

// ---------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------

const locationColumns = `l.id, l.tenant_id, l.site_id, l.parent_id, l.name, l.slug, l.operational_status, l.facility, l.business_unit_id,
	l.description, l.comments, l.source_kind, l.source_ref, l.custom_fields::text, l.created_by, l.created_at, l.updated_at,
	COALESCE(public.location_path(l.id), l.name),
	(SELECT COUNT(*) FROM assets a WHERE a.tenant_id = l.tenant_id AND a.location_id = l.id AND a.deleted_at IS NULL)`

func scanLocation(r rowScanner) (*models.Location, error) {
	var (
		l                  models.Location
		custom             string
		parent, bu, crtdBy uuid.NullUUID
	)
	if err := r.Scan(&l.ID, &l.TenantID, &l.SiteID, &parent, &l.Name, &l.Slug, &l.OperationalStatus, &l.Facility, &bu,
		&l.Description, &l.Comments, &l.SourceKind, &l.SourceRef, &custom, &crtdBy, &l.CreatedAt, &l.UpdatedAt, &l.Path, &l.AssetCount); err != nil {
		return nil, err
	}
	if parent.Valid {
		l.ParentID = &parent.UUID
	}
	if bu.Valid {
		l.BusinessUnitID = &bu.UUID
	}
	if crtdBy.Valid {
		l.CreatedBy = &crtdBy.UUID
	}
	l.CustomFields = map[string]interface{}{}
	_ = json.Unmarshal([]byte(custom), &l.CustomFields)
	return &l, nil
}

func locationSnapshot(l *models.Location) map[string]any {
	if l == nil {
		return nil
	}
	return map[string]any{
		"site_id": l.SiteID.String(), "parent_id": uuidStr(l.ParentID), "name": l.Name, "slug": l.Slug,
		"operational_status": l.OperationalStatus, "facility": l.Facility, "business_unit_id": uuidStr(l.BusinessUnitID),
		"description": l.Description, "comments": l.Comments,
	}
}

func (s *SiteService) getLocationTx(ctx context.Context, tx *sqlx.Tx, tenantID, id uuid.UUID) (*models.Location, error) {
	l, err := scanLocation(tx.QueryRowContext(ctx, `SELECT `+locationColumns+` FROM locations l WHERE l.tenant_id = $1 AND l.id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("location %w", ErrSiteNotFound)
	}
	return l, err
}

// ListLocations returns the tenant's locations, optionally of one site, in
// tree order (by path).
func (s *SiteService) ListLocations(ctx context.Context, tenantID uuid.UUID, siteID *uuid.UUID) ([]models.Location, error) {
	out := []models.Location{}
	q := `SELECT ` + locationColumns + ` FROM locations l WHERE l.tenant_id = $1`
	args := []any{tenantID}
	if siteID != nil {
		args = append(args, *siteID)
		q += ` AND l.site_id = $2`
	}
	q += ` ORDER BY 18, l.id`
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			l, err := scanLocation(rows)
			if err != nil {
				return err
			}
			out = append(out, *l)
		}
		return rows.Err()
	})
	return out, err
}

// GetLocation returns one location.
func (s *SiteService) GetLocation(ctx context.Context, tenantID, id uuid.UUID) (*models.Location, error) {
	var out *models.Location
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.getLocationTx(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// checkLocationParent: the parent is a location of the same site, and the
// tree rules hold.
func checkLocationParent(ctx context.Context, tx *sqlx.Tx, tenantID, id, siteID uuid.UUID, parent *uuid.UUID) error {
	if parent != nil {
		var parentSite uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT site_id FROM locations WHERE tenant_id = $1 AND id = $2`, tenantID, *parent).Scan(&parentSite)
		if errors.Is(err, sql.ErrNoRows) {
			return siteInvalid("parent location not found")
		}
		if err != nil {
			return err
		}
		if parentSite != siteID {
			return siteInvalid("a location's parent must be in the same site")
		}
	}
	return checkParent(ctx, tx, "locations", "location", tenantID, id, parent)
}

// CreateLocation adds a location inside a site.
func (s *SiteService) CreateLocation(ctx context.Context, tenantID, actor uuid.UUID, in models.LocationInput) (*models.Location, error) {
	name := trimmedPtr(in.Name)
	if name == nil {
		return nil, siteInvalid("name is required")
	}
	if in.SiteID == nil {
		return nil, siteInvalid("site_id is required")
	}
	status := "active"
	if in.OperationalStatus != nil {
		status = strings.TrimSpace(*in.OperationalStatus)
		if !validSiteStatuses[status] {
			return nil, siteInvalid("operational_status must be one of planned, staged, active, decommissioning, retired")
		}
	}
	var out *models.Location
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := visibleIn(ctx, tx, "sites", "site", in.SiteID); err != nil {
			return err
		}
		if err := checkLocationParent(ctx, tx, tenantID, uuid.Nil, *in.SiteID, in.ParentID); err != nil {
			return err
		}
		if err := visibleIn(ctx, tx, "business_units", "business unit", in.BusinessUnitID); err != nil {
			return err
		}
		id := uuid.New()
		slug, err := slugFor(ctx, tx, "locations", tenantID, "site_id", *in.SiteID, in.Slug, *name, "location", id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO locations (id, tenant_id, site_id, parent_id, name, slug, operational_status, facility,
			business_unit_id, description, comments, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			id, tenantID, *in.SiteID, in.ParentID, *name, slug, status, trimmedPtr(in.Facility), in.BusinessUnitID,
			in.Description, in.Comments, nullActor(actor)); err != nil {
			return mapUnique(err)
		}
		if out, err = s.getLocationTx(ctx, tx, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindLocation, "create", id, nil, locationSnapshot(out))
	})
	return out, err
}

// UpdateLocation patches a location. Its site cannot change: a location IS a
// place inside one site; moving the room is a new location.
func (s *SiteService) UpdateLocation(ctx context.Context, tenantID, actor, id uuid.UUID, in models.LocationInput) (*models.Location, error) {
	var out *models.Location
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := s.getLocationTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		l := *before
		if in.Has("site_id") && in.SiteID != nil && *in.SiteID != before.SiteID {
			return siteInvalid("a location cannot move to another site")
		}
		if in.Has("name") {
			n := trimmedPtr(in.Name)
			if n == nil {
				return siteInvalid("name cannot be empty")
			}
			l.Name = *n
		}
		if in.Has("slug") && in.Slug != nil && strings.TrimSpace(*in.Slug) != "" {
			if l.Slug, err = slugFor(ctx, tx, "locations", tenantID, "site_id", l.SiteID, in.Slug, l.Name, "location", id); err != nil {
				return err
			}
		}
		if in.Has("parent_id") {
			l.ParentID = in.ParentID
			if err := checkLocationParent(ctx, tx, tenantID, id, l.SiteID, l.ParentID); err != nil {
				return err
			}
		}
		if in.Has("operational_status") && in.OperationalStatus != nil {
			v := strings.TrimSpace(*in.OperationalStatus)
			if !validSiteStatuses[v] {
				return siteInvalid("operational_status must be one of planned, staged, active, decommissioning, retired")
			}
			l.OperationalStatus = v
		}
		if in.Has("facility") {
			l.Facility = trimmedPtr(in.Facility)
		}
		if in.Has("business_unit_id") {
			l.BusinessUnitID = in.BusinessUnitID
			if err := visibleIn(ctx, tx, "business_units", "business unit", l.BusinessUnitID); err != nil {
				return err
			}
		}
		if in.Has("description") {
			l.Description = in.Description
		}
		if in.Has("comments") {
			l.Comments = in.Comments
		}
		if _, err := tx.ExecContext(ctx, `UPDATE locations SET parent_id=$3, name=$4, slug=$5, operational_status=$6, facility=$7,
			business_unit_id=$8, description=$9, comments=$10, updated_at=now() WHERE tenant_id=$1 AND id=$2`,
			tenantID, id, l.ParentID, l.Name, l.Slug, l.OperationalStatus, l.Facility, l.BusinessUnitID, l.Description, l.Comments); err != nil {
			return mapUnique(err)
		}
		if out, err = s.getLocationTx(ctx, tx, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindLocation, "update", id, locationSnapshot(before), locationSnapshot(out))
	})
	return out, err
}

// DeleteLocation removes a location and its sub-locations (NetBox's CASCADE).
// Assets in any of them stay in the site and lose only the location; prefixes
// and VLAN groups scoped to them are re-scoped to the site.
func (s *SiteService) DeleteLocation(ctx context.Context, tenantID, actor, id uuid.UUID) error {
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		before, err := s.getLocationTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		subtree, err := idsWhere(ctx, tx, `
			WITH RECURSIVE down(id, d) AS (
				SELECT id, 0 FROM locations WHERE tenant_id = $1 AND id = $2
				UNION ALL
				SELECT l.id, down.d + 1 FROM locations l JOIN down ON l.parent_id = down.id WHERE down.d < 64
			) SELECT id FROM down`, tenantID, id)
		if err != nil {
			return err
		}
		site := before.SiteID
		if err := clearScopes(ctx, tx, tenantID, string(dcim.ObjectKindLocation), subtree, &site); err != nil {
			return err
		}
		for _, sub := range subtree {
			if sub == id {
				continue
			}
			sb, err := s.getLocationTx(ctx, tx, tenantID, sub)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenantID, actor, dcim.ObjectKindLocation, "delete", sub, locationSnapshot(sb), nil); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM locations WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return err
		}
		return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindLocation, "delete", id, locationSnapshot(before), nil)
	})
}

// ---------------------------------------------------------------------------
// Asset placement
// ---------------------------------------------------------------------------

// ValidateAssetPlacement is the rule DATA_MODEL section 1 puts in the service:
// an asset's location belongs to the asset's site. A location with no site is
// refused (an asset cannot be in a room of no building), as is a site or a
// location the tenant cannot see.
func ValidateAssetPlacement(ctx context.Context, tx *sqlx.Tx, siteID, locationID *uuid.UUID) error {
	if siteID != nil {
		if err := visibleIn(ctx, tx, "sites", "site", siteID); err != nil {
			return err
		}
	}
	if locationID == nil {
		return nil
	}
	if siteID == nil {
		return siteInvalid("a location needs the asset's site to be set")
	}
	var locSite uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT site_id FROM locations WHERE id = $1`, *locationID).Scan(&locSite)
	if errors.Is(err, sql.ErrNoRows) {
		return siteInvalid("location %s not found", locationID)
	}
	if err != nil {
		return err
	}
	if locSite != *siteID {
		return siteInvalid("the location is not in the asset's site")
	}
	return nil
}

// ResolveAssetPlacement turns an asset write's site/location references into
// the (site_id, location_id) pair to store, enforcing ValidateAssetPlacement.
//
//   - siteRef/locRef nil: not stated; the current value is kept.
//   - "" clears. Clearing the site clears the location with it.
//   - A location alone, with no site stated and none recorded, places the asset
//     in that location's site — the one site it can be in.
//   - A new site that the current location is not in drops the location.
//
// changed reports whether either column moves.
func ResolveAssetPlacement(ctx context.Context, tx *sqlx.Tx, curSite, curLoc *uuid.UUID, siteRef, locRef *string) (site, loc *uuid.UUID, changed bool, err error) {
	parse := func(ref *string, label string) (*uuid.UUID, bool, error) {
		if ref == nil {
			return nil, false, nil
		}
		v := strings.TrimSpace(*ref)
		if v == "" {
			return nil, true, nil
		}
		u, perr := uuid.Parse(v)
		if perr != nil {
			return nil, false, siteInvalid("%s is not a uuid", label)
		}
		return &u, true, nil
	}
	newSite, siteSet, err := parse(siteRef, "site_id")
	if err != nil {
		return nil, nil, false, err
	}
	newLoc, locSet, err := parse(locRef, "location_id")
	if err != nil {
		return nil, nil, false, err
	}
	site, loc = curSite, curLoc
	if siteSet {
		site = newSite
		if site == nil {
			loc = nil
		}
	}
	if locSet {
		loc = newLoc
	}
	if loc != nil && site == nil && !siteSet {
		var ls uuid.UUID
		if e := tx.QueryRowContext(ctx, `SELECT site_id FROM locations WHERE id = $1`, *loc).Scan(&ls); e == nil {
			site = &ls
		}
	}
	if siteSet && !locSet && loc != nil && site != nil {
		var ls uuid.UUID
		if e := tx.QueryRowContext(ctx, `SELECT site_id FROM locations WHERE id = $1`, *loc).Scan(&ls); e != nil || ls != *site {
			loc = nil
		}
	}
	if err := ValidateAssetPlacement(ctx, tx, site, loc); err != nil {
		return nil, nil, false, err
	}
	changed = uuidStr(site) != uuidStr(curSite) || uuidStr(loc) != uuidStr(curLoc)
	return site, loc, changed, nil
}

// ResolveSiteByName finds the tenant's site by name or slug (case-insensitive),
// or by external id first when given, creating it when nothing matches. It is
// how an import's site text becomes a site (NetBox's dcim/site, a CMDB
// location): the import names it, and a site with that name is either the one
// a person made or one the import now declares.
func (s *SiteService) ResolveSiteByName(ctx context.Context, tx *sqlx.Tx, tenantID, actor uuid.UUID, name, sourceKind string, sourceRef *string) (*uuid.UUID, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	if len(name) > 100 {
		name = name[:100]
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE tenant_id = $1 AND (lower(name) = lower($2) OR slug = $3)
		ORDER BY (lower(name) = lower($2)) DESC, created_at LIMIT 1`, tenantID, name, sites.Slug(name, "site")).Scan(&id)
	if err == nil {
		return &id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	id = uuid.New()
	slug, err := sites.UniqueSlug(ctx, tx, "sites", tenantID, "", uuid.Nil, sites.Slug(name, "site"), id)
	if err != nil {
		return nil, err
	}
	if sourceKind == "" {
		sourceKind = "imported"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sites (id, tenant_id, name, slug, source_kind, source_ref, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, tenantID, name, slug, sourceKind, sourceRef, nullActor(actor)); err != nil {
		return nil, mapUnique(err)
	}
	created, err := s.getSiteTx(ctx, tx, tenantID, id, false)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, tx, tenantID, actor, dcim.ObjectKindSite, "create", id, nil, siteSnapshot(created)); err != nil {
		return nil, err
	}
	return &id, nil
}

// RecordAssetPlacement records, on the asset's Changes tab, that its site or
// location moved. It writes nothing when neither did.
func (s *SiteService) RecordAssetPlacement(ctx context.Context, tx *sqlx.Tx, tenantID, actor, assetID uuid.UUID, oldSite, oldLoc, newSite, newLoc *uuid.UUID) error {
	if uuidStr(oldSite) == uuidStr(newSite) && uuidStr(oldLoc) == uuidStr(newLoc) {
		return nil
	}
	b := map[string]any{"site_id": uuidStr(oldSite), "location_id": uuidStr(oldLoc)}
	a := map[string]any{"site_id": uuidStr(newSite), "location_id": uuidStr(newLoc)}
	return s.record(ctx, tx, tenantID, actor, dcim.ObjectKindAsset, "update", assetID, b, a)
}

// siteInputError maps a placement validation failure onto the asset service's
// ErrInvalidInput so the asset handlers answer 400, not 500.
func siteInputError(err error) error {
	if errors.Is(err, ErrSiteInvalid) || errors.Is(err, ErrSiteNotFound) {
		return fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
	}
	return err
}
