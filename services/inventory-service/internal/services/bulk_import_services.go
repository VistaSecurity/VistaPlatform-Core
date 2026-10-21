package services

// The service-backed kinds of the bulk importer (bulk_import.go): business
// units, locations, assets and interfaces. Each writes through its own
// service, so that service's rules and transactions apply to an imported row
// exactly as to a person's; the rows are therefore applied one at a time and a
// dry run is a PREVIEW (references resolve, enumerations are checked, the
// create/update/unchanged decision is made) rather than the apply rolled
// back. A rule only the service knows surfaces as that row's error at apply.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type bulkExisting struct {
	ID   string
	Vals map[string]string
}

// bulkSimple is the shared shape of a service-backed kind.
type bulkSimple struct {
	db   *sql.DB
	cols []BulkColumn
	// keys are the identity keys of a row, in precedence order (lower-cased).
	keys func(vals map[string]string) []string
	// load returns every existing row, parents before children.
	load func(ctx context.Context, tenant uuid.UUID) ([]bulkExisting, error)
	// check validates provided values and resolves references; a reference to a
	// row that may exist later in the file is a *bulkUnresolvedErr.
	check func(ctx context.Context, tenant uuid.UUID, vals map[string]string, create bool, st *bulkCustomState) error
	// create writes a new row and returns its id.
	create func(ctx context.Context, tenant uuid.UUID, vals map[string]string, st *bulkCustomState) (string, error)
	// update writes the changed columns of an existing row; merged is the row as
	// it will be.
	update func(ctx context.Context, tenant uuid.UUID, ex bulkExisting, merged map[string]string, changed []string, st *bulkCustomState) error
}

type bulkSimpleState struct {
	snap map[string]*bulkExisting
	refs map[string]*bulkRefIndex
}

func (b *bulkSimple) state(ctx context.Context, tenant uuid.UUID, st *bulkCustomState) (*bulkSimpleState, error) {
	if st.simple != nil {
		return st.simple, nil
	}
	rows, err := b.load(ctx, tenant)
	if err != nil {
		return nil, err
	}
	s := &bulkSimpleState{snap: map[string]*bulkExisting{}, refs: map[string]*bulkRefIndex{}}
	for i := range rows {
		for _, k := range b.keys(rows[i].Vals) {
			s.snap[k] = &rows[i]
		}
	}
	st.simple = s
	return s, nil
}

func (b *bulkSimple) process(ctx context.Context, tenant uuid.UUID, rec BulkRecord, row int, dryRun bool, st *bulkCustomState) BulkRowResult {
	s, err := b.state(ctx, tenant, st)
	if err != nil {
		return BulkRowResult{Action: BulkError, Reason: err.Error()}
	}
	vals := map[string]string{}
	clear := map[string]bool{}
	for _, c := range b.cols {
		v := strings.TrimSpace(rec[c.Name])
		switch v {
		case "":
		case "-":
			clear[c.Name] = true
		default:
			vals[c.Name] = v
		}
	}
	fail := func(key string, err error) BulkRowResult {
		var ue *bulkUnresolvedErr
		return BulkRowResult{Action: BulkError, Key: key, Reason: bulkReason(err), unresolved: errors.As(err, &ue)}
	}
	keys := b.keys(vals)
	key := ""
	if len(keys) > 0 {
		key = keys[len(keys)-1]
	}
	label := b.label(vals)
	var ex *bulkExisting
	for _, k := range keys {
		if e, ok := s.snap[k]; ok {
			ex = e
			break
		}
	}
	create := ex == nil
	if create {
		for _, c := range b.cols {
			if c.Required && vals[c.Name] == "" {
				return fail(label, fmt.Errorf("%s is required", c.Name))
			}
		}
		if len(keys) == 0 {
			return fail(label, errors.New("the row names nothing to identify it by"))
		}
	}
	if err := b.check(ctx, tenant, vals, create, st); err != nil {
		return fail(label, err)
	}
	_ = key
	if create {
		if dryRun {
			e := &bulkExisting{Vals: vals}
			for _, k := range b.keys(vals) {
				s.snap[k] = e
			}
			return BulkRowResult{Action: BulkCreate, Key: label}
		}
		id, err := b.create(ctx, tenant, vals, st)
		if err != nil {
			return fail(label, err)
		}
		e := &bulkExisting{ID: id, Vals: vals}
		for _, k := range b.keys(vals) {
			s.snap[k] = e
		}
		return BulkRowResult{Action: BulkCreate, Key: label, ID: id}
	}

	merged := map[string]string{}
	for k, v := range ex.Vals {
		merged[k] = v
	}
	var changed []string
	for _, c := range b.cols {
		if clear[c.Name] {
			if merged[c.Name] != "" {
				merged[c.Name] = ""
				changed = append(changed, c.Name)
			}
			continue
		}
		v, ok := vals[c.Name]
		if !ok || bulkSimpleEqual(merged[c.Name], v) {
			continue
		}
		merged[c.Name] = v
		changed = append(changed, c.Name)
	}
	if len(changed) == 0 {
		return BulkRowResult{Action: BulkUnchanged, Key: label, ID: ex.ID}
	}
	if !dryRun {
		if err := b.update(ctx, tenant, *ex, merged, changed, st); err != nil {
			return fail(label, err)
		}
	}
	ex.Vals = merged
	return BulkRowResult{Action: BulkUpdate, Key: label, ID: ex.ID, Changed: changed}
}

// label is the human key of a row: its first identity column values.
func (b *bulkSimple) label(vals map[string]string) string {
	var parts []string
	for _, c := range b.cols {
		if c.Required && vals[c.Name] != "" {
			parts = append(parts, vals[c.Name])
		}
	}
	return strings.Join(parts, " ")
}

func bulkSimpleEqual(a, b string) bool {
	if a == b {
		return true
	}
	fa, e1 := strconv.ParseFloat(a, 64)
	fb, e2 := strconv.ParseFloat(b, 64)
	if e1 == nil && e2 == nil {
		return fa == fb
	}
	return strings.EqualFold(a, b) && (a == "true" || a == "false" || strings.EqualFold(a, "true") || strings.EqualFold(a, "false"))
}

func (b *bulkSimple) export(ctx context.Context, tenant uuid.UUID, q BulkExportQuery, emit func(BulkRecord) error) error {
	rows, err := b.load(ctx, tenant)
	if err != nil {
		return err
	}
	needle := strings.ToLower(strings.TrimSpace(q.Q))
	for _, r := range rows {
		if needle != "" {
			hit := false
			for _, v := range r.Vals {
				if strings.Contains(strings.ToLower(v), needle) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		rec := BulkRecord{}
		for _, c := range b.cols {
			rec[c.Name] = r.Vals[c.Name]
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

// ref resolves a label through a bulkRefs index.
func (b *bulkSimple) ref(ctx context.Context, tenant uuid.UUID, st *bulkCustomState, key, col, cell string) (string, error) {
	s, err := b.state(ctx, tenant, st)
	if err != nil {
		return "", err
	}
	idx, ok := s.refs[key]
	if !ok {
		err := database.WithTenantTx(ctx, b.db, tenant, func(tx *sql.Tx) error {
			var err error
			idx, err = loadBulkRef(ctx, tx, key)
			return err
		})
		if err != nil {
			return "", err
		}
		s.refs[key] = idx
	}
	ids := idx.byLabel[strings.ToLower(cell)]
	switch len(ids) {
	case 0:
		return "", &bulkUnresolvedErr{msg: fmt.Sprintf("%s: no %s named %q", col, strings.ReplaceAll(key, "_", " "), cell)}
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("%s: %q names %d %ss; make it unambiguous", col, cell, len(ids), strings.ReplaceAll(key, "_", " "))
}

// ---- registry ----------------------------------------------------------------

type bulkCustomEntry struct {
	info BulkKindInfo
	impl bulkCustomKind
}

func bulkCustomKinds(db *sql.DB, deps BulkDeps) []bulkCustomEntry {
	var out []bulkCustomEntry
	add := func(kind dcim.ObjectKind, label, plural, perm string, b *bulkSimple) {
		b.db = db
		out = append(out, bulkCustomEntry{
			info: BulkKindInfo{Kind: string(kind), Label: label, Plural: plural, Permission: perm, Columns: b.cols, Preview: true},
			impl: b,
		})
	}
	add(dcim.ObjectKindBusinessUnit, "Business unit", "Business units", rbac.PermissionBusinessUnitsManage, businessUnitBulk(deps))
	add(dcim.ObjectKindSite, "Site", "Sites", rbac.PermissionDcimManage, siteBulk(db, deps))
	add(dcim.ObjectKindLocation, "Location", "Locations", rbac.PermissionDcimManage, locationBulk(db, deps))
	add(dcim.ObjectKindAsset, "Asset", "Assets", rbac.PermissionAssetsUpdate, assetBulk(db, deps))
	add(dcim.ObjectKindInterface, "Interface", "Interfaces", rbac.PermissionDcimManage, interfaceBulk(db, deps))
	return out
}

func bulkJoinPath(parent, name, sep string) string {
	if parent == "" {
		return name
	}
	return parent + sep + name
}

func bulkActorID(ctx context.Context) uuid.UUID {
	if a, ok := changes.ActorFrom(ctx); ok {
		return a.UserID
	}
	return uuid.Nil
}

func bulkStrPtr(s string) *string { return &s }

func bulkNullStr(n sql.NullString) string {
	if n.Valid {
		return n.String
	}
	return ""
}

// ---- business units ----------------------------------------------------------

func businessUnitBulk(deps BulkDeps) *bulkSimple {
	b := &bulkSimple{
		cols: []BulkColumn{
			{Name: "name", Required: true, Example: "Finance"},
			{Name: "parent", Example: "Corporate", Help: "Path of the parent unit, Parent/Child; blank for a top-level unit."},
			{Name: "slug", Example: "finance"},
			{Name: "description", Example: "Finance and accounting"},
			{Name: "comments", Example: ""},
		},
	}
	b.keys = func(v map[string]string) []string {
		if v["name"] == "" {
			return nil
		}
		return []string{strings.ToLower(bulkJoinPath(v["parent"], v["name"], "/"))}
	}
	b.load = func(ctx context.Context, tenant uuid.UUID) ([]bulkExisting, error) {
		var out []bulkExisting
		err := database.WithTenantTx(ctx, b.db, tenant, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, `WITH RECURSIVE p AS (
				SELECT id, name::text AS path, ''::text AS parent, 1 AS depth FROM public.business_units WHERE parent_id IS NULL
				UNION ALL SELECT c.id, p.path || '/' || c.name, p.path, p.depth + 1 FROM public.business_units c JOIN p ON c.parent_id = p.id)
				SELECT b.id::text, b.name, p.parent, b.slug, b.description, b.comments
				  FROM p JOIN public.business_units b ON b.id = p.id ORDER BY p.depth, lower(p.path), b.id`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id, name, parent, slug string
				var desc, comm sql.NullString
				if err := rows.Scan(&id, &name, &parent, &slug, &desc, &comm); err != nil {
					return err
				}
				out = append(out, bulkExisting{ID: id, Vals: map[string]string{
					"name": name, "parent": parent, "slug": slug, "description": bulkNullStr(desc), "comments": bulkNullStr(comm)}})
			}
			return rows.Err()
		})
		return out, err
	}
	b.check = func(ctx context.Context, tenant uuid.UUID, v map[string]string, create bool, st *bulkCustomState) error {
		if p := v["parent"]; p != "" {
			s, err := b.state(ctx, tenant, st)
			if err != nil {
				return err
			}
			if _, ok := s.snap[strings.ToLower(p)]; !ok {
				return &bulkUnresolvedErr{msg: fmt.Sprintf("parent: no business unit %q", p)}
			}
		}
		return nil
	}
	b.create = func(ctx context.Context, tenant uuid.UUID, v map[string]string, st *bulkCustomState) (string, error) {
		in := models.BusinessUnitInput{Name: bulkStrPtr(v["name"])}
		if v["slug"] != "" {
			in.Slug = bulkStrPtr(v["slug"])
		}
		if v["description"] != "" {
			in.Description = bulkStrPtr(v["description"])
		}
		if v["comments"] != "" {
			in.Comments = bulkStrPtr(v["comments"])
		}
		if p := v["parent"]; p != "" {
			s, _ := b.state(ctx, tenant, st)
			pid, err := uuid.Parse(s.snap[strings.ToLower(p)].ID)
			if err != nil {
				return "", &bulkUnresolvedErr{msg: fmt.Sprintf("parent: business unit %q is not created yet", p)}
			}
			in.ParentID = &pid
		}
		ref := bulkSourceRef
		bu, err := deps.BusinessUnits.CreateImported(ctx, tenant, in, &ref)
		if err != nil {
			return "", err
		}
		return bu.ID.String(), nil
	}
	b.update = func(ctx context.Context, tenant uuid.UUID, ex bulkExisting, m map[string]string, changed []string, _ *bulkCustomState) error {
		id, err := uuid.Parse(ex.ID)
		if err != nil {
			return err
		}
		in := models.BusinessUnitInput{}
		for _, c := range changed {
			switch c {
			case "name":
				in.Name = bulkStrPtr(m["name"])
			case "slug":
				in.Slug = bulkStrPtr(m["slug"])
			case "description":
				in.Description = bulkStrPtr(m["description"])
			case "comments":
				in.Comments = bulkStrPtr(m["comments"])
			}
		}
		_, err = deps.BusinessUnits.Update(ctx, tenant, bulkActorID(ctx), id, in)
		return err
	}
	return b
}

// ---- sites ---------------------------------------------------------------------

// siteBulk is the site kind (row 2.1). A site is matched on its name. Region,
// site group and business unit are not columns yet: they are set in the
// site's form until their own bulk kinds exist.
func siteBulk(db *sql.DB, deps BulkDeps) *bulkSimple {
	b := &bulkSimple{
		cols: []BulkColumn{
			{Name: "name", Required: true, Example: "HQ"},
			{Name: "slug", Example: ""},
			{Name: "operational_status", Example: "active", Help: "planned, staged, active, decommissioning or retired; blank is active."},
			{Name: "facility", Example: ""}, {Name: "time_zone", Example: "America/Los_Angeles"},
			{Name: "physical_address", Example: "1 Main St, Portland OR"}, {Name: "shipping_address", Example: ""},
			{Name: "latitude", Example: "45.52"}, {Name: "longitude", Example: "-122.67"},
			{Name: "description", Example: ""}, {Name: "comments", Example: ""},
		},
	}
	b.keys = func(v map[string]string) []string {
		if v["name"] == "" {
			return nil
		}
		return []string{strings.ToLower(v["name"])}
	}
	b.load = func(ctx context.Context, tenant uuid.UUID) ([]bulkExisting, error) {
		var out []bulkExisting
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, `SELECT id::text, name, slug, operational_status, facility, time_zone, physical_address,
				shipping_address, latitude::text, longitude::text, description, comments FROM public.sites ORDER BY lower(name), id`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id, name, slug, status string
				var facility, tz, phys, ship, lat, lon, desc, comments sql.NullString
				if err := rows.Scan(&id, &name, &slug, &status, &facility, &tz, &phys, &ship, &lat, &lon, &desc, &comments); err != nil {
					return err
				}
				out = append(out, bulkExisting{ID: id, Vals: map[string]string{
					"name": name, "slug": slug, "operational_status": status, "facility": bulkNullStr(facility),
					"time_zone": bulkNullStr(tz), "physical_address": bulkNullStr(phys), "shipping_address": bulkNullStr(ship),
					"latitude": bulkNullStr(lat), "longitude": bulkNullStr(lon),
					"description": bulkNullStr(desc), "comments": bulkNullStr(comments)}})
			}
			return rows.Err()
		})
		return out, err
	}
	b.check = func(_ context.Context, _ uuid.UUID, v map[string]string, _ bool, _ *bulkCustomState) error {
		if s := v["operational_status"]; s != "" && !validSiteStatuses[s] {
			return fmt.Errorf("operational_status %q is not one of planned, staged, active, decommissioning, retired", s)
		}
		for _, n := range []string{"latitude", "longitude"} {
			if v[n] != "" {
				if _, err := strconv.ParseFloat(v[n], 64); err != nil {
					return fmt.Errorf("%s: %q is not a number", n, v[n])
				}
			}
		}
		return nil
	}
	opt := func(v map[string]string, k string) *string {
		if v[k] == "" {
			return nil
		}
		return bulkStrPtr(v[k])
	}
	fl := func(v map[string]string, k string) *float64 {
		if v[k] == "" {
			return nil
		}
		f, _ := strconv.ParseFloat(v[k], 64)
		return &f
	}
	b.create = func(ctx context.Context, tenant uuid.UUID, v map[string]string, _ *bulkCustomState) (string, error) {
		site, err := deps.Sites.CreateSite(ctx, tenant, bulkActorID(ctx), models.SiteInput{
			Name: bulkStrPtr(v["name"]), Slug: opt(v, "slug"), OperationalStatus: opt(v, "operational_status"),
			Facility: opt(v, "facility"), TimeZone: opt(v, "time_zone"), PhysicalAddress: opt(v, "physical_address"),
			ShippingAddress: opt(v, "shipping_address"), Latitude: fl(v, "latitude"), Longitude: fl(v, "longitude"),
			Description: opt(v, "description"), Comments: opt(v, "comments"),
		})
		if err != nil {
			return "", err
		}
		return site.ID.String(), nil
	}
	b.update = func(ctx context.Context, tenant uuid.UUID, ex bulkExisting, m map[string]string, changed []string, _ *bulkCustomState) error {
		id, err := uuid.Parse(ex.ID)
		if err != nil {
			return err
		}
		in := models.SiteInput{Set: map[string]bool{}}
		for _, c := range changed {
			switch c {
			case "name":
				in.Name = bulkStrPtr(m["name"])
			case "slug":
				in.Slug = opt(m, "slug")
			case "operational_status":
				in.OperationalStatus = opt(m, "operational_status")
			case "facility":
				in.Facility = opt(m, "facility")
			case "time_zone":
				in.TimeZone = opt(m, "time_zone")
			case "physical_address":
				in.PhysicalAddress = opt(m, "physical_address")
			case "shipping_address":
				in.ShippingAddress = opt(m, "shipping_address")
			case "latitude":
				in.Latitude = fl(m, "latitude")
			case "longitude":
				in.Longitude = fl(m, "longitude")
			case "description":
				in.Description = opt(m, "description")
			case "comments":
				in.Comments = opt(m, "comments")
			default:
				continue
			}
			in.Set[c] = true
		}
		_, err = deps.Sites.UpdateSite(ctx, tenant, bulkActorID(ctx), id, in)
		return err
	}
	return b
}

// ---- locations ----------------------------------------------------------------

// locationBulk is the within-site location tree (row 2.1): a location belongs
// to exactly one site, so its identity is site + path ("HQ / Floor 2 / Room
// 201"), and parent is a path inside that site.
func locationBulk(db *sql.DB, deps BulkDeps) *bulkSimple {
	b := &bulkSimple{
		cols: []BulkColumn{
			{Name: "site", Required: true, Example: "HQ", Help: "The site the location is in, by name."},
			{Name: "name", Required: true, Example: "Room 201"},
			{Name: "parent", Example: "Floor 2", Help: "Path of the parent inside the site, Parent / Child; blank for a top-level location."},
			{Name: "slug", Example: ""},
			{Name: "operational_status", Example: "active", Help: "planned, staged, active, decommissioning or retired; blank is active."},
			{Name: "facility", Example: ""}, {Name: "description", Example: ""}, {Name: "comments", Example: ""},
		},
	}
	pathKey := func(site, parent, name string) string {
		return strings.ToLower(site + " / " + bulkJoinPath(parent, name, " / "))
	}
	b.keys = func(v map[string]string) []string {
		if v["site"] == "" || v["name"] == "" {
			return nil
		}
		return []string{pathKey(v["site"], v["parent"], v["name"])}
	}
	b.load = func(ctx context.Context, tenant uuid.UUID) ([]bulkExisting, error) {
		var out []bulkExisting
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, `WITH RECURSIVE p AS (
				SELECT id, name::text AS path, ''::text AS parent, 1 AS depth FROM public.locations WHERE parent_id IS NULL
				UNION ALL SELECT c.id, p.path || ' / ' || c.name, p.path, p.depth + 1 FROM public.locations c JOIN p ON c.parent_id = p.id)
				SELECT l.id::text, s.name, l.name, p.parent, l.slug, l.operational_status, l.facility, l.description, l.comments
				  FROM p JOIN public.locations l ON l.id = p.id JOIN public.sites s ON s.id = l.site_id
				 ORDER BY p.depth, lower(s.name), lower(p.path), l.id`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id, site, name, parent, slug, status string
				var facility, desc, comments sql.NullString
				if err := rows.Scan(&id, &site, &name, &parent, &slug, &status, &facility, &desc, &comments); err != nil {
					return err
				}
				out = append(out, bulkExisting{ID: id, Vals: map[string]string{
					"site": site, "name": name, "parent": parent, "slug": slug, "operational_status": status,
					"facility": bulkNullStr(facility), "description": bulkNullStr(desc), "comments": bulkNullStr(comments)}})
			}
			return rows.Err()
		})
		return out, err
	}
	siteID := func(ctx context.Context, tenant uuid.UUID, name string) (uuid.UUID, error) {
		var id uuid.UUID
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT id FROM public.sites WHERE lower(name) = lower($1) ORDER BY id LIMIT 1`, name).Scan(&id)
		})
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("site: no site %q", name)
		}
		return id, err
	}
	b.check = func(ctx context.Context, tenant uuid.UUID, v map[string]string, create bool, st *bulkCustomState) error {
		if s := v["operational_status"]; s != "" && !validSiteStatuses[s] {
			return fmt.Errorf("operational_status %q is not one of planned, staged, active, decommissioning, retired", s)
		}
		if v["site"] != "" {
			if _, err := siteID(ctx, tenant, v["site"]); err != nil {
				return err
			}
		}
		if p := v["parent"]; p != "" {
			s, err := b.state(ctx, tenant, st)
			if err != nil {
				return err
			}
			if _, ok := s.snap[strings.ToLower(v["site"]+" / "+p)]; !ok {
				return &bulkUnresolvedErr{msg: fmt.Sprintf("parent: no location %q in site %q", p, v["site"])}
			}
		}
		return nil
	}
	parentOf := func(ctx context.Context, tenant uuid.UUID, v map[string]string, st *bulkCustomState) (*uuid.UUID, error) {
		if v["parent"] == "" {
			return nil, nil
		}
		s, _ := b.state(ctx, tenant, st)
		ex := s.snap[strings.ToLower(v["site"]+" / "+v["parent"])]
		if ex == nil {
			return nil, &bulkUnresolvedErr{msg: fmt.Sprintf("parent: no location %q in site %q", v["parent"], v["site"])}
		}
		pid, err := uuid.Parse(ex.ID)
		if err != nil {
			return nil, &bulkUnresolvedErr{msg: fmt.Sprintf("parent: location %q is not created yet", v["parent"])}
		}
		return &pid, nil
	}
	opt := func(v map[string]string, k string) *string {
		if v[k] == "" {
			return nil
		}
		return bulkStrPtr(v[k])
	}
	b.create = func(ctx context.Context, tenant uuid.UUID, v map[string]string, st *bulkCustomState) (string, error) {
		sid, err := siteID(ctx, tenant, v["site"])
		if err != nil {
			return "", err
		}
		pid, err := parentOf(ctx, tenant, v, st)
		if err != nil {
			return "", err
		}
		loc, err := deps.Sites.CreateLocation(ctx, tenant, bulkActorID(ctx), models.LocationInput{
			SiteID: &sid, ParentID: pid, Name: bulkStrPtr(v["name"]), Slug: opt(v, "slug"), OperationalStatus: opt(v, "operational_status"),
			Facility: opt(v, "facility"), Description: opt(v, "description"), Comments: opt(v, "comments"),
		})
		if err != nil {
			return "", err
		}
		return loc.ID.String(), nil
	}
	b.update = func(ctx context.Context, tenant uuid.UUID, ex bulkExisting, m map[string]string, changed []string, st *bulkCustomState) error {
		id, err := uuid.Parse(ex.ID)
		if err != nil {
			return err
		}
		in := models.LocationInput{Set: map[string]bool{}}
		for _, c := range changed {
			switch c {
			case "name":
				in.Name = bulkStrPtr(m["name"])
			case "parent":
				if in.ParentID, err = parentOf(ctx, tenant, m, st); err != nil {
					return err
				}
				c = "parent_id"
			case "slug":
				in.Slug = opt(m, "slug")
			case "operational_status":
				in.OperationalStatus = opt(m, "operational_status")
			case "facility":
				in.Facility = opt(m, "facility")
			case "description":
				in.Description = opt(m, "description")
			case "comments":
				in.Comments = opt(m, "comments")
			default:
				continue
			}
			in.Set[c] = true
		}
		_, err = deps.Sites.UpdateLocation(ctx, tenant, bulkActorID(ctx), id, in)
		return err
	}
	return b
}

// ---- assets ------------------------------------------------------------------

func assetBulk(db *sql.DB, deps BulkDeps) *bulkSimple {
	b := &bulkSimple{
		cols: []BulkColumn{
			{Name: "display_name", Example: "core-sw-01", Help: "With class_key, how an asset without an asset_tag is matched."},
			{Name: "class_key", Required: true, Example: "network_switch", Help: "An asset class from the class registry."},
			{Name: "hostname", Example: "core-sw-01.example.test"},
			{Name: "ip_address", Example: "10.10.0.2"},
			{Name: "environment", Example: "production"},
			{Name: "business_unit", Ref: "business_unit", Example: "", Help: "Business unit path, Parent/Child."},
			{Name: "owner_email", Example: ""}, {Name: "support_group", Example: ""},
			{Name: "device_type", Ref: "device_type", Example: "Cisco/C9300-48P", Help: "Manufacturer/model."},
			{Name: "device_role", Ref: "device_role", Example: "Core switch"},
			{Name: "platform", Ref: "platform", Example: "IOS XE"},
			{Name: "serial", Example: "FOC1234ABCD"},
			{Name: "asset_tag", Example: "A-0001", Help: "When present, the asset is matched on it."},
			{Name: "description", Example: ""},
			// The commercial lifecycle (DCIM gap 4), written through the same
			// hardware PATCH as serial and asset_tag.
			{Name: "purchase_date", Example: "2024-03-01", Help: "YYYY-MM-DD."},
			{Name: "warranty_start", Example: "2024-03-01", Help: "YYYY-MM-DD."},
			{Name: "warranty_end", Example: "2027-02-28", Help: "YYYY-MM-DD; not before warranty_start."},
			{Name: "purchase_cost", Example: "4200.00", Help: "A non-negative amount, at most two decimals."},
			{Name: "purchase_currency", Example: "USD", Help: "ISO 4217 code."},
			{Name: "purchase_order", Example: "PO-1001"},
			{Name: "vendor", Example: "", Help: "Who sold it (the reseller), not the manufacturer."},
			{Name: "support_contract", Example: ""},
			{Name: "support_contract_end", Example: "", Help: "YYYY-MM-DD."},
			{Name: "installed_at", Example: "", Help: "YYYY-MM-DD."},
			{Name: "decommissioned_at", Example: "", Help: "YYYY-MM-DD; not before installed_at."},
		},
	}
	// Placement columns (site, location, rack, position, face) are one more
	// spec entry each once row 2.3 is on main; see BUILD_PLAN row 2.7.
	b.keys = func(v map[string]string) []string {
		var ks []string
		if v["asset_tag"] != "" {
			ks = append(ks, "tag:"+strings.ToLower(v["asset_tag"]))
		}
		if v["class_key"] != "" && v["hostname"] != "" {
			ks = append(ks, "host:"+v["class_key"]+"|"+strings.ToLower(v["hostname"]))
		}
		if v["class_key"] != "" && v["display_name"] != "" {
			ks = append(ks, "name:"+v["class_key"]+"|"+strings.ToLower(v["display_name"]))
		}
		return ks
	}
	b.load = func(ctx context.Context, tenant uuid.UUID) ([]bulkExisting, error) {
		var out []bulkExisting
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, `
				SELECT a.id::text, COALESCE(a.display_name, ''), a.class_key, COALESCE(a.hostname, ''), COALESCE(host(a.primary_address), ''),
				       COALESCE(a.environment::text, ''), COALESCE(bu.path, ''), COALESCE(a.owner_email, ''), COALESCE(a.support_group, ''),
				       COALESCE(m.name || '/' || dt.model, ''), COALESCE(r.name, ''), COALESCE(p.name, ''),
				       COALESCE(a.serial, ''), COALESCE(a.asset_tag, ''), COALESCE(a.description, ''),
				       COALESCE(a.purchase_date::text, ''), COALESCE(a.warranty_start::text, ''), COALESCE(a.warranty_end::text, ''),
				       COALESCE(a.purchase_cost::text, ''), COALESCE(a.purchase_currency::text, ''), COALESCE(a.purchase_order, ''),
				       COALESCE(a.vendor, ''), COALESCE(a.support_contract, ''), COALESCE(a.support_contract_end::text, ''),
				       COALESCE(a.installed_at::text, ''), COALESCE(a.decommissioned_at::text, '')
				  FROM public.assets a
				  LEFT JOIN public.device_types dt ON dt.id = a.device_type_id
				  LEFT JOIN public.manufacturers m ON m.id = dt.manufacturer_id
				  LEFT JOIN public.device_roles r ON r.id = a.device_role_id
				  LEFT JOIN public.platforms p ON p.id = a.platform_id
				  LEFT JOIN (WITH RECURSIVE t AS (
				      SELECT id, name::text AS path FROM public.business_units WHERE parent_id IS NULL
				      UNION ALL SELECT c.id, t.path || '/' || c.name FROM public.business_units c JOIN t ON c.parent_id = t.id)
				      SELECT id, path FROM t) bu ON bu.id = a.business_unit_id
				 WHERE a.deleted_at IS NULL
				 ORDER BY lower(COALESCE(a.display_name, a.hostname, '')), a.class_key, a.id`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id string
				commercial := CommercialFields()
				v := make([]string, 14+len(commercial))
				dest := []any{&id}
				for i := range v {
					dest = append(dest, &v[i])
				}
				if err := rows.Scan(dest...); err != nil {
					return err
				}
				vals := map[string]string{
					"display_name": v[0], "class_key": v[1], "hostname": v[2], "ip_address": v[3], "environment": v[4],
					"business_unit": v[5], "owner_email": v[6], "support_group": v[7], "device_type": v[8], "device_role": v[9],
					"platform": v[10], "serial": v[11], "asset_tag": v[12], "description": v[13]}
				for i, k := range commercial {
					vals[k] = v[14+i]
				}
				out = append(out, bulkExisting{ID: id, Vals: vals})
			}
			return rows.Err()
		})
		return out, err
	}
	refCols := map[string]string{"business_unit": "business_unit", "device_type": "device_type", "device_role": "device_role", "platform": "platform"}
	b.check = func(ctx context.Context, tenant uuid.UUID, v map[string]string, create bool, st *bulkCustomState) error {
		if create && v["display_name"] == "" && v["hostname"] == "" && v["asset_tag"] == "" {
			return errors.New("display_name, hostname or asset_tag is required to identify a new asset")
		}
		// The commercial cells are checked here, in the dry run, by the same
		// parser the write uses — a bad date is a row error, not a failed apply.
		for _, col := range CommercialFields() {
			if v[col] == "" {
				continue
			}
			raw, _ := json.Marshal(v[col])
			if _, err := parseHardwareValue(col, hardwareFields[col], raw); err != nil {
				return err
			}
		}
		for col, key := range refCols {
			if v[col] != "" {
				if _, err := b.ref(ctx, tenant, st, key, col, v[col]); err != nil {
					return err
				}
			}
		}
		return nil
	}
	hardware := func(ctx context.Context, tenant uuid.UUID, id uuid.UUID, v map[string]string, only map[string]bool, st *bulkCustomState) error {
		patch := HardwarePatch{}
		put := func(field string, val any) {
			raw, _ := json.Marshal(val)
			patch[field] = raw
		}
		// Column → asset field. Built as pairs rather than a string-literal map so the
		// device-type literal scanner (shared/assetclass) does not read "device_type":
		// "…" as a collector naming a device type.
		for _, cf := range []struct{ col, field string }{{"device_type", "device_type_id"}, {"device_role", "device_role_id"}, {"platform", "platform_id"}} {
			col, field := cf.col, cf.field
			if only != nil && !only[col] {
				continue
			}
			if v[col] == "" {
				if only != nil {
					put(field, nil)
				}
				continue
			}
			rid, err := b.ref(ctx, tenant, st, refCols[col], col, v[col])
			if err != nil {
				return err
			}
			put(field, rid)
		}
		for _, col := range append([]string{"serial", "asset_tag"}, CommercialFields()...) {
			if only != nil && !only[col] {
				continue
			}
			if v[col] == "" && only == nil {
				continue
			}
			if v[col] == "" {
				put(col, nil)
			} else {
				put(col, v[col])
			}
		}
		if len(patch) == 0 {
			return nil
		}
		_, err := deps.Catalogue.UpdateHardware(ctx, tenant, id, patch)
		return err
	}
	input := func(ctx context.Context, tenant uuid.UUID, v map[string]string, st *bulkCustomState) (models.AssetInput, error) {
		in := models.AssetInput{ClassKey: v["class_key"]}
		opt := func(k string) *string {
			if v[k] == "" {
				return nil
			}
			return bulkStrPtr(v[k])
		}
		in.DisplayName, in.Hostname, in.IPAddress = opt("display_name"), opt("hostname"), opt("ip_address")
		in.Environment, in.OwnerEmail, in.SupportGroup, in.Description = opt("environment"), opt("owner_email"), opt("support_group"), opt("description")
		if v["business_unit"] != "" {
			id, err := b.ref(ctx, tenant, st, "business_unit", "business_unit", v["business_unit"])
			if err != nil {
				return in, err
			}
			in.BusinessUnitID = &id
		}
		return in, nil
	}
	b.create = func(ctx context.Context, tenant uuid.UUID, v map[string]string, st *bulkCustomState) (string, error) {
		in, err := input(ctx, tenant, v, st)
		if err != nil {
			return "", err
		}
		a, outcome, err := deps.Assets.CreateAssetFromSource(tenant, in, identity.Source{Kind: identity.SourceImported, Ref: bulkSourceRef})
		if err != nil {
			return "", err
		}
		if a == nil {
			return "", fmt.Errorf("the identity engine did not create an asset (%s)", outcome)
		}
		if v["display_name"] != "" && (a.DisplayName == nil || *a.DisplayName != v["display_name"]) {
			// The identity engine derives a display name from the identifiers; the
			// file's name is the person's, so it is written as an edit.
			if _, _, err := deps.Assets.UpdateAsset(tenant, a.ID, models.AssetInput{DisplayName: bulkStrPtr(v["display_name"])}, bulkActorID(ctx)); err != nil {
				return a.ID.String(), fmt.Errorf("created, but the display name failed: %w", err)
			}
		}
		if err := hardware(ctx, tenant, a.ID, v, nil, st); err != nil {
			return a.ID.String(), fmt.Errorf("created, but the hardware columns failed: %w", err)
		}
		return a.ID.String(), nil
	}
	b.update = func(ctx context.Context, tenant uuid.UUID, ex bulkExisting, m map[string]string, changed []string, st *bulkCustomState) error {
		id, err := uuid.Parse(ex.ID)
		if err != nil {
			return err
		}
		only := map[string]bool{}
		ctxCols := false
		for _, c := range changed {
			only[c] = true
			switch c {
			case "device_type", "device_role", "platform", "serial", "asset_tag":
			default:
				if _, commercial := hardwareFields[c]; !commercial {
					ctxCols = true
				}
			}
		}
		if ctxCols {
			in, err := input(ctx, tenant, m, st)
			if err != nil {
				return err
			}
			if _, _, err := deps.Assets.UpdateAsset(tenant, id, in, bulkActorID(ctx)); err != nil {
				return err
			}
		}
		return hardware(ctx, tenant, id, m, only, st)
	}
	return b
}

// ---- interfaces --------------------------------------------------------------

func interfaceBulk(db *sql.DB, deps BulkDeps) *bulkSimple {
	b := &bulkSimple{
		cols: []BulkColumn{
			{Name: "asset", Required: true, Ref: "asset", Example: "A-0001", Help: "The asset's asset_tag, or its name when it has none."},
			{Name: "name", Required: true, Example: "GigabitEthernet1/0/1"},
			{Name: "type", Required: true, Example: "1000base-t", Help: "An interface type key."},
			{Name: "label", Example: ""}, {Name: "enabled", Example: "true"}, {Name: "mgmt_only", Example: "false"},
			{Name: "mtu", Example: "1500"}, {Name: "mac_address", Example: "00:11:22:33:44:55"},
			{Name: "speed_kbps", Example: "1000000"}, {Name: "duplex", Example: "full"}, {Name: "mode", Example: "access"},
			{Name: "description", Example: "Uplink"},
		},
	}
	b.keys = func(v map[string]string) []string {
		if v["asset"] == "" || v["name"] == "" {
			return nil
		}
		return []string{strings.ToLower(v["asset"]) + "\x00" + strings.ToLower(v["name"])}
	}
	b.load = func(ctx context.Context, tenant uuid.UUID) ([]bulkExisting, error) {
		var out []bulkExisting
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			rows, err := tx.QueryContext(ctx, `
				SELECT i.id::text, COALESCE(NULLIF(a.asset_tag, ''), NULLIF(a.display_name, ''), a.hostname, ''), i.name, i.type,
				       COALESCE(i.label, ''), i.enabled, i.mgmt_only, COALESCE(i.mtu::text, ''),
				       COALESCE((SELECT m.mac::text FROM public.mac_addresses m WHERE m.interface_id = i.id AND m.is_primary LIMIT 1), ''),
				       COALESCE(i.speed_kbps::text, ''), COALESCE(i.duplex, ''), COALESCE(i.mode, ''), COALESCE(i.description, '')
				  FROM public.interfaces i JOIN public.assets a ON a.id = i.asset_id AND a.tenant_id = i.tenant_id
				 WHERE a.deleted_at IS NULL AND i.status <> 'rejected'
				 ORDER BY 2, `+interfaceNaturalOrder+`, i.id`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id, asset, name, typ, label, mtu, mac, speed, duplex, mode, desc string
				var enabled, mgmt bool
				if err := rows.Scan(&id, &asset, &name, &typ, &label, &enabled, &mgmt, &mtu, &mac, &speed, &duplex, &mode, &desc); err != nil {
					return err
				}
				out = append(out, bulkExisting{ID: id, Vals: map[string]string{
					"asset": asset, "name": name, "type": typ, "label": label, "enabled": strconv.FormatBool(enabled),
					"mgmt_only": strconv.FormatBool(mgmt), "mtu": mtu, "mac_address": mac, "speed_kbps": speed,
					"duplex": duplex, "mode": mode, "description": desc}})
			}
			return rows.Err()
		})
		return out, err
	}
	b.check = func(ctx context.Context, tenant uuid.UUID, v map[string]string, create bool, st *bulkCustomState) error {
		if v["asset"] != "" {
			if _, err := b.ref(ctx, tenant, st, "asset", "asset", v["asset"]); err != nil {
				return err
			}
		}
		for _, n := range []string{"enabled", "mgmt_only"} {
			if v[n] != "" {
				if _, err := bulkParseCell(n, ipamCol{Type: colBool}, v[n]); err != nil {
					return err
				}
			}
		}
		for _, n := range []string{"mtu", "speed_kbps"} {
			if v[n] != "" {
				if _, err := strconv.ParseInt(v[n], 10, 64); err != nil {
					return fmt.Errorf("%s: %q is not a whole number", n, v[n])
				}
			}
		}
		return nil
	}
	b.create = func(ctx context.Context, tenant uuid.UUID, v map[string]string, st *bulkCustomState) (string, error) {
		aid, err := b.ref(ctx, tenant, st, "asset", "asset", v["asset"])
		if err != nil {
			return "", err
		}
		asset, err := uuid.Parse(aid)
		if err != nil {
			return "", err
		}
		in := InterfaceInput{AssetID: asset, Name: v["name"], Type: v["type"]}
		opt := func(k string) *string {
			if v[k] == "" {
				return nil
			}
			return bulkStrPtr(v[k])
		}
		in.Label, in.MACAddress, in.Duplex, in.Mode, in.Description = opt("label"), opt("mac_address"), opt("duplex"), opt("mode"), opt("description")
		if v["enabled"] != "" {
			e, _ := bulkParseCell("enabled", ipamCol{Type: colBool}, v["enabled"])
			eb := e.(bool)
			in.Enabled = &eb
		}
		if v["mgmt_only"] != "" {
			m, _ := bulkParseCell("mgmt_only", ipamCol{Type: colBool}, v["mgmt_only"])
			in.MgmtOnly = m.(bool)
		}
		if v["mtu"] != "" {
			n, _ := strconv.Atoi(v["mtu"])
			in.MTU = &n
		}
		if v["speed_kbps"] != "" {
			n, _ := strconv.ParseInt(v["speed_kbps"], 10, 64)
			in.SpeedKbps = &n
		}
		out, err := deps.Interfaces.Create(ctx, tenant, bulkActorID(ctx), in)
		if err != nil {
			return "", err
		}
		return out.ID.String(), nil
	}
	b.update = func(ctx context.Context, tenant uuid.UUID, ex bulkExisting, m map[string]string, changed []string, _ *bulkCustomState) error {
		id, err := uuid.Parse(ex.ID)
		if err != nil {
			return err
		}
		patch := map[string]json.RawMessage{}
		for _, c := range changed {
			var val any
			switch c {
			case "enabled", "mgmt_only":
				if m[c] == "" {
					continue
				}
				bv, _ := bulkParseCell(c, ipamCol{Type: colBool}, m[c])
				val = bv
			case "mtu", "speed_kbps":
				if m[c] != "" {
					n, _ := strconv.ParseInt(m[c], 10, 64)
					val = n
				}
			default:
				if m[c] != "" {
					val = m[c]
				}
			}
			raw, _ := json.Marshal(val)
			patch[c] = raw
		}
		_, err = deps.Interfaces.Patch(ctx, tenant, id, patch)
		return err
	}
	return b
}

// assetRefSQL labels an asset for the interface kind's "asset" column.
func init() {
	bulkRefs["asset"] = bulkRefSpec{Table: "assets", SQL: `SELECT id::text, COALESCE(NULLIF(asset_tag, ''), NULLIF(display_name, ''), hostname)
		FROM public.assets WHERE deleted_at IS NULL AND COALESCE(NULLIF(asset_tag, ''), NULLIF(display_name, ''), hostname) IS NOT NULL`}
}
