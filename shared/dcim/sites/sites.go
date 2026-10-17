// Package sites holds the placement primitives every writer of regions, site
// groups, sites and locations shares (DCIM row 2.1, ADR-0010 D4): slugs, the
// scope-kind → table map the polymorphic `scope_kind`/`scope_id` columns of
// prefixes and VLAN groups resolve against, and the find-or-create writers the
// intake paths use to place what they measure (a cloud account's site and its
// regions, ADR-0009 D1).
//
// The CRUD service a person drives is inventory-service's site_service.go; it
// uses Slug and UniqueSlug from here so a site a person creates and one an
// intake creates are spelled by the same rule.
package sites

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Slug derives a slug from a name: lowercase kebab, NetBox's rule. A name with
// no letters or digits slugs to fallback.
func Slug(name, fallback string) string {
	s := strings.Trim(slugNonAlnum.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
	if s == "" {
		return fallback
	}
	if len(s) > 100 {
		s = strings.TrimRight(s[:100], "-")
	}
	return s
}

// Table is the table of a placement kind, and whether it is one.
//
// The four kinds are the ones `prefixes.scope_kind` admits (NetBox 4.2
// Prefix.scope). `vlan_groups.scope_kind` also admits rack, cluster group and
// cluster; those tables arrive with rows 2.3 and phase 5, and until they exist
// a scope naming them cannot be resolved, so ScopeTable reports false for them.
func Table(kind string) (string, bool) {
	switch dcim.ObjectKind(kind) {
	case dcim.ObjectKindRegion:
		return "regions", true
	case dcim.ObjectKindSiteGroup:
		return "site_groups", true
	case dcim.ObjectKindSite:
		return "sites", true
	case dcim.ObjectKindLocation:
		return "locations", true
	}
	return "", false
}

// ErrScope is returned by CheckScope for a scope that does not resolve.
var ErrScope = errors.New("scope does not resolve")

// CheckScope verifies that (kind, id) names a region, site group, site or
// location the transaction's tenant can see. Both empty is "no scope" and
// valid. The DB CHECK only constrains the kind's spelling; whether the id
// exists — and is the tenant's, which RLS decides — is this check's job
// (DATA_MODEL section 5, prefixes.scope).
func CheckScope(ctx context.Context, tx changes.DBTX, kind string, id *uuid.UUID) error {
	if kind == "" && id == nil {
		return nil
	}
	if kind == "" || id == nil {
		return fmt.Errorf("%w: scope_kind and scope_id go together", ErrScope)
	}
	table, ok := Table(kind)
	if !ok {
		return fmt.Errorf("%w: %q is not a region, site group, site or location", ErrScope, kind)
	}
	var found bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.`+pq.QuoteIdentifier(table)+` WHERE id = $1)`, *id).Scan(&found); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: no such %s %s", ErrScope, strings.ReplaceAll(kind, "_", " "), id)
	}
	return nil
}

// UniqueSlug returns base, or base-2, base-3, … until no row of table in the
// tenant (other than except) holds it. scopeCol/scopeID narrow uniqueness to
// one parent where the identity is scoped (a location's slug is unique per
// site); pass "" for a tenant-wide slug.
func UniqueSlug(ctx context.Context, tx changes.DBTX, table string, tenantID uuid.UUID, scopeCol string, scopeID uuid.UUID, base string, except uuid.UUID) (string, error) {
	q := `SELECT EXISTS (SELECT 1 FROM public.` + pq.QuoteIdentifier(table) + ` WHERE tenant_id = $1 AND slug = $2 AND id <> $3`
	args := []any{tenantID, "", except}
	if scopeCol != "" {
		q += ` AND ` + pq.QuoteIdentifier(scopeCol) + ` = $4`
		args = append(args, scopeID)
	}
	q += `)`
	for i := 1; i < 1000; i++ {
		cand := base
		if i > 1 {
			cand = fmt.Sprintf("%s-%d", base, i)
		}
		args[1] = cand
		var taken bool
		if err := tx.QueryRowContext(ctx, q, args...).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return cand, nil
		}
	}
	return "", fmt.Errorf("sites: could not derive a free slug from %q", base)
}

// uniqueName is name, or "name (2)", … until no site of the tenant holds it
// (site names are unique per tenant, case-insensitively).
func uniqueSiteName(ctx context.Context, tx changes.DBTX, tenantID uuid.UUID, name string) (string, error) {
	for i := 1; i < 1000; i++ {
		cand := name
		if i > 1 {
			cand = fmt.Sprintf("%s (%d)", name, i)
		}
		var taken bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.sites WHERE tenant_id = $1 AND lower(name) = lower($2))`, tenantID, cand).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return cand, nil
		}
	}
	return "", fmt.Errorf("sites: could not derive a free site name from %q", name)
}

// SiteSpec is a site an intake path declares.
type SiteSpec struct {
	Name       string
	Facility   string
	SourceKind string // declared, imported, measured, inferred
	// SourceRef is the site's identity for its writer: a site is found by it
	// before anything is created, so a renamed site is not recreated.
	SourceRef string
}

// EnsureSite returns the tenant's site whose source_ref is spec.SourceRef,
// creating it (and recording the creation) when there is none. A person may
// rename or re-slug the site afterwards; it is still found by its ref. The
// change source comes from ctx; with none the change is recorded as `system`.
func EnsureSite(ctx context.Context, tx changes.Tx, tenantID uuid.UUID, spec SiteSpec) (uuid.UUID, bool, error) {
	if strings.TrimSpace(spec.SourceRef) == "" {
		return uuid.Nil, false, errors.New("sites: EnsureSite needs a source_ref")
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM public.sites WHERE tenant_id = $1 AND source_ref = $2 ORDER BY created_at LIMIT 1`, tenantID, spec.SourceRef).Scan(&id)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, err
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = spec.SourceRef
	}
	if len(name) > 100 {
		name = name[:100]
	}
	if name, err = uniqueSiteName(ctx, tx, tenantID, name); err != nil {
		return uuid.Nil, false, err
	}
	id = uuid.New()
	slug, err := UniqueSlug(ctx, tx, "sites", tenantID, "", uuid.Nil, Slug(name, "site"), id)
	if err != nil {
		return uuid.Nil, false, err
	}
	kind := spec.SourceKind
	if kind == "" {
		kind = "declared"
	}
	var facility any
	if strings.TrimSpace(spec.Facility) != "" {
		facility = strings.TrimSpace(spec.Facility)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.sites (id, tenant_id, name, slug, facility, source_kind, source_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, tenantID, name, slug, facility, kind, spec.SourceRef); err != nil {
		return uuid.Nil, false, fmt.Errorf("sites: create site %q: %w", name, err)
	}
	post := map[string]any{"name": name, "slug": slug, "facility": facility, "operational_status": "active", "source_kind": kind, "source_ref": spec.SourceRef}
	if err := changes.InTx(tx).Record(withSource(ctx), changes.Change{TenantID: tenantID, Kind: dcim.ObjectKindSite, ID: id, Action: changes.ActionCreate, Post: post}); err != nil {
		return uuid.Nil, false, err
	}
	return id, true, nil
}

// EnsureLocation returns the top-level location named name in the site,
// creating it (and recording the creation) when there is none. Locations are
// identified by (tenant, site, parent, name) — DATA_MODEL section 1.
func EnsureLocation(ctx context.Context, tx changes.Tx, tenantID, siteID uuid.UUID, name, sourceKind, sourceRef string) (uuid.UUID, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return uuid.Nil, false, errors.New("sites: a location needs a name")
	}
	if len(name) > 100 {
		name = name[:100]
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM public.locations WHERE tenant_id = $1 AND site_id = $2 AND parent_id IS NULL AND name = $3`, tenantID, siteID, name).Scan(&id)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, err
	}
	id = uuid.New()
	slug, err := UniqueSlug(ctx, tx, "locations", tenantID, "site_id", siteID, Slug(name, "location"), id)
	if err != nil {
		return uuid.Nil, false, err
	}
	if sourceKind == "" {
		sourceKind = "declared"
	}
	var ref any
	if sourceRef != "" {
		ref = sourceRef
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.locations (id, tenant_id, site_id, name, slug, source_kind, source_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, tenantID, siteID, name, slug, sourceKind, ref); err != nil {
		return uuid.Nil, false, fmt.Errorf("sites: create location %q: %w", name, err)
	}
	post := map[string]any{"site_id": siteID.String(), "parent_id": nil, "name": name, "slug": slug, "operational_status": "active", "source_kind": sourceKind, "source_ref": ref}
	if err := changes.InTx(tx).Record(withSource(ctx), changes.Change{TenantID: tenantID, Kind: dcim.ObjectKindLocation, ID: id, Action: changes.ActionCreate, Post: post}); err != nil {
		return uuid.Nil, false, err
	}
	return id, true, nil
}

// withSource defaults the change source to system for a write nobody asked
// for in a request.
func withSource(ctx context.Context) context.Context {
	if _, ok := changes.SourceFrom(ctx); ok {
		return ctx
	}
	return changes.System(ctx)
}
