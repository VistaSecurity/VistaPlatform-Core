package postgres

// DCIM row 4.2: clusters through the intake seam (identity.ObservedCluster).
//
// A cluster is the `clusters` object, matched by its identity (tenant, type,
// name) among non-rejected rows; nothing here writes an asset row except a
// VM's cluster_id. A new cluster is `measured` and `pending` (the asset
// lifecycle), stamped with the observation's source; an existing one has its
// observation counted, its group filled where it has none and its external id
// added — a declared value is never overwritten. A cluster a person rejected
// stays rejected: the observation is not recorded on it and no second row is
// made.
//
// Membership: a hypervisor (or hardware node) is a cluster host — one cluster
// per host, so a host observed in another cluster is moved; a virtual machine
// or cloud compute instance gets assets.cluster_id. Every row created or
// visibly changed is recorded in object_changes, source `intake:identity`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ErrUnknownClusterType is a cluster whose type the tenant cannot see.
var ErrUnknownClusterType = errors.New("identity/postgres: unknown cluster type")

// UpsertObservedCluster implements [identity.ObservedClusterRepository].
func (r *Repository) UpsertObservedCluster(ctx context.Context, tenantID string, c identity.ObservedCluster, src identity.Source) (identity.ClusterRef, error) {
	var ref identity.ClusterRef
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		var err error
		ref, err = upsertCluster(ctx, tx, tenantID, c, src, time.Now().UTC())
		return err
	})
	return ref, err
}

// RecordClusterMembership implements [identity.ObservedClusterRepository].
func (r *Repository) RecordClusterMembership(ctx context.Context, asset identity.AssetRef, c identity.ObservedCluster, src identity.Source) error {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		ref, err := upsertCluster(ctx, tx, asset.TenantID, c, src, time.Now().UTC())
		if err != nil || ref.Rejected {
			return err
		}
		return recordMembership(ctx, tx, asset.TenantID, assetID, uuid.MustParse(ref.ID), c.Member)
	})
}

// clusterTypeID resolves a type slug: the tenant's own type first, then the
// platform's.
func clusterTypeID(ctx context.Context, tx *sql.Tx, tenantID, slug string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM public.cluster_types
		 WHERE slug = $2 AND (tenant_id = $1 OR tenant_id IS NULL)
		 ORDER BY (tenant_id IS NULL) LIMIT 1`, tenantID, slug).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("%w %q", ErrUnknownClusterType, slug)
	}
	return id, err
}

var clusterSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

func clusterSlug(name string) string {
	return strings.Trim(clusterSlugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// clusterGroupID finds the tenant's group by name, creating it when absent.
func clusterGroupID(ctx context.Context, tx *sql.Tx, tenantID, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM public.cluster_groups WHERE tenant_id = $1 AND lower(name) = lower($2)`, tenantID, name).Scan(&id)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return id, err
	}
	slug := clusterSlug(name)
	if slug == "" {
		slug = "group-" + uuid.NewString()[:8]
	}
	id = uuid.New()
	res, err := tx.ExecContext(ctx, `INSERT INTO public.cluster_groups (id, tenant_id, name, slug, source_kind)
		VALUES ($1, $2, $3, $4, 'measured') ON CONFLICT DO NOTHING`, id, tenantID, name, slug)
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity/postgres: create cluster group %q: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// A concurrent observation made it, or the slug is another group's.
		if err := tx.QueryRowContext(ctx, `SELECT id FROM public.cluster_groups WHERE tenant_id = $1 AND (lower(name) = lower($2) OR slug = $3) LIMIT 1`, tenantID, name, slug).Scan(&id); err != nil {
			return uuid.Nil, fmt.Errorf("identity/postgres: cluster group %q: %w", name, err)
		}
		return id, nil
	}
	return id, recordChange(ctx, tx, tenantID, dcim.ObjectKindClusterGroup, id, changes.ActionCreate, nil,
		map[string]any{"name": name, "slug": slug, "source_kind": "measured"})
}

func upsertCluster(ctx context.Context, tx *sql.Tx, tenantID string, c identity.ObservedCluster, src identity.Source, at time.Time) (identity.ClusterRef, error) {
	ref := identity.ClusterRef{TenantID: tenantID}
	c, err := c.Normalize()
	if err != nil {
		return ref, fmt.Errorf("identity/postgres: %w", err)
	}
	typeID, err := clusterTypeID(ctx, tx, tenantID, c.Type)
	if err != nil {
		return ref, err
	}
	// A rejected cluster of this identity stays rejected, and is not recreated.
	var rejected uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT id FROM public.clusters WHERE tenant_id = $1 AND type_id = $2 AND name = $3 AND status = 'rejected' LIMIT 1`,
		tenantID, typeID, c.Name).Scan(&rejected)
	if err == nil {
		var live bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.clusters WHERE tenant_id = $1 AND type_id = $2 AND name = $3 AND status <> 'rejected')`,
			tenantID, typeID, c.Name).Scan(&live); err != nil {
			return ref, err
		}
		if !live {
			ref.ID, ref.Rejected = rejected.String(), true
			return ref, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ref, err
	}
	var groupID uuid.NullUUID
	if c.Group != "" {
		g, err := clusterGroupID(ctx, tx, tenantID, c.Group)
		if err != nil {
			return ref, err
		}
		groupID = uuid.NullUUID{UUID: g, Valid: true}
	}
	ext := map[string]string{}
	if c.ExternalID != "" {
		ext[c.ExternalKey] = c.ExternalID
	}
	extJSON, _ := json.Marshal(ext)
	sourceKind := string(src.Kind)
	if sourceKind == "" {
		sourceKind = string(identity.SourceMeasured)
	}
	id := uuid.New()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO public.clusters (id, tenant_id, name, type_id, group_id, external_ids, status, source_kind, source_ref,
		                             first_seen_at, last_seen_at, observation_count)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'pending', $7, NULLIF($8, ''), $9, $9, 1)
		ON CONFLICT (tenant_id, type_id, name) WHERE status <> 'rejected' DO NOTHING`,
		id, tenantID, c.Name, typeID, groupID, string(extJSON), sourceKind, src.Ref, at)
	if err != nil {
		return ref, fmt.Errorf("identity/postgres: create cluster %q: %w", c.Name, err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		ref.ID, ref.Created = id.String(), true
		post := map[string]any{"name": c.Name, "type_id": typeID.String(), "status": "pending", "source_kind": sourceKind}
		if groupID.Valid {
			post["group_id"] = groupID.UUID.String()
		}
		if len(ext) > 0 {
			post["external_ids"] = ext
		}
		return ref, recordChange(ctx, tx, tenantID, dcim.ObjectKindCluster, id, changes.ActionCreate, nil, post)
	}
	// The cluster exists: count the observation, fill the group where empty,
	// add the external id where the key is absent.
	var (
		existing uuid.UUID
		preGroup uuid.NullUUID
		preExt   []byte
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT id, group_id, external_ids FROM public.clusters
		 WHERE tenant_id = $1 AND type_id = $2 AND name = $3 AND status <> 'rejected' FOR UPDATE`,
		tenantID, typeID, c.Name).Scan(&existing, &preGroup, &preExt); err != nil {
		return ref, fmt.Errorf("identity/postgres: read cluster %q: %w", c.Name, err)
	}
	ref.ID = existing.String()
	var have map[string]any
	_ = json.Unmarshal(preExt, &have)
	pre, post := map[string]any{}, map[string]any{}
	if !preGroup.Valid && groupID.Valid {
		pre["group_id"], post["group_id"] = nil, groupID.UUID.String()
	}
	addExt := c.ExternalID != "" && have[c.ExternalKey] == nil
	if addExt {
		pre["external_ids"] = have
		merged := map[string]any{}
		for k, v := range have {
			merged[k] = v
		}
		merged[c.ExternalKey] = c.ExternalID
		post["external_ids"] = merged
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.clusters
		   SET last_seen_at = GREATEST(COALESCE(last_seen_at, $2), $2),
		       first_seen_at = COALESCE(first_seen_at, $2),
		       observation_count = observation_count + 1,
		       group_id = COALESCE(group_id, $3),
		       external_ids = CASE WHEN $4 THEN external_ids || $5::jsonb ELSE external_ids END,
		       updated_at = CASE WHEN $6 THEN now() ELSE updated_at END
		 WHERE id = $1`, existing, at, groupID, addExt, string(extJSON), len(post) > 0); err != nil {
		return ref, fmt.Errorf("identity/postgres: update cluster %q: %w", c.Name, err)
	}
	if len(post) == 0 {
		return ref, nil
	}
	return ref, recordChange(ctx, tx, tenantID, dcim.ObjectKindCluster, existing, changes.ActionUpdate, pre, post)
}

// memberRole decides host or VM from the asset's class when the observation
// did not say.
func memberRole(path string, stated identity.ClusterMember) identity.ClusterMember {
	if stated != "" {
		return stated
	}
	switch {
	case path == "virtual.hypervisor" || strings.HasPrefix(path, "virtual.hypervisor."):
		return identity.ClusterMemberHost
	case path == "virtual.virtual_machine" || strings.HasPrefix(path, "virtual.virtual_machine."),
		path == "cloud_resource.compute_instance" || strings.HasPrefix(path, "cloud_resource.compute_instance."):
		return identity.ClusterMemberVM
	}
	return ""
}

func clusterHostIDs(ctx context.Context, tx *sql.Tx, cluster uuid.UUID) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT asset_id::text FROM public.cluster_hosts WHERE cluster_id = $1`, cluster)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, rows.Err()
}

// setClusterHost adds (or removes) one host and records the cluster's host
// list before and after.
func setClusterHost(ctx context.Context, tx *sql.Tx, tenantID string, cluster, asset uuid.UUID, add bool) error {
	pre, err := clusterHostIDs(ctx, tx, cluster)
	if err != nil {
		return err
	}
	if add {
		_, err = tx.ExecContext(ctx, `INSERT INTO public.cluster_hosts (tenant_id, cluster_id, asset_id, source_kind) VALUES ($1, $2, $3, 'measured')`, tenantID, cluster, asset)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM public.cluster_hosts WHERE tenant_id = $1 AND cluster_id = $2 AND asset_id = $3`, tenantID, cluster, asset)
	}
	if err != nil {
		return fmt.Errorf("identity/postgres: cluster host: %w", err)
	}
	post, err := clusterHostIDs(ctx, tx, cluster)
	if err != nil {
		return err
	}
	return recordChange(ctx, tx, tenantID, dcim.ObjectKindCluster, cluster, changes.ActionUpdate,
		map[string]any{"host_asset_ids": pre}, map[string]any{"host_asset_ids": post})
}

func recordMembership(ctx context.Context, tx *sql.Tx, tenantID string, asset, cluster uuid.UUID, stated identity.ClusterMember) error {
	var path string
	var vmCluster uuid.NullUUID
	err := tx.QueryRowContext(ctx, `SELECT class_path, cluster_id FROM public.assets WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, asset).Scan(&path, &vmCluster)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, asset)
	}
	if err != nil {
		return err
	}
	switch memberRole(path, stated) {
	case identity.ClusterMemberHost:
		var prior uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT cluster_id FROM public.cluster_hosts WHERE tenant_id = $1 AND asset_id = $2`, tenantID, asset).Scan(&prior); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if prior.Valid && prior.UUID == cluster {
			return nil
		}
		if prior.Valid {
			if err := setClusterHost(ctx, tx, tenantID, prior.UUID, asset, false); err != nil {
				return err
			}
		}
		return setClusterHost(ctx, tx, tenantID, cluster, asset, true)
	case identity.ClusterMemberVM:
		if vmCluster.Valid && vmCluster.UUID == cluster {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE public.assets SET cluster_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`, tenantID, asset, cluster); err != nil {
			return fmt.Errorf("identity/postgres: set the VM's cluster: %w", err)
		}
		var pre any
		if vmCluster.Valid {
			pre = vmCluster.UUID.String()
		}
		return recordChange(ctx, tx, tenantID, dcim.ObjectKindAsset, asset, changes.ActionUpdate,
			map[string]any{"cluster_id": pre}, map[string]any{"cluster_id": cluster.String()})
	}
	return nil
}

// MirrorCloudCluster mirrors a cloud account + region as a cluster of the
// provider's type (asset-inventory ADR-0010 D8, ADR-0009 D1) and makes asset
// (an instance in that account and region) one of its VMs. The cluster is
// named `<account>/<region>`, identified for sync by external_ids.cloud =
// `<account>:<region>`, and `active`: it mirrors a declared, approved account
// rather than proposing anything. It is for NetBox sync fidelity only — the
// account asset stays the inventory object. One cluster per account+region.
func (r *Repository) MirrorCloudCluster(ctx context.Context, asset identity.AssetRef, provider, account, region string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	account, region = strings.TrimSpace(account), strings.TrimSpace(region)
	if provider == "" || account == "" || region == "" {
		return nil
	}
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		typeID, err := clusterTypeID(ctx, tx, asset.TenantID, provider)
		if err != nil {
			return err
		}
		key := account + ":" + region
		var id uuid.UUID
		err = tx.QueryRowContext(ctx, `
			SELECT id FROM public.clusters
			 WHERE tenant_id = $1 AND type_id = $2 AND external_ids ->> 'cloud' = $3 AND status <> 'rejected'
			 ORDER BY created_at LIMIT 1`, asset.TenantID, typeID, key).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			id = uuid.New()
			name := account + "/" + region
			ext, _ := json.Marshal(map[string]string{"cloud": key})
			res, err := tx.ExecContext(ctx, `
				INSERT INTO public.clusters (id, tenant_id, name, type_id, external_ids, status, source_kind, source_ref,
				                             first_seen_at, last_seen_at, observation_count, description)
				VALUES ($1, $2, $3, $4, $5::jsonb, 'active', 'inferred', $6, now(), now(), 1, $7)
				ON CONFLICT (tenant_id, type_id, name) WHERE status <> 'rejected' DO NOTHING`,
				id, asset.TenantID, name, typeID, string(ext), "cloud-account:"+provider+":"+account,
				"Mirror of the cloud account and region, for NetBox sync")
			if err != nil {
				return fmt.Errorf("identity/postgres: mirror %s %s: %w", provider, key, err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				if err := tx.QueryRowContext(ctx, `SELECT id FROM public.clusters WHERE tenant_id = $1 AND type_id = $2 AND name = $3 AND status <> 'rejected'`,
					asset.TenantID, typeID, name).Scan(&id); err != nil {
					return fmt.Errorf("identity/postgres: mirror %s %s: %w", provider, key, err)
				}
			} else if err := recordChange(ctx, tx, asset.TenantID, dcim.ObjectKindCluster, id, changes.ActionCreate, nil,
				map[string]any{"name": name, "type_id": typeID.String(), "external_ids": map[string]string{"cloud": key}, "status": "active", "source_kind": "inferred"}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		return recordMembership(ctx, tx, asset.TenantID, assetID, id, identity.ClusterMemberVM)
	})
}
