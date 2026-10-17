package services

// Cloud placement (asset-inventory ADR-0009 D7; DCIM row 4.6): where a cloud
// resource is — account › region › network prefix › child prefix — what it is
// in the provider's own words, and which security groups it is a member of.
// One read for the asset page's Placement breadcrumb, and the cloud half of the
// topology tree (account → region → prefix → class counts).
//
// Everything here is READ from what the intake already stores: the
// `cloud_resource` attributes (provider, account_id, region, provider_type),
// the asset's prefix and the prefix that contains it in the same cloud network
// (`cloud_network_ref`, row 1.5f), the stored `hosted_on` edge to the account
// asset (row 0.5) and the `member_of` edges to security-group assets (row 4.6).
// Nothing is synthesised: a resource with no region has no region step, and
// one in no prefix has no prefix steps.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// CloudPlacementPrefix is one prefix step of the breadcrumb.
type CloudPlacementPrefix struct {
	PrefixID uuid.UUID `json:"prefix_id"`
	Prefix   string    `json:"prefix"`
}

// CloudPlacementGroup is one security group the resource is in. AssetID is
// nil when the group is known only from the membership fact (its listing was
// not run), which is said rather than hidden.
type CloudPlacementGroup struct {
	AssetID *uuid.UUID `json:"asset_id"`
	ID      string     `json:"id"`
	Name    string     `json:"name"`
}

// CloudPlacement is one cloud resource's placement.
type CloudPlacement struct {
	AssetID      uuid.UUID `json:"asset_id"`
	ClassKey     string    `json:"class_key"`
	Provider     string    `json:"provider"`
	ProviderType string    `json:"provider_type"`
	AccountID    string    `json:"account_id"`
	// AccountAssetID / AccountName are the `cloud_account` asset reached by
	// the stored `hosted_on` edge; nil when there is none.
	AccountAssetID *uuid.UUID `json:"account_asset_id"`
	AccountName    string     `json:"account_name"`
	Region         string     `json:"region"`
	// Network is the container prefix of the resource's cloud network (the
	// VPC / VNet range); Prefix the prefix the resource is in. Either may be
	// nil.
	Network        *CloudPlacementPrefix `json:"network"`
	Prefix         *CloudPlacementPrefix `json:"prefix"`
	SecurityGroups []CloudPlacementGroup `json:"security_groups"`
}

// ErrNotCloudResource is returned for an asset outside the cloud_resource
// subtree: placement is a cloud question.
var ErrNotCloudResource = errors.New("not a cloud resource")

// GetCloudPlacement reads one cloud resource's placement.
func (s *AssetService) GetCloudPlacement(ctx context.Context, tenantID, assetID uuid.UUID) (*CloudPlacement, error) {
	var out *CloudPlacement
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var (
			classKey, classPath           string
			provider, account, region, pt sql.NullString
			prefixID                      *uuid.UUID
		)
		err := tx.QueryRowContext(ctx, `
			SELECT a.class_key, a.class_path,
			       a.attributes->>'provider', a.attributes->>'account_id',
			       a.attributes->>'region', a.attributes->>'provider_type', a.prefix_id
			  FROM assets a
			 WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL`, tenantID, assetID).
			Scan(&classKey, &classPath, &provider, &account, &region, &pt, &prefixID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("cloud placement: %w", err)
		}
		if !strings.HasPrefix(classPath, "cloud_resource.") {
			return ErrNotCloudResource
		}
		p := &CloudPlacement{AssetID: assetID, ClassKey: classKey, Provider: provider.String, AccountID: account.String,
			Region: region.String, ProviderType: pt.String, SecurityGroups: []CloudPlacementGroup{}}

		if prefixID != nil {
			var sub CloudPlacementPrefix
			var ref sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT id, prefix::text, cloud_network_ref FROM prefixes WHERE tenant_id = $1 AND id = $2`,
				tenantID, *prefixID).Scan(&sub.PrefixID, &sub.Prefix, &ref); err == nil {
				p.Prefix = &sub
				if ref.Valid && ref.String != "" {
					var net CloudPlacementPrefix
					err := tx.QueryRowContext(ctx, `
						SELECT id, prefix::text FROM prefixes
						 WHERE tenant_id = $1 AND cloud_network_ref = $2 AND id <> $3
						   AND prefix >> (SELECT prefix FROM prefixes WHERE id = $3)
						 ORDER BY masklen(prefix) DESC, id LIMIT 1`, tenantID, ref.String, sub.PrefixID).Scan(&net.PrefixID, &net.Prefix)
					if err == nil {
						p.Network = &net
					}
				}
			}
		}

		var accID uuid.UUID
		var accName sql.NullString
		if err := tx.QueryRowContext(ctx, `
			SELECT t.id, COALESCE(NULLIF(t.display_name, ''), t.hostname)
			  FROM asset_relationships r JOIN assets t ON t.id = r.to_asset_id AND t.tenant_id = r.tenant_id
			 WHERE r.tenant_id = $1 AND r.from_asset_id = $2 AND r.type = 'hosted_on' AND r.status <> 'rejected'
			   AND t.class_key = 'cloud_account' AND t.deleted_at IS NULL
			 ORDER BY r.last_seen_at DESC LIMIT 1`, tenantID, assetID).Scan(&accID, &accName); err == nil {
			p.AccountAssetID, p.AccountName = &accID, accName.String
		}

		// Groups that are assets, through member_of …
		rows, err := tx.QueryContext(ctx, `
			SELECT t.id, COALESCE(NULLIF(t.display_name, ''), t.hostname, ''),
			       COALESCE((SELECT i.value FROM asset_identifiers i WHERE i.tenant_id = t.tenant_id AND i.asset_id = t.id AND i.kind = 'cloud_resource_id' LIMIT 1), '')
			  FROM asset_relationships r JOIN assets t ON t.id = r.to_asset_id AND t.tenant_id = r.tenant_id
			 WHERE r.tenant_id = $1 AND r.from_asset_id = $2 AND r.type = 'member_of' AND r.status <> 'rejected'
			   AND t.class_key = 'security_group' AND t.deleted_at IS NULL`, tenantID, assetID)
		if err != nil {
			return fmt.Errorf("cloud placement groups: %w", err)
		}
		seen := map[string]bool{}
		for rows.Next() {
			var g CloudPlacementGroup
			var id uuid.UUID
			if err := rows.Scan(&id, &g.Name, &g.ID); err != nil {
				_ = rows.Close()
				return err
			}
			g.AssetID = &id
			p.SecurityGroups = append(p.SecurityGroups, g)
			seen[g.ID] = true
			seen[lastPathSegment(g.ID)] = true
		}
		_ = rows.Close()
		// … and the ones known only from the membership fact.
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT value FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3
			ORDER BY observed_at DESC LIMIT 1`, tenantID, assetID, facts.KeyCloudSecurityGroups).Scan(&raw); err == nil {
			var groups []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(raw, &groups) == nil {
				for _, g := range groups {
					if g.ID == "" || seen[g.ID] || seen[lastPathSegment(g.ID)] {
						continue
					}
					p.SecurityGroups = append(p.SecurityGroups, CloudPlacementGroup{ID: g.ID, Name: g.Name})
				}
			}
		}
		sort.SliceStable(p.SecurityGroups, func(i, j int) bool { return p.SecurityGroups[i].Name < p.SecurityGroups[j].Name })
		out = p
		return nil
	})
	return out, err
}

func lastPathSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// The topology's cloud hierarchy
// ---------------------------------------------------------------------------

// TopologyCloudRegion is one region of one account, with its prefixes (the
// same prefix → class shape the site tree uses, so the client draws both the
// same way).
type TopologyCloudRegion struct {
	Region     string           `json:"region"`
	AssetCount int              `json:"asset_count"`
	Prefixes   []TopologyPrefix `json:"prefixes"`
}

// TopologyCloudAccount is one cloud account node.
type TopologyCloudAccount struct {
	Provider       string                `json:"provider"`
	AccountID      string                `json:"account_id"`
	AccountAssetID *uuid.UUID            `json:"account_asset_id"`
	AccountName    string                `json:"account_name"`
	AssetCount     int                   `json:"asset_count"`
	Regions        []TopologyCloudRegion `json:"regions"`
}

// TopologyNoRegion labels resources that state no region.
const TopologyNoRegion = "No region"

type topologyCloudRow struct {
	Provider   string     `db:"provider"`
	AccountID  string     `db:"account_id"`
	Region     string     `db:"region"`
	PrefixID   *uuid.UUID `db:"prefix_id"`
	PrefixName string     `db:"prefix_name"`
	ClassKey   string     `db:"class_key"`
	ClassPath  string     `db:"class_path"`
	AssetCount int        `db:"asset_count"`
}

// loadTopologyClouds reads the account → region → prefix → class tree of the
// tenant's cloud resources (the account assets themselves are the account
// nodes, not counted under them).
func loadTopologyClouds(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID) ([]TopologyCloudAccount, error) {
	var rows []topologyCloudRow
	if err := tx.SelectContext(ctx, &rows, `
		SELECT COALESCE(a.attributes->>'provider', '')    AS provider,
		       COALESCE(a.attributes->>'account_id', '')  AS account_id,
		       COALESCE(NULLIF(a.attributes->>'region', ''), $2) AS region,
		       a.prefix_id                                AS prefix_id,
		       COALESCE(pfx.prefix::text, $3)             AS prefix_name,
		       a.class_key, a.class_path,
		       count(*)                                   AS asset_count
		  FROM assets a
		  LEFT JOIN prefixes pfx ON pfx.id = a.prefix_id AND pfx.tenant_id = a.tenant_id
		 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		   AND a.class_path LIKE 'cloud_resource.%' AND a.class_key <> 'cloud_account'
		 GROUP BY 1, 2, 3, 4, 5, 6, 7
		 ORDER BY 1, 2, 3, prefix_name, a.class_key
		 LIMIT $4`, tenantID, TopologyNoRegion, TopologyNoPrefix, TopologyNodeCap); err != nil {
		return nil, fmt.Errorf("topology clouds: %w", err)
	}
	type acc struct {
		id   uuid.UUID
		name string
	}
	accounts := map[string]acc{}
	accRows, err := tx.QueryContext(ctx, `
		SELECT a.id, COALESCE(a.attributes->>'provider',''), COALESCE(a.attributes->>'account_id',''),
		       COALESCE(NULLIF(a.display_name, ''), a.hostname, '')
		  FROM assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.class_key = 'cloud_account'`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("topology cloud accounts: %w", err)
	}
	for accRows.Next() {
		var id uuid.UUID
		var prov, account, name string
		if err := accRows.Scan(&id, &prov, &account, &name); err != nil {
			_ = accRows.Close()
			return nil, err
		}
		accounts[prov+"|"+account] = acc{id, name}
	}
	_ = accRows.Close()
	return assembleTopologyClouds(rows, func(provider, account string) (*uuid.UUID, string) {
		if a, ok := accounts[provider+"|"+account]; ok {
			id := a.id
			return &id, a.name
		}
		return nil, ""
	}), nil
}

// assembleTopologyClouds folds rows into the tree. Pure.
func assembleTopologyClouds(rows []topologyCloudRow, account func(provider, account string) (*uuid.UUID, string)) []TopologyCloudAccount {
	out := []TopologyCloudAccount{}
	accIdx := map[string]int{}
	regIdx := map[string]int{}
	pfxIdx := map[string]int{}
	for _, r := range rows {
		ak := r.Provider + "|" + r.AccountID
		ai, ok := accIdx[ak]
		if !ok {
			ai = len(out)
			accIdx[ak] = ai
			id, name := account(r.Provider, r.AccountID)
			out = append(out, TopologyCloudAccount{Provider: r.Provider, AccountID: r.AccountID, AccountAssetID: id, AccountName: name, Regions: []TopologyCloudRegion{}})
		}
		out[ai].AssetCount += r.AssetCount
		rk := ak + "|" + r.Region
		ri, ok := regIdx[rk]
		if !ok {
			ri = len(out[ai].Regions)
			regIdx[rk] = ri
			out[ai].Regions = append(out[ai].Regions, TopologyCloudRegion{Region: r.Region, Prefixes: []TopologyPrefix{}})
		}
		reg := &out[ai].Regions[ri]
		reg.AssetCount += r.AssetCount
		pk := rk + "|"
		if r.PrefixID != nil {
			pk += r.PrefixID.String()
		}
		pi, ok := pfxIdx[pk]
		if !ok {
			pi = len(reg.Prefixes)
			pfxIdx[pk] = pi
			reg.Prefixes = append(reg.Prefixes, TopologyPrefix{PrefixID: r.PrefixID, PrefixName: r.PrefixName, Classes: []TopologyClass{}})
		}
		reg.Prefixes[pi].AssetCount += r.AssetCount
		reg.Prefixes[pi].Classes = append(reg.Prefixes[pi].Classes, TopologyClass{ClassKey: r.ClassKey, ClassPath: r.ClassPath, AssetCount: r.AssetCount})
	}
	return out
}
