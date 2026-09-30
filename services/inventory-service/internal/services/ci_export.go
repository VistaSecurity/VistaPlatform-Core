package services

// The CI export: what a connector running OUTSIDE this service reads to push
// the inventory into a system of record (platform ADR-0002 D4, step M3).
//
// Before M3 the Enterprise CMDB sync ran inside this service and read
// v_ci_inventory, assets, asset_facts, asset_identifiers and
// asset_relationships directly. It now runs in the Enterprise integration service, which owns
// its profiles, jobs and links but none of the inventory — so every inventory
// read it needs is here, behind the same HMAC-only, signed-tenant gate as the
// source-import writes (source_import.go), and denied at the edge.
//
// Three rules shape it:
//
//   - The push scope is decided HERE, not by the caller. ExportItems reads
//     v_ci_inventory, whose definition is the scope rule (approved, not
//     archived, not merged away — W11 / review M9): a connector cannot widen
//     what it is shown.
//   - Every read is tenant-scoped under RLS for the ONE tenant the signed call
//     names, and every id a caller passes is filtered by that tenant — an id
//     of another tenant's asset answers nothing, never an error that confirms
//     it exists.
//   - A field allowlist. The canonical asset fields, the fact keys a mapping
//     names, the crypto posture a summary needs, one link identifier kind. No
//     `SELECT *`, no metadata, no attributes.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// MaxCIExportPage bounds one page of the CI listing and of the relationship
// listing.
const MaxCIExportPage = 5000

// MaxCIExportAssets bounds the asset ids one detail request may name.
const MaxCIExportAssets = MaxSourceBatch

// CIExportItem is one configuration item in push scope: an approved
// infrastructure asset, or a certificate, key or crypto configuration hanging
// off one (v_ci_inventory).
type CIExportItem struct {
	ID       uuid.UUID `json:"id"`
	Category string    `json:"category"`
	// CMDBCIType is the default CMDB class for the item (the class registry's
	// cmdb_ci_type for an asset).
	CMDBCIType  string `json:"cmdb_ci_type"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	// RiskScore is null where the item has none (certificates, keys) — NOT
	// ASSESSED, which must not read as zero.
	RiskScore *int `json:"risk_score"`
	// RiskLevel is banded from RiskScore by the one ladder (shared/riskbands),
	// "" where RiskScore is null.
	RiskLevel      string    `json:"risk_level"`
	DiscoveredAt   time.Time `json:"discovered_at"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
}

// ciExportAssetFields maps the exported field names onto the assets columns
// they are read from. It is the allowlist: nothing else about an asset leaves
// through the export.
var ciExportAssetFields = []struct{ name, expr string }{
	{"display_name", "display_name"},
	{"hostname", "hostname"},
	{"ip_address", "host(primary_address)"},
	{"description", "description"},
	{"environment", "environment::text"},
	{"business_unit", "business_unit"},
	{"owner_email", "owner_email"},
	{"support_group", "support_group"},
	{"site", "site"},
	{"region", "region"},
	{"class_key", "class_key"},
}

// CIExportAssetFieldNames is the allowlist, in order.
func CIExportAssetFieldNames() []string {
	out := make([]string, 0, len(ciExportAssetFields))
	for _, f := range ciExportAssetFields {
		out = append(out, f.name)
	}
	return out
}

// ciExportIdentifierKinds are the identifier kinds the export reads back: the
// link identifiers a connector itself attached (a profile-scoped cmdb_sys_id).
// Other identifiers — serials, MACs, cloud resource ids — are evidence the
// identity engine keeps, not something a push needs.
var ciExportIdentifierKinds = map[string]bool{string(identity.KindCMDBSysID): true}

// CIExportAssetQuery is what a detail request asks for, beyond the asset's
// scope state (always returned).
type CIExportAssetQuery struct {
	AssetIDs []uuid.UUID
	// Fields includes the allowlisted canonical fields.
	Fields bool
	// FactKeys includes the newest live value of each named fact.
	FactKeys []string
	// CryptoPosture includes the asset's crypto configurations as a posture
	// summary needs them.
	CryptoPosture bool
	// IdentifierKind / IdentifierScope include the asset's identifiers of one
	// (allowlisted) kind and one scope.
	IdentifierKind  string
	IdentifierScope string
}

// CIExportCrypto is one crypto configuration, as a posture summary reads it.
type CIExportCrypto struct {
	Protocol             string  `json:"protocol"`
	ProtocolVersion      *string `json:"protocol_version,omitempty"`
	KeyExchangeAlgorithm *string `json:"key_exchange_algorithm,omitempty"`
	SignatureAlgorithm   *string `json:"signature_algorithm,omitempty"`
	SymmetricEncryption  *string `json:"symmetric_encryption,omitempty"`
	KeySize              *int    `json:"key_size,omitempty"`
}

// CIExportPosture is an asset's crypto posture.
type CIExportPosture struct {
	RiskLevel      string           `json:"risk_level"`
	Configurations []CIExportCrypto `json:"configurations"`
}

// CIExportAsset is one asset's detail.
type CIExportAsset struct {
	ID uuid.UUID `json:"id"`
	// Retired is true when the asset has left push scope for good — deleted,
	// archived (by a person or the stale lifecycle), or merged into another.
	// A connector retires the CI it created for such an asset (D11.2).
	Retired bool `json:"retired"`
	// Fields holds the non-empty allowlisted fields (requested with Fields).
	Fields map[string]string `json:"fields,omitempty"`
	// Facts holds the newest live value of each requested fact key.
	Facts map[string]any `json:"facts,omitempty"`
	// CryptoPosture is present when requested and the asset is live.
	CryptoPosture *CIExportPosture `json:"crypto_posture,omitempty"`
	// Identifiers holds the values of the requested identifier kind + scope.
	Identifiers []string `json:"identifiers,omitempty"`
}

// CIExportRelationship is one APPROVED relationship between two assets.
type CIExportRelationship struct {
	ID          uuid.UUID `json:"id"`
	FromAssetID uuid.UUID `json:"from_asset_id"`
	ToAssetID   uuid.UUID `json:"to_asset_id"`
	Type        string    `json:"type"`
}

// ErrCIExportQuery is a detail request the export refuses as asked.
type ErrCIExportQuery struct{ Message string }

func (e *ErrCIExportQuery) Error() string { return e.Message }

// ciPostureReader is the one AssetService read the export needs.
type ciPostureReader interface {
	GetAssetByID(tenantID, assetID uuid.UUID) (*models.Asset, error)
}

// CIExportService is the service layer behind the internal CI export routes.
type CIExportService struct {
	db     *database.DB
	assets ciPostureReader
}

// NewCIExportService wires it against Core's AssetService.
func NewCIExportService(db *database.DB, assets *AssetService) *CIExportService {
	return &CIExportService{db: db, assets: assets}
}

// ExportItems reads one page of the tenant's configuration items in push scope,
// in id order, after `after`.
func (s *CIExportService) ExportItems(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]CIExportItem, error) {
	if limit <= 0 || limit > MaxCIExportPage {
		limit = MaxCIExportPage
	}
	// risk_level is BANDED FROM risk_score rather than read from the view's
	// column, by the one ladder: rows with a NULL score keep "" (not
	// assessed). The view's asset branch bands the same way today; banding
	// here keeps the export right whatever the view carries.
	query := `
		SELECT id, ci_category, cmdb_ci_type, COALESCE(display_name, ''),
		       COALESCE(description, ''), risk_score,
		       CASE WHEN risk_score IS NULL THEN '' ELSE ` + models.RiskLevelCaseSQL("risk_score") + ` END,
		       COALESCE(first_discovered_at, NOW()), COALESCE(last_verified_at, NOW())
		FROM v_ci_inventory
		WHERE tenant_id = $1 AND deleted_at IS NULL AND id > $2
		ORDER BY id
		LIMIT $3`
	out := []CIExportItem{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, query, tenantID, after, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var it CIExportItem
			if err := rows.Scan(&it.ID, &it.Category, &it.CMDBCIType, &it.DisplayName, &it.Description,
				&it.RiskScore, &it.RiskLevel, &it.DiscoveredAt, &it.LastVerifiedAt); err != nil {
				return err
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

// ExportAssets reads the named assets' detail. An id that is not this tenant's
// asset is simply absent from the answer.
func (s *CIExportService) ExportAssets(ctx context.Context, tenantID uuid.UUID, q CIExportAssetQuery) ([]CIExportAsset, error) {
	if len(q.AssetIDs) == 0 {
		return []CIExportAsset{}, nil
	}
	if len(q.AssetIDs) > MaxCIExportAssets {
		return nil, &ErrCIExportQuery{Message: fmt.Sprintf("at most %d asset ids per request", MaxCIExportAssets)}
	}
	for _, k := range q.FactKeys {
		if _, ok := facts.Get(k); !ok {
			return nil, &ErrCIExportQuery{Message: fmt.Sprintf("%q is not a registered fact key", k)}
		}
	}
	if q.IdentifierKind != "" {
		if !ciExportIdentifierKinds[q.IdentifierKind] {
			return nil, &ErrCIExportQuery{Message: fmt.Sprintf("identifier kind %q cannot be exported", q.IdentifierKind)}
		}
		if strings.TrimSpace(q.IdentifierScope) == "" {
			return nil, &ErrCIExportQuery{Message: "an exported identifier needs its scope"}
		}
	}

	ids := make([]string, 0, len(q.AssetIDs))
	for _, id := range q.AssetIDs {
		ids = append(ids, id.String())
	}
	byID := map[uuid.UUID]*CIExportAsset{}
	var order []uuid.UUID

	cols := make([]string, 0, len(ciExportAssetFields))
	for _, c := range ciExportAssetFields {
		cols = append(cols, "COALESCE("+c.expr+", '')")
	}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// The asset rows, with the scope-exit state. The retirement rule is
		// the complement of the push scope's asset rule (v_ci_inventory's
		// ci_scope_assets): deleted, archived by a person or by the stale
		// lifecycle, or merged into another asset.
		rows, err := tx.QueryContext(ctx, `
			SELECT id,
			       COALESCE(deleted_at IS NOT NULL OR asset_status = 'archived'
			        OR stale_status = 'archived' OR metadata ? 'merged_into', false),
			       `+strings.Join(cols, ", ")+`
			FROM assets
			WHERE tenant_id = $1 AND id = ANY($2::uuid[])
			ORDER BY id`, tenantID, pq.Array(ids))
		if err != nil {
			return err
		}
		for rows.Next() {
			var a CIExportAsset
			vals := make([]string, len(ciExportAssetFields))
			dest := []any{&a.ID, &a.Retired}
			for i := range vals {
				dest = append(dest, &vals[i])
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				return err
			}
			if q.Fields {
				a.Fields = map[string]string{}
				for i, c := range ciExportAssetFields {
					if vals[i] != "" {
						a.Fields[c.name] = vals[i]
					}
				}
			}
			cp := a
			byID[a.ID] = &cp
			order = append(order, a.ID)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(order) == 0 {
			return nil
		}

		if len(q.FactKeys) > 0 {
			// The most recently observed live value per (asset, key),
			// whichever source reported it.
			frows, err := tx.QueryContext(ctx, `
				SELECT DISTINCT ON (asset_id, key) asset_id, key, value
				FROM asset_facts
				WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND key = ANY($3)
				  AND (expires_at IS NULL OR expires_at > NOW())
				ORDER BY asset_id, key, observed_at DESC`, tenantID, pq.Array(ids), pq.Array(q.FactKeys))
			if err != nil {
				return err
			}
			for frows.Next() {
				var id uuid.UUID
				var key string
				var raw []byte
				if err := frows.Scan(&id, &key, &raw); err != nil {
					_ = frows.Close()
					return err
				}
				var v any
				if json.Unmarshal(raw, &v) != nil {
					continue
				}
				if a := byID[id]; a != nil {
					if a.Facts == nil {
						a.Facts = map[string]any{}
					}
					a.Facts[key] = v
				}
			}
			if err := frows.Close(); err != nil {
				return err
			}
		}

		if q.IdentifierKind != "" {
			irows, err := tx.QueryContext(ctx, `
				SELECT asset_id, value FROM asset_identifiers
				WHERE tenant_id = $1 AND kind = $2 AND scope = $3 AND asset_id = ANY($4::uuid[])
				ORDER BY asset_id, value`,
				tenantID, q.IdentifierKind, q.IdentifierScope, pq.Array(ids))
			if err != nil {
				return err
			}
			for irows.Next() {
				var id uuid.UUID
				var v string
				if err := irows.Scan(&id, &v); err != nil {
					_ = irows.Close()
					return err
				}
				if a := byID[id]; a != nil {
					a.Identifiers = append(a.Identifiers, v)
				}
			}
			if err := irows.Close(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// The crypto posture is the asset read every page shows (GetAssetByID),
	// so a summary pushed into a CMDB says what the asset page says. One read
	// per asset, as the in-process summary did; only for assets still live.
	if q.CryptoPosture && s.assets != nil {
		for _, id := range order {
			a := byID[id]
			if a.Retired {
				continue
			}
			asset, err := s.assets.GetAssetByID(tenantID, id)
			if err != nil || asset == nil {
				// Best-effort, as it always was: an asset whose posture
				// cannot be read is pushed without a summary.
				continue
			}
			a.CryptoPosture = postureOf(asset)
		}
	}

	out := make([]CIExportAsset, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// postureOf projects an asset onto the crypto posture a summary reads.
func postureOf(asset *models.Asset) *CIExportPosture {
	p := &CIExportPosture{RiskLevel: asset.RiskLevel, Configurations: []CIExportCrypto{}}
	for _, impl := range asset.CryptoImplementations {
		p.Configurations = append(p.Configurations, CIExportCrypto{
			Protocol:             impl.Protocol,
			ProtocolVersion:      impl.ProtocolVersion,
			KeyExchangeAlgorithm: impl.KeyExchangeAlgorithm,
			SignatureAlgorithm:   impl.SignatureAlgorithm,
			SymmetricEncryption:  impl.SymmetricEncryption,
			KeySize:              impl.KeySize,
		})
	}
	return p
}

// ExportRelationships reads one page of the tenant's APPROVED relationships
// (status active), in id order, after `after`. A pending observation is not yet
// the tenant's to assert in someone else's CMDB.
func (s *CIExportService) ExportRelationships(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]CIExportRelationship, error) {
	if limit <= 0 || limit > MaxCIExportPage {
		limit = MaxCIExportPage
	}
	out := []CIExportRelationship{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, from_asset_id, to_asset_id, type
			FROM asset_relationships
			WHERE tenant_id = $1 AND status = 'active' AND id > $2
			ORDER BY id
			LIMIT $3`, tenantID, after, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r CIExportRelationship
			if err := rows.Scan(&r.ID, &r.FromAssetID, &r.ToAssetID, &r.Type); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
