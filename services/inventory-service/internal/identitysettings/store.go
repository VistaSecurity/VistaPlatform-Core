// Package identitysettings owns the audited tenant controls for identity admission
// and enrichment. Workers continue to read the existing shared settings keys.
package identitysettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const MaxExcludedCIDRs = 128
const MaxSensitiveAssetIDs = 256
const MaxReasonLength = 2000

var ErrStaleVersion = errors.New("stale_version")
var ErrCapability = errors.New("activation_required_release")
var ErrActivated = errors.New("pause_required_after_activation")
var ErrInvalid = errors.New("invalid_identity_discovery_settings")

type Enrichment struct {
	Enabled           bool        `json:"enabled"`
	ExcludedCIDRs     []string    `json:"excluded_cidrs"`
	SensitiveAssetIDs []uuid.UUID `json:"sensitive_asset_ids"`
}
type Capabilities struct {
	Admission  bool `json:"admission"`
	Enrichment bool `json:"enrichment"`
}
type Limits struct {
	MaxExcludedCIDRs     int `json:"max_excluded_cidrs"`
	MaxSensitiveAssetIDs int `json:"max_sensitive_asset_ids"`
	MaxReasonLength      int `json:"max_reason_length"`
}
type Settings struct {
	Mode         string       `json:"mode"`
	Enrichment   Enrichment   `json:"enrichment"`
	Version      int          `json:"version"`
	ActivatedAt  *time.Time   `json:"activated_at"`
	Capabilities Capabilities `json:"capabilities"`
	Limits       Limits       `json:"limits"`
}
type Update struct {
	Mode       string
	Enrichment Enrichment
	Version    int
	Reason     string
}
type Store struct {
	db           *database.DB
	capabilities func() identity.ReleaseCapabilities
}

func NewStore(db *database.DB) *Store {
	return &Store{db: db, capabilities: identity.AvailableCapabilities}
}

func (s *Store) decode(raw []byte, version int) (Settings, error) {
	out := Settings{Mode: "disabled", Version: version, Enrichment: Enrichment{ExcludedCIDRs: []string{}, SensitiveAssetIDs: []uuid.UUID{}}, Limits: Limits{MaxExcludedCIDRs, MaxSensitiveAssetIDs, MaxReasonLength}}
	caps := s.capabilities()
	out.Capabilities = Capabilities{caps.Admission, caps.Enrichment}
	var config struct {
		Admission struct {
			Mode        string     `json:"mode"`
			ActivatedAt *time.Time `json:"activated_at"`
		} `json:"identity_admission"`
		Enrichment Enrichment `json:"identity_enrichment"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &config); err != nil {
			return out, err
		}
	}
	if config.Admission.Mode != "" {
		out.Mode = config.Admission.Mode
	}
	out.ActivatedAt = config.Admission.ActivatedAt
	out.Enrichment = config.Enrichment
	if out.Enrichment.ExcludedCIDRs == nil {
		out.Enrichment.ExcludedCIDRs = []string{}
	}
	if out.Enrichment.SensitiveAssetIDs == nil {
		out.Enrichment.SensitiveAssetIDs = []uuid.UUID{}
	}
	return out, nil
}
func (s *Store) Get(ctx context.Context, tenant uuid.UUID) (Settings, error) {
	var raw []byte
	version := 1
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT config,version FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&raw, &version)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return Settings{}, err
	}
	return s.decode(raw, version)
}
func normalize(in Update) (Update, error) {
	switch in.Mode {
	case "disabled", "observe", "enforce", "paused":
	default:
		return in, fmt.Errorf("%w: unsupported mode", ErrInvalid)
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Version < 1 || len(in.Reason) < 3 || len(in.Reason) > MaxReasonLength {
		return in, fmt.Errorf("%w: version and a reason of 3–2000 characters are required", ErrInvalid)
	}
	if in.Enrichment.ExcludedCIDRs == nil || in.Enrichment.SensitiveAssetIDs == nil || len(in.Enrichment.ExcludedCIDRs) > MaxExcludedCIDRs || len(in.Enrichment.SensitiveAssetIDs) > MaxSensitiveAssetIDs {
		return in, fmt.Errorf("%w: exclusion lists are required and must be within their limits", ErrInvalid)
	}
	if in.Enrichment.Enabled && in.Mode != "enforce" && in.Mode != "paused" {
		return in, fmt.Errorf("%w: enrichment requires enforced or paused admission", ErrInvalid)
	}
	cidrs := map[string]bool{}
	for _, raw := range in.Enrichment.ExcludedCIDRs {
		if len(raw) > 64 {
			return in, fmt.Errorf("%w: excluded CIDR exceeds 64 characters", ErrInvalid)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return in, fmt.Errorf("%w: invalid excluded CIDR", ErrInvalid)
		}
		cidrs[prefix.Masked().String()] = true
	}
	in.Enrichment.ExcludedCIDRs = []string{}
	for cidr := range cidrs {
		in.Enrichment.ExcludedCIDRs = append(in.Enrichment.ExcludedCIDRs, cidr)
	}
	sort.Strings(in.Enrichment.ExcludedCIDRs)
	ids := map[uuid.UUID]bool{}
	for _, id := range in.Enrichment.SensitiveAssetIDs {
		if id == uuid.Nil {
			return in, fmt.Errorf("%w: invalid sensitive asset ID", ErrInvalid)
		}
		ids[id] = true
	}
	in.Enrichment.SensitiveAssetIDs = []uuid.UUID{}
	for id := range ids {
		in.Enrichment.SensitiveAssetIDs = append(in.Enrichment.SensitiveAssetIDs, id)
	}
	sort.Slice(in.Enrichment.SensitiveAssetIDs, func(i, j int) bool {
		return in.Enrichment.SensitiveAssetIDs[i].String() < in.Enrichment.SensitiveAssetIDs[j].String()
	})
	return in, nil
}
func (s *Store) Set(ctx context.Context, tenant, actor uuid.UUID, in Update) (Settings, error) {
	in, err := normalize(in)
	if err != nil {
		return Settings{}, err
	}
	var out Settings
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		var actorID any
		if actor != uuid.Nil {
			actorID = actor
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO NOTHING`, tenant); err != nil {
			return err
		}
		var raw []byte
		var version int
		if err := tx.QueryRowContext(ctx, `SELECT config,version FROM tenant_admin_settings WHERE tenant_id=$1 FOR UPDATE`, tenant).Scan(&raw, &version); err != nil {
			return err
		}
		current, err := s.decode(raw, version)
		if err != nil {
			return err
		}
		if version != in.Version {
			return ErrStaleVersion
		}
		// Already-enforced pre-API configuration also must never fall back to the
		// permissive path, even when its original activation clock is unavailable.
		activated := current.ActivatedAt != nil || current.Mode == "enforce"
		if activated && in.Mode != "enforce" && in.Mode != "paused" {
			return ErrActivated
		}
		caps := s.capabilities()
		if (in.Mode == "observe" || in.Mode == "enforce" || (in.Mode == "paused" && !activated)) && !caps.Admission {
			return ErrCapability
		}
		if in.Enrichment.Enabled && !caps.Enrichment && (in.Mode != "paused" || !current.Enrichment.Enabled) {
			return ErrCapability
		}
		if len(in.Enrichment.SensitiveAssetIDs) > 0 {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND id=ANY($2) AND deleted_at IS NULL`, tenant, pq.Array(in.Enrichment.SensitiveAssetIDs)).Scan(&count); err != nil {
				return err
			}
			if count != len(in.Enrichment.SensitiveAssetIDs) {
				return fmt.Errorf("%w: sensitive assets must belong to this tenant", ErrInvalid)
			}
		}
		activation := current.ActivatedAt
		if activation == nil && (activated || in.Mode == "enforce") {
			now := time.Now().UTC()
			activation = &now
		}
		admission, err := json.Marshal(map[string]any{"mode": in.Mode, "activated_at": activation})
		if err != nil {
			return err
		}
		enrichment, err := json.Marshal(in.Enrichment)
		if err != nil {
			return err
		}
		// Merge just our fields into their namespaces. Other producers' config and
		// future fields survive, including concurrent autoscan worker state.
		if err := tx.QueryRowContext(ctx, `UPDATE tenant_admin_settings SET config=jsonb_set(jsonb_set(config,'{identity_admission}',COALESCE(config->'identity_admission','{}')||$2::jsonb),'{identity_enrichment}',COALESCE(config->'identity_enrichment','{}')||$3::jsonb),version=version+1,updated_by=$4,updated_at=now() WHERE tenant_id=$1 RETURNING config,version`, tenant, string(admission), string(enrichment), actorID).Scan(&raw, &version); err != nil {
			return err
		}
		// The existing AFTER UPDATE trigger owns before/after snapshots and actor.
		// Row serialization makes this exact version pair ours, not another writer's.
		if _, err := tx.ExecContext(ctx, `UPDATE tenant_admin_settings_audit SET change_reason=$4 WHERE tenant_id=$1 AND version_before=$2 AND version_after=$3`, tenant, in.Version, version, in.Reason); err != nil {
			return err
		}
		out, err = s.decode(raw, version)
		return err
	})
	return out, err
}
