package dispatchguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func IsAutomaticScan(options map[string]interface{}) bool { return options["origin"] == "auto_scan" }

// AuthorizeAutomaticScan protects the preexisting asset scanner as well as
// identity enrichment. Call within the transaction that queues or starts work;
// policy is locked before reading asset protection, matching merge lock order.
func AuthorizeAutomaticScan(tx Queryer, payload sensordispatch.Payload) error {
	if !IsAutomaticScan(payload.Options) {
		return nil
	}
	var raw []byte
	if err := tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, payload.TenantID).Scan(&raw); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	config := map[string]interface{}{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &config); err != nil {
			return denied("invalid automatic-scan policy")
		}
	}
	restrictions, err := autoscan.RestrictionsFromConfig(config)
	if err != nil {
		return denied("invalid automatic-scan restrictions")
	}
	policy, err := autoscan.Normalize(autoscan.FromConfig(config))
	if err != nil {
		return denied("invalid automatic-scan policy")
	}
	if restrictions.Paused || !policy.Enabled {
		return ErrPaused
	}
	if len(payload.Protocols) == 0 || len(payload.Ports) == 0 || len(payload.Targets) == 0 || len(payload.Targets) > 1000 {
		return denied("automatic scan exceeds explicit target/protocol bounds")
	}
	for _, protocol := range payload.Protocols {
		if !slices.Contains(policy.Protocols, protocol) {
			return denied("automatic scan protocol no longer authorized")
		}
	}
	for _, port := range payload.Ports {
		if !slices.Contains(policy.Ports, port) {
			return denied("automatic scan port no longer authorized")
		}
	}
	var segmentRaw []byte
	if err := tx.QueryRow(`SELECT COALESCE(jsonb_agg(jsonb_build_object('value',value,'network_type',network_type,'blocked',COALESCE(metadata->>'sensitive','false')='true' OR COALESCE(metadata->>'active_probes_disabled','false')='true')),'[]') FROM network_segments WHERE tenant_id=$1 AND is_active AND segment_type='cidr'`, payload.TenantID).Scan(&segmentRaw); err != nil {
		return err
	}
	var segments []struct {
		Value       string
		NetworkType string `json:"network_type"`
		Blocked     bool
	}
	if err := json.Unmarshal(segmentRaw, &segments); err != nil {
		return err
	}
	excluded := append(autoscan.PlatformExcludedPrefixes(), restrictions.Excluded...)
	allowed := []netip.Prefix{}
	for _, seg := range segments {
		prefix, err := netip.ParsePrefix(seg.Value)
		if err != nil {
			continue
		}
		if seg.Blocked {
			excluded = append(excluded, prefix)
		} else if seg.NetworkType == "private" || seg.NetworkType == "vpn" || seg.NetworkType == "cloud" {
			allowed = append(allowed, prefix)
		}
	}
	for _, target := range payload.Targets {
		address, _, valid := autoscan.ParseTarget(target)
		if !valid {
			return denied("automatic scan requires individual addresses")
		}
		if ok, _ := autoscan.Classify(address, allowed, excluded); !ok {
			return denied("automatic scan address is excluded or outside authorized scope")
		}
		var assetRaw []byte
		if err := tx.QueryRow(`SELECT COALESCE(jsonb_agg(jsonb_build_object('id',a.id,'class',a.class_key,'eligible',a.deleted_at IS NULL AND a.asset_status NOT IN ('denied','archived') AND a.asset_ownership<>'third_party' AND COALESCE(a.stale_status,'')<>'archived')),'[]') FROM assets a WHERE a.tenant_id=$1 AND (a.primary_address=$2::inet OR EXISTS(SELECT 1 FROM asset_endpoints e WHERE e.tenant_id=a.tenant_id AND e.asset_id=a.id AND e.address=$2::inet))`, payload.TenantID, address.String()).Scan(&assetRaw); err != nil {
			return err
		}
		var assets []struct {
			ID       uuid.UUID
			Class    string
			Eligible bool
		}
		if err := json.Unmarshal(assetRaw, &assets); err != nil {
			return err
		}
		eligible := false
		for _, a := range assets {
			if restrictions.ProtectsAsset(a.ID, a.Class) {
				return denied("automatic scan target belongs to a sensitive asset")
			}
			eligible = eligible || a.Eligible
		}
		if !eligible {
			return denied("automatic scan target has no eligible tenant asset")
		}
	}
	return nil
}
