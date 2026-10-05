package dispatchguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
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
	// The addresses and ports the scanner will contact, from the legacy
	// payload or from a plan (planned.go, WP2).
	scope, err := probeScopeOf(payload)
	if err != nil {
		return err
	}
	// A plan names no protocols: services are identified from what answers.
	if (!scope.Planned && len(scope.Protocols) == 0) || len(scope.Ports) == 0 || len(scope.Targets) == 0 || len(scope.Targets) > 1000 {
		return denied("automatic scan exceeds explicit target/protocol bounds")
	}
	if scope.Planned && len(scope.Ports) > autoscan.MaxPorts {
		return denied("automatic scan names more ports than the automatic-scan policy allows")
	}
	for _, protocol := range scope.Protocols {
		if !slices.Contains(policy.Protocols, protocol) {
			return denied("automatic scan protocol no longer authorized")
		}
	}
	for _, port := range scope.Ports {
		if !slices.Contains(policy.Ports, port) {
			return denied("automatic scan port no longer authorized")
		}
	}
	var segmentRaw []byte
	if err := tx.QueryRow(`SELECT COALESCE(jsonb_agg(jsonb_build_object('value',value,'network_type',network_type,'learned',`+learnedSegmentSQL+`,'imported',`+connectionImportedSegmentSQL+`,'blocked',COALESCE(metadata->>'sensitive','false')='true' OR COALESCE(metadata->>'active_probes_disabled','false')='true')),'[]') FROM network_segments WHERE tenant_id=$1 AND is_active AND segment_type='cidr'`, payload.TenantID).Scan(&segmentRaw); err != nil {
		return err
	}
	var segments []struct {
		Value       string
		NetworkType string `json:"network_type"`
		Learned     bool
		Imported    bool
		Blocked     bool
	}
	if err := json.Unmarshal(segmentRaw, &segments); err != nil {
		return err
	}
	excluded := append(autoscan.PlatformExcludedPrefixes(), restrictions.Excluded...)
	allowed := []netip.Prefix{}
	// declared: the segments a person registered. Connection consent is not
	// required for an address inside one (SegmentDeclaresAutomaticScope).
	declared := []netip.Prefix{}
	for _, seg := range segments {
		prefix, err := netip.ParsePrefix(seg.Value)
		if err != nil {
			continue
		}
		if seg.Blocked {
			excluded = append(excluded, prefix)
		} else if SegmentPrefixGrantsOwnership(prefix, seg.NetworkType, seg.Learned, true) {
			allowed = append(allowed, prefix)
			if SegmentDeclaresAutomaticScope(prefix, seg.NetworkType, seg.Learned, seg.Imported) {
				declared = append(declared, prefix)
			}
		}
	}
	// Every target is judged in order, and the first refusal is the one
	// returned, exactly as when each target was checked on its own. The
	// address rules need no database; the targets that pass them, up to the
	// first that does not, are then looked up in ONE query (targetAssets), so
	// a 1000-target job costs the same number of round trips as a 1-target
	// one.
	var addressRefusal error
	addresses := make([]netip.Addr, 0, len(scope.Targets))
	for _, target := range scope.Targets {
		address, _, valid := autoscan.ParseTarget(target)
		if !valid {
			addressRefusal = denied("automatic scan requires individual addresses")
			break
		}
		if ok, _ := autoscan.Classify(address, allowed, excluded); !ok {
			addressRefusal = denied("automatic scan address is excluded or outside authorized scope")
			break
		}
		addresses = append(addresses, address)
	}
	assets, err := targetAssets(tx, payload.TenantID, addresses)
	if err != nil {
		return err
	}
	for i, address := range addresses {
		eligible := false
		for _, a := range assets[i] {
			if restrictions.ProtectsAsset(a.ID, a.Class) {
				return denied("automatic scan target belongs to a sensitive asset")
			}
			// An asset known only from an import counts only when one of
			// its importing sources allows active scanning
			// (ImportedWithoutConsentSQL), or when the address lies in a
			// segment a person declared: an address whose only tenant asset
			// came from a CMDB or NetBox with no consent, in private space
			// nobody registered, is refused at every stage — job creation,
			// platform execution and sensor pickup — not only by the planner.
			eligible = eligible || (a.Eligible && (!a.ImportBlocked || InAnyPrefix(address, declared)))
		}
		if !eligible {
			return denied("automatic scan target has no eligible tenant asset")
		}
	}
	return addressRefusal
}

// targetAsset is one tenant asset holding a target address (as its primary
// address or as an endpoint).
type targetAsset struct {
	ID    uuid.UUID
	Class string
	// Eligible: live, not denied or archived, not third-party.
	Eligible bool
	// ImportBlocked: known only from a connection that does not consent to
	// active scanning (autoscan.ImportedWithoutConsentSQL). Applies only
	// outside declared segments; the caller decides that.
	ImportBlocked bool `json:"import_blocked"`
}

// targetAssets returns, for each address, the tenant assets that hold it, in
// one set-based query. The consent clause is left out entirely when the
// tenant has no import-only asset (autoscan.AnyImportOnlySQL), which is the
// case for every tenant without connections.
func targetAssets(tx Queryer, tenantID string, addresses []netip.Addr) ([][]targetAsset, error) {
	out := make([][]targetAsset, len(addresses))
	if len(addresses) == 0 {
		return out, nil
	}
	var anyImportOnly bool
	if err := tx.QueryRow(autoscan.AnyImportOnlySQL, tenantID).Scan(&anyImportOnly); err != nil {
		return nil, err
	}
	importBlocked := "false"
	if anyImportOnly {
		importBlocked = autoscan.ImportedWithoutConsentSQL("a")
	}
	values := make([]string, len(addresses))
	for i, address := range addresses {
		values[i] = address.String()
	}
	var raw []byte
	if err := tx.QueryRow(`WITH t AS (
			SELECT u.addr, u.ord FROM unnest($2::text[]::inet[]) WITH ORDINALITY AS u(addr, ord)
		), hits AS (
			SELECT t.ord, a.id FROM t JOIN assets a ON a.tenant_id = $1 AND a.primary_address = t.addr
			UNION
			SELECT t.ord, e.asset_id FROM t JOIN asset_endpoints e ON e.tenant_id = $1 AND e.address = t.addr
		)
		SELECT COALESCE(jsonb_agg(jsonb_build_object('ord',h.ord,'id',a.id,'class',a.class_key,
			'eligible',a.deleted_at IS NULL AND a.asset_status NOT IN ('denied','archived') AND a.asset_ownership<>'third_party' AND COALESCE(a.stale_status,'')<>'archived',
			'import_blocked',`+importBlocked+`)),'[]')
		  FROM hits h JOIN assets a ON a.tenant_id = $1 AND a.id = h.id`, tenantID, pq.Array(values)).Scan(&raw); err != nil {
		return nil, err
	}
	var rows []struct {
		Ord int `json:"ord"`
		targetAsset
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Ord < 1 || r.Ord > len(addresses) {
			return nil, errors.New("dispatchguard: target lookup returned an unknown address")
		}
		out[r.Ord-1] = append(out[r.Ord-1], r.targetAsset)
	}
	return out, nil
}
