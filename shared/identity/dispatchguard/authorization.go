// Package dispatchguard rechecks queued identity enrichment against current tenant policy.
package dispatchguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// Recheck automatic work when it leaves the durable queue. Hold the policy
// row until command insertion commits so a committed pause wins the race.
var ErrPaused = errors.New("identity enrichment is paused")

// ErrDenied is the package-wide refusal. Its wording is deliberately not
// enrichment-specific any more: since #H5 the same sentinel also carries target
// authorization refusals for MANUAL jobs, which have nothing to do with
// identity enrichment.
var ErrDenied = errors.New("scan dispatch is not authorized")

func denied(message string) error { return fmt.Errorf("%w: %s", ErrDenied, message) }

type Queryer interface{ QueryRow(string, ...any) *sql.Row }

func AuthorizeProbe(tx Queryer, payload sensordispatch.Payload, sensor uuid.UUID) error {
	if err := AuthorizeAutomaticScan(tx, payload); err != nil {
		return err
	}
	return authorize(tx, payload, sensor, nil)
}

func authorize(tx Queryer, payload sensordispatch.Payload, sensor uuid.UUID, dns *sensordispatch.IdentityDNSRequest) error {
	if _, ok := payload.Options["identity_enrichment_request_id"]; !ok {
		return nil
	}
	var raw []byte
	if err := tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, payload.TenantID).Scan(&raw); err != nil {
		return err
	}
	var policy struct {
		Admission struct {
			Mode string `json:"mode"`
		} `json:"identity_admission"`
		Enrichment struct {
			Enabled   bool        `json:"enabled"`
			Excluded  []string    `json:"excluded_cidrs"`
			Sensitive []uuid.UUID `json:"sensitive_asset_ids"`
		} `json:"identity_enrichment"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return denied("invalid enrichment policy")
	}
	if policy.Admission.Mode != "enforce" || !policy.Enrichment.Enabled {
		return ErrPaused
	}
	var config map[string]interface{}
	if err := json.Unmarshal(raw, &config); err != nil {
		return denied("invalid scan policy")
	}
	scan, err := autoscan.Normalize(autoscan.FromConfig(config))
	if err != nil {
		return denied("invalid scan policy")
	}
	if !scan.Enabled {
		return denied("automatic probing is disabled")
	}
	for _, protocol := range payload.Protocols {
		if !slices.Contains(scan.Protocols, protocol) {
			return denied("probe protocol is no longer authorized")
		}
	}
	for _, port := range payload.Ports {
		if !slices.Contains(scan.Ports, port) {
			return denied("probe port is no longer authorized")
		}
	}
	observation, err := uuid.Parse(fmt.Sprint(payload.Options["identity_observation_id"]))
	if err != nil {
		return denied("probe observation is invalid")
	}
	segment, err := uuid.Parse(fmt.Sprint(payload.Options["identity_network_scope"]))
	if err != nil {
		return denied("probe scope is invalid")
	}
	var evidence []byte
	var asset *uuid.UUID
	var state, class string
	if err := tx.QueryRow(`SELECT o.evidence,o.asset_id,o.state,COALESCE(a.class_key,'') FROM identity_observations o LEFT JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id WHERE o.tenant_id=$1 AND o.id=$2 AND o.last_seen_at>now()-interval '30 days'`, payload.TenantID, observation).Scan(&evidence, &asset, &state, &class); err != nil {
		return err
	}
	if state == "conflict" || state == "dismissed" || state == "expired" {
		return denied("probe observation no longer eligible")
	}
	if asset != nil && slices.Contains(policy.Enrichment.Sensitive, *asset) {
		return denied("sensitive asset requires review")
	}
	var obs identity.Observation
	if err := json.Unmarshal(evidence, &obs); err != nil {
		return denied("invalid observation evidence")
	}
	parts := strings.Split(obs.Source.Ref, ":")
	if obs.Network.SegmentID != segment.String() || obs.Source.Kind != identity.SourceMeasured || len(parts) < 2 || (parts[0] != "sensor" && parts[0] != "scan") || parts[len(parts)-1] != sensor.String() {
		return denied("probe source or scope changed")
	}
	if class == "" {
		class = obs.ClassHint
	}
	if strings.Contains(class, "industrial") || strings.Contains(class, "medical") || assetclass.IsAncestor(assetclass.KeyOtDevice, class) || strings.HasPrefix(class, "ot_") {
		return denied("sensitive device requires review")
	}
	var cidr string
	if err := tx.QueryRow(`SELECT value FROM network_segments WHERE tenant_id=$1 AND id=$2 AND is_active AND segment_type='cidr' AND COALESCE(cloud_network_ref,'')='' AND COALESCE(metadata->>'sensitive','false')<>'true' AND COALESCE(metadata->>'active_probes_disabled','false')<>'true'`, payload.TenantID, segment).Scan(&cidr); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || prefix.Bits() == 0 {
		return denied("probe network scope is unresolved")
	}
	var overlaps bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM network_segments WHERE tenant_id=$1 AND id<>$2 AND is_active AND CASE WHEN segment_type='cidr' THEN value::cidr && $3::cidr ELSE false END)`, payload.TenantID, segment, cidr).Scan(&overlaps); err != nil {
		return err
	}
	if overlaps {
		return denied("probe network scope overlaps another segment")
	}
	var reachable bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM agent_addresses a JOIN sensors s ON s.id=a.sensor_id WHERE s.id=$1 AND s.tenant_id=$2 AND s.deleted_at IS NULL AND s.status='active' AND NOT s.air_gapped AND s.version<>'' AND s.profile<>'' AND s.last_heartbeat>now()-interval '2 minutes' AND a.last_seen_at>now()-interval '5 minutes' AND a.interface_name=ANY(s.reported_dns_interfaces) AND a.prefix_length IS NOT NULL AND a.address << $3::cidr AND family(a.address)=family($3::cidr) AND set_masklen(a.address,a.prefix_length) && $3::cidr)`, sensor, payload.TenantID, cidr).Scan(&reachable); err != nil {
		return err
	}
	if !reachable {
		return denied("observing collector network scope is no longer reachable")
	}
	excluded := autoscan.PlatformExcludedPrefixes()
	for _, raw := range policy.Enrichment.Excluded {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return denied("invalid exclusion policy")
		}
		excluded = append(excluded, p)
	}
	if dns != nil {
		if prefix.Masked().String() != dns.SegmentCIDR {
			return denied("DNS network scope changed")
		}
		for _, p := range excluded {
			if p.Bits() <= prefix.Bits() && p.Contains(prefix.Addr()) {
				return denied("DNS network scope is excluded")
			}
		}
		var capable bool
		if err := tx.QueryRow(`SELECT $3=ANY(reported_capabilities) FROM sensors WHERE id=$1 AND tenant_id=$2`, sensor, payload.TenantID, sensordispatch.IdentityDNSCapability).Scan(&capable); err != nil {
			return err
		}
		if !capable {
			return denied("collector DNS capability was withdrawn")
		}
		for _, id := range obs.Identifiers {
			scoped := id.Scope == segment.String() || (id.Kind == identity.KindFQDN && id.Scope == "")
			if scoped && (id.Kind == identity.KindHostname || id.Kind == identity.KindFQDN) && strings.TrimSuffix(strings.ToLower(id.Value), ".") == strings.TrimSuffix(dns.Hostname, ".") {
				return nil
			}
		}
		return denied("DNS hostname is no longer supported by observation evidence")
	}
	if len(payload.Protocols) == 0 || len(payload.Ports) == 0 {
		return denied("probe requires explicit protocols and ports")
	}
	if len(payload.Targets) == 0 || len(payload.Targets) > 8 {
		return denied("probe exceeds target bounds")
	}
	for _, target := range payload.Targets {
		address, err := netip.ParseAddr(target)
		if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || !prefix.Contains(address.Unmap()) {
			return denied("probe target outside authorized scope")
		}
		for _, p := range excluded {
			if p.Contains(address.Unmap()) {
				return denied("probe target is excluded")
			}
		}
		var collectorAddress bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM agent_addresses WHERE sensor_id=$1 AND address=$2::inet)`, sensor, target).Scan(&collectorAddress); err != nil {
			return err
		}
		if collectorAddress {
			return denied("probe target belongs to observing collector")
		}
	}
	return nil
}

// AuthorizeDNS applies the same tenant, evidence, sensitivity and reachability
// checks as probes, and binds a bounded lookup to the original scoped name.
func AuthorizeDNS(tx Queryer, tenant, sensor uuid.UUID, req sensordispatch.IdentityDNSRequest) error {
	if err := req.Validate(); err != nil {
		return denied(err.Error())
	}
	return authorize(tx, sensordispatch.Payload{TenantID: tenant.String(), Options: map[string]interface{}{
		"identity_enrichment_request_id": req.RequestID, "identity_observation_id": req.ObservationID, "identity_network_scope": req.NetworkScope,
	}}, sensor, &req)
}
