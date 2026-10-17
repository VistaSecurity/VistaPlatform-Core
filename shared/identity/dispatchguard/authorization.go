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
	"github.com/lib/pq"
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
	// The addresses and ports the sensor will contact, from the legacy
	// payload or from a plan (planned.go, WP2). A DNS request carries
	// neither and reads as an empty legacy scope.
	probe, err := probeScopeOf(payload)
	if err != nil {
		return err
	}
	for _, protocol := range probe.Protocols {
		if !slices.Contains(scan.Protocols, protocol) {
			return denied("probe protocol is no longer authorized")
		}
	}
	for _, port := range probe.Ports {
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
	// Re-read at dispatch, inside this transaction: the evidence must still be
	// a measurement in the network scope the job was planned for, by a named
	// collector. The OBSERVER is no longer required to be the collector the
	// job runs on (see observerOf).
	observer, ok := observerOf(obs, segment)
	if !ok {
		return denied("probe source or scope changed")
	}
	if class == "" {
		class = obs.ClassHint
	}
	if strings.Contains(class, "industrial") || strings.Contains(class, "medical") || assetclass.IsAncestor(assetclass.KeyOtDevice, class) || strings.HasPrefix(class, "ot_") {
		return denied("sensitive device requires review")
	}
	// The network scope is an IPAM prefix (DCIM row 1.6): a live global-VRF
	// prefix with no cloud network ref, not marked sensitive or
	// active-probes-disabled, that names exactly one place — not a container,
	// no other live prefix with the same CIDR (the rule provisional inventory
	// applies), and no live prefix INSIDE it: a more specific prefix created
	// since the evidence was scoped is now where its addresses belong, so the
	// planned scope is stale. A PARENT is fine — prefixes nest by design, and
	// refusing every prefix with a parent would refuse nearly all of them.
	var cidr, networkType, opStatus string
	var learned bool
	var twins, children int
	if err := tx.QueryRow(`SELECT p.prefix::text,COALESCE(p.network_type,''),p.source_kind IN ('measured','inferred'),p.operational_status,
		(SELECT count(*) FROM prefixes o WHERE o.tenant_id=p.tenant_id AND o.vrf_id IS NULL AND o.id<>p.id AND o.prefix=p.prefix AND o.status NOT IN ('rejected','archived')),
		(SELECT count(*) FROM prefixes o WHERE o.tenant_id=p.tenant_id AND o.vrf_id IS NULL AND o.prefix<<p.prefix AND o.status NOT IN ('rejected','archived'))
		FROM prefixes p WHERE p.tenant_id=$1 AND p.id=$2 AND p.vrf_id IS NULL AND p.status NOT IN ('rejected','archived')
		AND COALESCE(p.cloud_network_ref,'')='' AND NOT p.sensitive AND NOT p.active_probes_disabled`, payload.TenantID, segment).Scan(&cidr, &networkType, &learned, &opStatus, &twins, &children); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || prefix.Bits() == 0 || opStatus == "container" {
		return denied("probe network scope is unresolved")
	}
	if PrefixNetworkType(networkType, prefix) == "public" && learned {
		// A public network learned from a device is where that device is
		// connected — an ISP transit link, a carrier-NAT WAN — not an estate
		// the tenant declared. It scopes identities; it never scopes a probe —
		// unless a person has claimed it (set its source to declared). See
		// SegmentGrantsOwnership.
		return denied("probe network scope is a learned public network")
	}
	if twins > 0 || children > 0 {
		return denied("probe network scope overlaps another prefix")
	}
	// The EXECUTOR — the collector this work is dispatched to — must be a live
	// tenant collector with an interface on the target network. This is the
	// whole of the executor's authorization, so it also excludes the
	// platform's own collectors, which identity enrichment never selects: the
	// platform sensor serves every tenant.
	var reachable bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM agent_addresses a JOIN sensors s ON s.id=a.sensor_id WHERE s.id=$1 AND s.tenant_id=$2 AND s.deleted_at IS NULL AND NOT `+platformCollectorSQL+` AND s.status='active' AND NOT s.air_gapped AND s.version<>'' AND s.profile<>'' AND s.profile<>'system' AND s.last_heartbeat>now()-interval '2 minutes' AND a.last_seen_at>now()-interval '5 minutes' AND a.interface_name=ANY(s.reported_dns_interfaces) AND a.prefix_length IS NOT NULL AND a.address << $3::cidr AND family(a.address)=family($3::cidr) AND set_masklen(a.address,a.prefix_length) && $3::cidr)`, sensor, payload.TenantID, cidr).Scan(&reachable); err != nil {
		return err
	}
	if !reachable {
		return denied("executing collector network scope is no longer reachable")
	}
	// The OBSERVER is provenance only: the collector the evidence came from
	// must be a current collector of THIS tenant, and not the platform's. It
	// need not be live or reach the network — a sensor on one VLAN that heard
	// an advert about another is exactly the case an executor exists for.
	// Without this, a ref naming another tenant's sensor (or an unknown id)
	// would pass, since nothing above compares it with anything any more.
	var tenantObserver bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sensors s WHERE s.id=$1 AND s.tenant_id=$2 AND s.deleted_at IS NULL AND NOT `+platformCollectorSQL+`)`, observer, payload.TenantID).Scan(&tenantObserver); err != nil {
		return err
	}
	if !tenantObserver {
		return denied("probe source is not a collector of this tenant")
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
	// A plan names no protocols: services are identified from what answers.
	if (!probe.Planned && len(probe.Protocols) == 0) || len(probe.Ports) == 0 {
		return denied("probe requires explicit protocols and ports")
	}
	if len(probe.Targets) == 0 || len(probe.Targets) > 8 {
		return denied("probe exceeds target bounds")
	}
	for _, target := range probe.Targets {
		address, err := netip.ParseAddr(target)
		if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || !prefix.Contains(address.Unmap()) {
			return denied("probe target outside authorized scope")
		}
		for _, p := range excluded {
			if p.Contains(address.Unmap()) {
				return denied("probe target is excluded")
			}
		}
		// Neither collector's own interface is ever a target. They were one
		// collector when this check was written; now that they can differ,
		// both are excluded. The rule is collectorAddressesSQL, shared with the
		// planner (identityenrichment.Store.Scope) so the two cannot drift again.
		var collectorAddress bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM (`+collectorAddressesSQL+`) c WHERE c.address=$2::inet)`, pq.StringArray{sensor.String(), observer.String()}, target).Scan(&collectorAddress); err != nil {
			return err
		}
		if collectorAddress {
			return denied("probe target belongs to a collector")
		}
	}
	return nil
}

// platformCollectorSQL is true for a sensors row (alias s) that belongs to the
// platform rather than to the tenant: any of the markers only platform
// provisioning may set.
const platformCollectorSQL = `(s.platform_managed OR s.platform='platform' OR COALESCE(s.tags,'{}'::text[]) && ARRAY['system','platform']::text[])`

// observerOf returns the collector an observation names as its producer.
//
// The evidence must be a measurement, in the network scope the job was planned
// for, from a `sensor:…:<id>` or `scan:…:<id>` ref. Anything else — an
// interrogation, a cloud or imported source, a ref with no collector id — is
// refused as it always was: only a collector's own measurement may direct
// unattended probing. The id must be in canonical form, because until the
// executor was split from the observer this was a string comparison with the
// dispatched sensor's id, and a looser parse must not admit refs it refused.
//
// Since the executor was split from the observer (the planner prefers the
// observer, otherwise any eligible tenant collector on the target network),
// the id is NOT compared with the sensor the job is dispatched to. authorize
// checks it separately for provenance, and checks the executor on its own.
func observerOf(obs identity.Observation, segment uuid.UUID) (uuid.UUID, bool) {
	parts := strings.Split(obs.Source.Ref, ":")
	if obs.Network.SegmentID != segment.String() || obs.Source.Kind != identity.SourceMeasured || len(parts) < 2 || (parts[0] != "sensor" && parts[0] != "scan") {
		return uuid.Nil, false
	}
	last := parts[len(parts)-1]
	id, err := uuid.Parse(last)
	if err != nil || id == uuid.Nil || id.String() != last {
		return uuid.Nil, false
	}
	return id, true
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
