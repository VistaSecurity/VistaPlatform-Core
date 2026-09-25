package dispatchguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"

	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// OwnedNetworks is what a sensor is told, on its heartbeat, about the public
// space this tenant has claimed ( W5.13, owner decision Q10). The sensor's
// TLS enricher reacts to traffic it saw passively, so it must decide locally,
// per destination, whether a handshake would be unsolicited traffic to a third
// party. Private space it can judge by itself; this is the rest.
//
// It lists:
//
//   - every active CIDR segment the tenant DECLARED that grants ownership for
//     a scan a person asked for ([SegmentGrantsOwnership] with automatic=false),
//     except segments marked sensitive or active-probes-disabled, and except
//     prefixes wholly inside private address space (the sensor already owns
//     those). Enrichment is automatic, yet it takes the manual-scan reading of
//     a PUBLIC segment on purpose: the unattended sweep refuses public space
//     because it would go looking for hosts, whereas enrichment only ever
//     reaches a service the tenant's own hosts were already talking to, inside
//     a range the tenant said is theirs. That is the owner's "owned assets ...
//     they configure within their own tenant".
//   - never a prefix too broad to be anybody's ([probeconsent.TooBroadToClaim]:
//     shorter than /8 for IPv4 or /16 for IPv6, /0 above all).
//   - LEARNED segments never. A firewall reporting its ISP transit /30 is not
//     a claim of ownership (see [SegmentGrantsOwnership]).
//   - every endpoint the tenant ELEVATED from an external connection to a
// monitored asset whose asset still exists and is monitored. The
//     elevation path keeps a promoted asset current by refreshing it in place
//     on re-discovery, and for a TLS 1.3 service the enrichment handshake IS
//     the re-discovery that carries the certificate — without this, elevating
//     a vendor endpoint would freeze its certificate at whatever was captured
//     before the click.
//   - as EXCLUDED: every segment marked sensitive or active-probes-disabled
//     (learned or declared) and the tenant's automatic-scan exclusions — the
//     same exclusions LoadTargetScope applies to dispatched scans. The sensor
//     lets an exclusion beat everything, including the third-party opt-in.
//
// Call it inside a tenant-scoped transaction: network_segments, assets and
// external_connections are all RLS tables.
func OwnedNetworks(tx Queryer, tenantID string) (probeconsent.OwnedNetworks, error) {
	out := probeconsent.OwnedNetworks{Prefixes: []string{}, Endpoints: []string{}, Excluded: []string{}}
	excluded := map[netip.Prefix]bool{}
	excludedList := func() []string {
		list := make([]string, 0, len(excluded))
		for p := range excluded {
			list = append(list, p.String())
		}
		sort.Strings(list)
		return list
	}
	// incomplete is what is sent when the set cannot be built: NO ownership
	// (an owned set the sensor could not refresh must not keep granting
	// probes forever — review), and every exclusion that WAS read,
	// flagged so the sensor keeps the exclusions it already knew as well. The
	// error is still returned, for the caller to log.
	incomplete := func(err error) (probeconsent.OwnedNetworks, error) {
		return probeconsent.OwnedNetworks{Prefixes: []string{}, Endpoints: []string{}, Excluded: excludedList(), Incomplete: true}, err
	}

	// Segments first: they carry exclusions, and reading them before anything
	// that can fail on bad tenant data means an incomplete answer still names
	// every segment the tenant marked sensitive or probes-disabled.
	var segmentRaw []byte
	if err := tx.QueryRow(`SELECT COALESCE(jsonb_agg(jsonb_build_object('value',value,'network_type',network_type,'learned',`+learnedSegmentSQL+`,'blocked',COALESCE(metadata->>'sensitive','false')='true' OR COALESCE(metadata->>'active_probes_disabled','false')='true')),'[]') FROM network_segments WHERE tenant_id=$1 AND is_active AND segment_type='cidr'`, tenantID).Scan(&segmentRaw); err != nil {
		return incomplete(err)
	}
	var segments []struct {
		Value       string
		NetworkType string `json:"network_type"`
		Learned     bool
		Blocked     bool
	}
	if err := json.Unmarshal(segmentRaw, &segments); err != nil {
		return incomplete(err)
	}
	owned := map[netip.Prefix]bool{}
	for _, seg := range segments {
		prefix, err := netip.ParsePrefix(seg.Value)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		switch {
		case seg.Blocked:
			// Learned or declared, a segment marked sensitive or
			// active-probes-disabled is never probed automatically — the
			// conservative direction needs no statement of ownership.
			excluded[prefix] = true
		case seg.Learned || !SegmentGrantsOwnership(seg.NetworkType, false, false):
			// Not a claim of ownership.
		case probeconsent.TooBroadToClaim(prefix):
			// Nobody owns 0.0.0.0/0 or a /7 of the internet (owner decision
			// on). inventory-service now refuses to save one; a segment
			// saved before that is simply not ownership here.
		case !probeconsent.WhollyOwnedByAddressClass(prefix):
			owned[prefix] = true
		}
	}

	// The tenant's automatic-scan exclusions, read the way LoadTargetScope
	// reads them. Settings that do not parse make the whole answer
	// incomplete: sending the sensor an owned set without the exclusions the
	// tenant wrote would probe exactly what it asked us not to.
	var raw []byte
	if err := tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id=$1`, tenantID).Scan(&raw); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return incomplete(err)
	}
	if len(raw) > 0 {
		config := map[string]interface{}{}
		if err := json.Unmarshal(raw, &config); err != nil {
			return incomplete(denied("invalid scan restrictions"))
		}
		restrictions, err := autoscan.RestrictionsFromConfig(config)
		if err != nil {
			return incomplete(denied("invalid scan restrictions"))
		}
		for _, p := range restrictions.Excluded {
			excluded[p.Masked()] = true
		}
	}

	var endpointRaw []byte
	if err := tx.QueryRow(`SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_object('ip',host(ec.dest_ip),'port',ec.dest_port)),'[]')
		FROM external_connections ec
		JOIN assets a ON a.id = ec.elevated_asset_id AND a.tenant_id = ec.tenant_id
		WHERE ec.tenant_id=$1 AND ec.elevated_asset_id IS NOT NULL
		  AND a.deleted_at IS NULL AND a.asset_status = 'monitoring'`, tenantID).Scan(&endpointRaw); err != nil {
		return incomplete(err)
	}
	var endpoints []struct {
		IP   string
		Port int
	}
	if err := json.Unmarshal(endpointRaw, &endpoints); err != nil {
		return incomplete(err)
	}
	for _, e := range endpoints {
		if e.Port <= 0 || e.Port > 65535 {
			continue
		}
		out.Endpoints = append(out.Endpoints, probeconsent.EndpointString(e.IP, e.Port))
	}
	for p := range owned {
		out.Prefixes = append(out.Prefixes, p.String())
	}
	out.Excluded = excludedList()
	sort.Strings(out.Prefixes)
	sort.Strings(out.Endpoints)
	return out, nil
}
