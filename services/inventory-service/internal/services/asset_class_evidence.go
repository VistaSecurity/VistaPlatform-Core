package services

// Accumulated class evidence: what an EXISTING asset has told us about itself
// across every observation, not just the one in hand.
//
// # Why this exists
//
// Each intake builds its class evidence from the observation it is holding
// (hostObservationClassEvidence, findingClassEvidence). For a NEW asset that is
// everything there is. For an existing one it is a fragment: a passive sensor
// hears a host's MAC in an ARP frame at 20:18 and its mDNS advertisement — with
// no MAC, because the advertisement was relayed — at 20:21. Classified one
// frame at a time, a rule that needs the MAC's manufacturer never sees the
// advertisement's evidence and vice versa, and the asset stays `unknown_host`
// for ever although the inventory holds everything a rule needs.
//
// So for an asset the engine MATCHED, the evidence the classifier reads is the
// observation's own, merged with what is stored against the asset:
//
//   - every `mac_address` identifier it holds;
//   - `hw.vendor` and `hw.model`, but only from a DEVICE-IDENTITY source (see
//     [deviceIdentityFactSQL]);
//   - the union of every stored `net.mdns_services` value with the
//     observation's services;
//   - the LLDP / CDP capability bits from the stored host-observation
//     attributes, unioned with the observation's;
//   - the DHCP option 60 vendor class from the stored host-observation
//     attributes, when the observation carries none of its own.
//
// # Why the stored vendor is filtered
//
// classify.ClassifyInput.Vendor is an ANSWER, not a hypothesis: the engine
// returns it as-is and it guards `model` rules, which fire only for the vendor
// they name. The engine resolves a MAC to its manufacturer itself, through the
// IEEE registry (shared/classify matchMACs), and the asset's MACs are already in
// the merged input. Feeding the registry's own `catalog:oui` fact back in as
// `Vendor` would be the engine reading its own answer as somebody else's
// testimony; feeding a passive sensor's row in would do the same with an older
// sensor's private table. Only a vendor the DEVICE or a system of record named
// — a device agent, an interrogation, a connector, an import — is evidence
// the MACs do not already carry. `hw.model` follows the same rule, so a vendor
// and a model that guard each other come from the same kind of source.
//
// A stored device-identity vendor or model WINS over the observation's: the
// observation's vendor on the passive path is the registry's answer for its MAC
// (resolveHostObservationVendor), which applyRegistryVendorFact already ranks
// below a device-identity row.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// classEvidenceTx is the slice of a transaction the evidence reader needs. Both
// the ingest path's *sqlx.Tx and the floor sweep's *sql.Tx satisfy it.
type classEvidenceTx interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// deviceIdentityFactSQL selects the fact rows a device or a system of record
// wrote — the provenance [accumulatedClassEvidence] accepts for hw.vendor and
// hw.model. Not the OUI registry's row (`catalog:oui`) nor any other catalogue
// enrichment (`catalog:*`), not a passive sensor's (`sensor`, `sensor:*`),
// and not a model's inference: none of those is the device naming itself.
//
// The same partition applyRegistryVendorFact draws (oui_vendor.go), with the
// catalogue and inference exclusions added because this reader feeds a
// CLASSIFIER, where a catalogue's or a model's answer read back as input would
// be circular.
const deviceIdentityFactSQL = `f.source_ref NOT LIKE 'catalog:%'
	AND NOT (f.source_ref = 'sensor' OR f.source_ref LIKE 'sensor:%')
	AND f.source_kind <> 'inferred'`

// storedClassEvidenceSQL reads everything [accumulatedClassEvidence] merges, in
// one round trip, for one asset. Each sub-select answers with an empty value
// rather than NULL so the scan never has to special-case a missing piece.
//
// The device-identity vendor and model prefer a `measured` row over an
// `imported` one (ADR-0002 D4's ladder: the device's own word over a system of
// record's), then the most recent.
const storedClassEvidenceSQL = `
	SELECT
	  COALESCE((SELECT array_agg(DISTINCT i.value ORDER BY i.value)
	              FROM asset_identifiers i
	             WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.kind = 'mac_address'), '{}'::text[]),
	  COALESCE((SELECT f.value #>> '{}' FROM asset_facts f
	             WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.key = $3
	               AND jsonb_typeof(f.value) = 'string' AND ` + deviceIdentityFactSQL + `
	             ORDER BY (f.source_kind = 'measured') DESC, f.observed_at DESC
	             LIMIT 1), ''),
	  COALESCE((SELECT f.value #>> '{}' FROM asset_facts f
	             WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.key = $4
	               AND jsonb_typeof(f.value) = 'string' AND ` + deviceIdentityFactSQL + `
	             ORDER BY (f.source_kind = 'measured') DESC, f.observed_at DESC
	             LIMIT 1), ''),
	  COALESCE((SELECT array_agg(DISTINCT s.svc ORDER BY s.svc)
	              FROM asset_facts f,
	                   LATERAL jsonb_array_elements_text(
	                     CASE WHEN jsonb_typeof(f.value) = 'array' THEN f.value ELSE '[]'::jsonb END) AS s(svc)
	             WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.key = $5), '{}'::text[]),
	  COALESCE((SELECT a.metadata -> 'host_observation_attributes'
	              FROM assets a
	             WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL), 'null'::jsonb)`

// storedClassEvidence reads what the asset has accumulated, as class evidence.
// An asset that is not there reads as empty evidence, not an error: the
// classifier then answers from the observation alone, which is what it did
// before this existed.
func storedClassEvidence(ctx context.Context, tx classEvidenceTx, tenantID, assetID uuid.UUID) (classEvidence, error) {
	var (
		macs, services []string
		vendor, model  string
		attrsJSON      []byte
	)
	err := tx.QueryRowContext(ctx, storedClassEvidenceSQL,
		tenantID, assetID, facts.KeyHWVendor, facts.KeyHWModel, facts.KeyNetMdnsServices).
		Scan(pq.Array(&macs), &vendor, &model, pq.Array(&services), &attrsJSON)
	if err != nil {
		return classEvidence{}, fmt.Errorf("read the asset's accumulated class evidence: %w", err)
	}
	ev := classEvidence{
		MACs:         macs,
		Vendor:       strings.TrimSpace(vendor),
		Model:        strings.TrimSpace(model),
		MDNSServices: services,
	}
	var attrs map[string]any
	if len(attrsJSON) > 0 && json.Unmarshal(attrsJSON, &attrs) == nil {
		ev.LLDPCapabilities = attributeStrings(attrs, "lldp_capabilities")
		ev.CDPCapabilities = attributeStrings(attrs, "cdp_capabilities")
		ev.DHCPVendorClass = attributeString(attrs, "dhcp_vendor_class")
	}
	return ev, nil
}

// accumulatedClassEvidence is the evidence for an EXISTING asset: the current
// observation's, merged with everything stored against the asset.
//
// It MUST run on the engine's transaction, after this observation's own
// identifiers, facts and metadata are written, so it sees them as stored
// evidence too (the union makes that harmless when it also sees them in
// `current`). See applyHostObservationContext for where that point is.
func accumulatedClassEvidence(ctx context.Context, tx classEvidenceTx, tenantID, assetID uuid.UUID, current classEvidence) (classEvidence, error) {
	stored, err := storedClassEvidence(ctx, tx, tenantID, assetID)
	if err != nil {
		return classEvidence{}, err
	}
	return mergeClassEvidence(current, stored), nil
}

// mergeClassEvidence unions the list-shaped evidence and lets a stored
// device-identity vendor/model outrank the observation's (see the file doc for
// why), and fills the DHCP vendor class from the stored attributes only when
// the observation has none. Everything else — banners, ports, sysObjectID,
// platform, OS — is only ever the observation's: nothing stores it in a shape
// this could read back.
//
// Pure, so the union itself is unit-tested without a database.
func mergeClassEvidence(current, stored classEvidence) classEvidence {
	out := current
	out.MACs = unionFolded(current.MACs, stored.MACs)
	out.MDNSServices = unionFolded(current.MDNSServices, stored.MDNSServices)
	out.LLDPCapabilities = unionFolded(current.LLDPCapabilities, stored.LLDPCapabilities)
	out.CDPCapabilities = unionFolded(current.CDPCapabilities, stored.CDPCapabilities)
	if v := strings.TrimSpace(stored.Vendor); v != "" {
		out.Vendor = v
	}
	if m := strings.TrimSpace(stored.Model); m != "" {
		out.Model = m
	}
	// The option 60 identifier the CURRENT observation carries wins: it is what
	// the client says now. The stored one stands in only when this frame
	// carries none (an ARP or mDNS sighting of a host whose last DHCP exchange
	// is what named it).
	if strings.TrimSpace(out.DHCPVendorClass) == "" {
		out.DHCPVendorClass = strings.TrimSpace(stored.DHCPVendorClass)
	}
	return out
}

// unionFolded is the sorted union of two string lists, deduplicated
// case-insensitively (a MAC spelled upper- and lower-case is one MAC, an mDNS
// type is case-insensitive by protocol) and keeping the first spelling seen.
// Nil when both are empty, so an absent list stays absent.
func unionFolded(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{a, b} {
		for _, v := range list {
			v = strings.TrimSpace(v)
			k := strings.ToLower(v)
			if v == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
