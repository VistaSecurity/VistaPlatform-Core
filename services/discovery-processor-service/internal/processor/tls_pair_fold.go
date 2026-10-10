package processor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// One endpoint, one finding: folding the passive TLS row and the active
// enrichment row it triggered ( F11).
//
// The tenant sensor's TLS enricher (sensor/internal/enrichment/tls_enricher.go)
// probes a destination BECAUSE passive capture just saw a connection to it, and
// reports the probe as a second discovery — discovery_method
// "active_enrichment", same dest_ip/port/protocol, same source_ip (the client
// whose flow triggered it), usually in the same upload batch. Before this fold
// both rows went through classification, the approval rules and the import (or
// the external-connections upsert) separately, so inventory-service resolved
// identity and upserted crypto twice for one endpoint and relied on its crypto
// dedup to absorb the second write.
//
// THE PAIRING KEY: tenant, destination IP, destination port and protocol (the
// destinationKey the batch SNI index already uses). Within one key an active
// row is paired with exactly one passive row:
//
//   - both rows' SNI, when BOTH carry one, must be equal (the enricher records
//     none, so in practice this only refuses a pair a future producer makes
//     ambiguous);
//   - with several passive candidates, those whose source_ip equals the active
//     row's are preferred (the enricher copies the triggering flow's client);
//   - the remaining candidates must agree on source_ip and on SNI, otherwise
//     the pair is ambiguous and is REFUSED rather than guessed — both rows
//     then take the unfolded path exactly as before.
//
// Never folded: host observations, device-interrogation rows, host-inventory
// rows that name a source_asset_id, and anything whose discovery_method is not
// exactly "passive" (the passive half) or "active_enrichment" (the active half).
//
// THE MERGE RULE is the discovery-metadata envelope rule from CLAUDE.md ("The
// discovery metadata envelope: empty never wins"), applied across the two rows
// instead of across the two envelope levels: both rows are flattened first
// (flattenSensorDiscoveryEnvelope), then every key the ACTIVE row measured wins
// unless its value is empty (nil, "", 0, [] or {}), and the PASSIVE row fills
// every key the active row left empty or absent. A bool false is NOT empty —
// cert_has_sct: false is an answer and survives. Two values are pinned to the
// passive observation regardless: source_ip (the external-connections upsert
// key is the flow's client) and the row columns (hostname, timestamp,
// source_ip), with the active row filling a column only where the passive one
// is blank.
//
// The merged row keeps the PASSIVE row's id. The active row's id follows it:
// processedMarks stamps it with exactly the outcome (approval status, rule,
// asset) the merged finding received, so neither row is left in the queue and
// neither claims a different fate.

// tlsFoldFollowers maps a surviving row's id to the ids folded into it.
type tlsFoldFollowers map[uuid.UUID][]uuid.UUID

const (
	tlsFoldRoleNone = iota
	tlsFoldRolePassive
	tlsFoldRoleActive
)

type tlsFoldCandidate struct {
	d      *models.SensorDiscovery
	flat   map[string]interface{}
	role   int
	key    string
	sni    string
	source string
	paired bool
}

// foldTLSEnrichmentPairs returns the batch with every unambiguous passive +
// active_enrichment pair replaced by one merged row (in the passive row's
// position), and the ids that were folded away keyed by the row that absorbed
// them. Rows that are not part of a pair are returned unchanged, in order.
func foldTLSEnrichmentPairs(discoveries []*models.SensorDiscovery) ([]*models.SensorDiscovery, tlsFoldFollowers) {
	candidates := make([]*tlsFoldCandidate, len(discoveries))
	passivesByKey := map[string][]*tlsFoldCandidate{}
	var actives []*tlsFoldCandidate
	for i, d := range discoveries {
		c := classifyTLSFoldCandidate(d)
		candidates[i] = c
		switch c.role {
		case tlsFoldRolePassive:
			passivesByKey[c.key] = append(passivesByKey[c.key], c)
		case tlsFoldRoleActive:
			actives = append(actives, c)
		}
	}
	if len(actives) == 0 || len(passivesByKey) == 0 {
		return discoveries, nil
	}

	// passive candidate -> the active row folded into it
	partner := map[*tlsFoldCandidate]*tlsFoldCandidate{}
	for _, active := range actives {
		passive := pickPassivePartner(active, passivesByKey[active.key])
		if passive == nil {
			continue
		}
		passive.paired = true
		active.paired = true
		partner[passive] = active
	}
	if len(partner) == 0 {
		return discoveries, nil
	}

	followers := tlsFoldFollowers{}
	out := make([]*models.SensorDiscovery, 0, len(discoveries)-len(partner))
	for i, c := range candidates {
		switch {
		case c.role == tlsFoldRoleActive && c.paired:
			continue // carried by its passive partner
		case c.role == tlsFoldRolePassive && c.paired:
			active := partner[c]
			merged, err := mergeTLSPair(c, active)
			if err != nil {
				// Cannot happen for maps decoded from JSON; if it ever does,
				// leave both rows unfolded rather than lose either.
				fmt.Printf("Warning: could not fold discovery %s into %s: %v\n", active.d.ID, c.d.ID, err)
				out = append(out, discoveries[i], active.d)
				continue
			}
			followers[c.d.ID] = append(followers[c.d.ID], active.d.ID)
			out = append(out, merged)
		default:
			out = append(out, discoveries[i])
		}
	}
	return out, followers
}

// classifyTLSFoldCandidate decides whether a row can be half of a pair, and
// precomputes what the pairing needs.
func classifyTLSFoldCandidate(d *models.SensorDiscovery) *tlsFoldCandidate {
	c := &tlsFoldCandidate{d: d}
	if d == nil || len(d.Metadata) == 0 || isHostObservationDiscovery(d) || isInterrogationDiscovery(d) {
		return c
	}
	var raw map[string]interface{}
	if json.Unmarshal(d.Metadata, &raw) != nil || raw == nil {
		return c
	}
	flat := flattenSensorDiscoveryEnvelope(raw)
	if id, _ := flat["source_asset_id"].(string); strings.TrimSpace(id) != "" {
		// Host inventory / interrogation-owned: the row names the asset it
		// belongs to and is routed on that claim. Not a passive sighting.
		return c
	}
	method, _ := flat["discovery_method"].(string)
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "passive":
		c.role = tlsFoldRolePassive
	case "active_enrichment":
		c.role = tlsFoldRoleActive
	default:
		return c
	}
	c.flat = flat
	c.key = d.TenantID.String() + "|" + destinationKey(d)
	c.sni = sniHostnameFromDiscoveryMetadata(d.Metadata)
	if d.SourceIP != nil {
		c.source = strings.TrimSpace(*d.SourceIP)
	}
	return c
}

// pickPassivePartner returns the one passive row an active row folds into, or
// nil when there is none or the choice would be a guess.
func pickPassivePartner(active *tlsFoldCandidate, passives []*tlsFoldCandidate) *tlsFoldCandidate {
	var cands []*tlsFoldCandidate
	for _, p := range passives {
		if p.paired {
			continue
		}
		if p.sni != "" && active.sni != "" && p.sni != active.sni {
			continue
		}
		cands = append(cands, p)
	}
	if len(cands) > 1 && active.source != "" {
		var sameSource []*tlsFoldCandidate
		for _, p := range cands {
			if p.source == active.source {
				sameSource = append(sameSource, p)
			}
		}
		if len(sameSource) > 0 {
			cands = sameSource
		}
	}
	if len(cands) == 0 {
		return nil
	}
	// Several candidates left: fold only if they are interchangeable for every
	// attribute the merge would attribute the measurement to.
	for _, p := range cands[1:] {
		if p.source != cands[0].source || p.sni != cands[0].sni {
			return nil
		}
	}
	return cands[0]
}

// mergeTLSPair builds the single row a passive + active pair becomes.
func mergeTLSPair(passive, active *tlsFoldCandidate) (*models.SensorDiscovery, error) {
	metadata := mergeEnrichmentMetadata(passive.flat, active.flat)
	blob, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	merged := *passive.d
	merged.Metadata = blob
	if merged.Confidence < active.d.Confidence {
		merged.Confidence = active.d.Confidence
	}
	if merged.Hostname == nil || strings.TrimSpace(*merged.Hostname) == "" {
		merged.Hostname = active.d.Hostname
	}
	if merged.SourceIP == nil || strings.TrimSpace(*merged.SourceIP) == "" {
		merged.SourceIP = active.d.SourceIP
	}
	return &merged, nil
}

// mergeEnrichmentMetadata merges two FLATTENED metadata maps under the
// envelope rule: active wins unless empty, passive fills, false is a value,
// and source_ip stays the passive observation's.
func mergeEnrichmentMetadata(passive, active map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(passive)+len(active))
	for k, v := range passive {
		out[k] = v
	}
	for k, v := range active {
		if isEmptyMetadataValue(v) {
			if existing, present := out[k]; present && !isEmptyMetadataValue(existing) {
				continue
			}
		}
		out[k] = v
	}
	if src, ok := passive["source_ip"]; ok && !isEmptyMetadataValue(src) {
		out["source_ip"] = src
	}
	return out
}
