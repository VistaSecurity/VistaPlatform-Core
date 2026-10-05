package services

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The Observations review table: what each retained observation NEEDS
// from a person, and what the platform suggests doing about it.
//
// It is decided here, once, from the evidence the observation already carries,
// so the UI never re-derives it — a second copy of "is this ready to confirm"
// in TypeScript is how the bulk bar would come to offer Confirm on a row the
// server then refuses (spec D4). The same rule exists once more, as SQL, for
// filtering and counting a page the database has not handed to Go yet
// (observationNeedsSQL); TestIntegration_ObservationNeeds_SQLMatchesGo holds
// the two in lockstep over a generated matrix of inputs.

// Needs categories (the table's chips).
const (
	NeedsReadyToConfirm = "ready_to_confirm"
	NeedsLinkExisting   = "link_existing"
	NeedsReview         = "needs_review"
	NeedsNetwork        = "needs_network"
	NeedsSensor         = "needs_sensor"
	NeedsLikelyNoise    = "likely_noise"
	NeedsNone           = "none"
)

// ObservationNeedsValues is every needs value, in the order the table shows
// its chips and `sort=needs` orders rows.
var ObservationNeedsValues = []string{NeedsReadyToConfirm, NeedsLinkExisting, NeedsReview, NeedsNetwork, NeedsSensor, NeedsLikelyNoise, NeedsNone}

// Suggested actions.
const (
	SuggestConfirm       = "confirm"
	SuggestLink          = "link"
	SuggestAddNetwork    = "add_network"
	SuggestSensorOptions = "sensor_options"
	SuggestDismiss       = "dismiss"
	SuggestNone          = "none"
)

// Explanation codes: one per row of the spec's suggestion table, with the
// sensor and noise rows split by WHICH of their alternatives applied, because
// the sentence a person needs differs ("another device advertised this" is
// false for an address no collector can reach). The UI maps codes to words;
// the codes are a contract and must not be renamed.
const (
	ExplainDynamicAddressAnswered = "dynamic_address_answered"
	ExplainOwnedByAsset           = "owned_by_asset"
	ExplainOwnedBySeveralAssets   = "owned_by_several_assets"
	ExplainNetworkNotConfigured   = "network_not_configured"
	ExplainRelayedAdvertisement   = "relayed_advertisement"
	ExplainNoCollectorInNetwork   = "no_collector_in_network"
	ExplainNameOnly               = "name_only"
	ExplainNoAddressOrService     = "no_address_or_service"
	ExplainNotSeenRecently        = "not_seen_recently"
	ExplainNoSuggestion           = "no_suggestion"
	ExplainNotAwaitingReview      = "not_awaiting_review"
)

// observationStaleAfter is the "last seen more than 30 days ago" row. It is
// the same window the unresolved list and IdentitySummary already use.
const observationStaleAfter = 30 * 24 * time.Hour

// ObservationIdentifierSummary is one identifier in readable form. Value is
// for DISPLAY: a long opaque value (an SSH host key fingerprint) is shortened,
// and the full value stays in the observation's `evidence`.
type ObservationIdentifierSummary struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// ObservationOwner is an existing asset that already owns one of an
// observation's identifiers (a row of asset_identifiers with the same kind,
// value and scope). Linkable is false when the asset is deleted, archived or
// denied: the Link decision refuses those, so such an owner cannot be offered
// as a one-click answer.
type ObservationOwner struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Linkable bool      `json:"linkable"`
}

// ObservationSuggestionInput is everything the suggestion reads. The first six
// fields decide `needs` (and are mirrored in observationNeedsSQL); the names
// only shape the sentence.
type ObservationSuggestionInput struct {
	State            string
	AdmissionReasons []string
	EnrichmentReason string
	Evidence         identity.Observation
	LastSeenAt       time.Time
	// Owners are the DISTINCT existing assets owning any identifier of the
	// evidence. Confirm is refused whenever there is one (the declared
	// identity would collide with it), so ownership decides whether the
	// dynamic-address row may be offered as Confirm at all.
	Owners      []ObservationOwner
	NetworkName string
	SourceName  string
}

// ObservationSuggestion is the decided answer.
type ObservationSuggestion struct {
	Needs           string
	SuggestedAction string
	ExplanationCode string
	SuggestedReason string
	// LinkAsset is the owner a `link` suggestion points at; nil otherwise.
	LinkAsset *ObservationOwner
}

// SuggestObservation applies the spec's suggestion table ( §1). Precedence
// when several reasons are present, first match wins:
//
//  1. state other than unresolved           → none (decided or held elsewhere)
//  2. network_scope_unresolved              → needs_network
//  3. relayed advertisement, or no eligible
//     collector in the target network       → needs_sensor
//  4. dynamic address with an address AND
//     at least one endpoint                 → ready_to_confirm when no existing
//     asset owns an identifier of it; link_existing when exactly one
//     linkable asset does; needs_review when more than one does, or the
// one that does cannot be linked
//  5. name only, nothing to create from, or
//     not seen for 30 days                  → likely_noise
//  6. otherwise                             → none (no suggestion)
//
// A network is asked for before a sensor because a sensor cannot be placed on a
// network the tenant has not described, and both are asked for before Confirm
// because confirming evidence the platform could still corroborate itself
// spends the person's attention on work a sensor would do.
func SuggestObservation(in ObservationSuggestionInput, now time.Time) ObservationSuggestion {
	out := ObservationSuggestion{Needs: NeedsNone, SuggestedAction: SuggestNone, ExplanationCode: ExplainNotAwaitingReview}
	if in.State != "unresolved" {
		if in.State == "expired" {
			// Dismissal is the one decision an expired row still takes.
			out.SuggestedReason = dismissSentence(in, "")
		}
		return out
	}
	has := func(reason string) bool {
		for _, r := range in.AdmissionReasons {
			if r == reason {
				return true
			}
		}
		return false
	}
	address, endpoints := observationAddress(in.Evidence) != "", len(in.Evidence.Endpoints) > 0
	stale := !in.LastSeenAt.IsZero() && now.Sub(in.LastSeenAt) > observationStaleAfter
	set := func(needs, action, code string) ObservationSuggestion {
		return ObservationSuggestion{Needs: needs, SuggestedAction: action, ExplanationCode: code}
	}
	switch {
	case has(identity.ReasonNetworkScopeUnresolved):
		out = set(NeedsNetwork, SuggestAddNetwork, ExplainNetworkNotConfigured)
		out.SuggestedReason = dismissSentence(in, "which is not inside any configured network")
	case has("unverified_relayed_advertisement"):
		out = set(NeedsSensor, SuggestSensorOptions, ExplainRelayedAdvertisement)
		out.SuggestedReason = dismissSentence(in, "advertised by another device; nothing here saw the device itself")
	case in.EnrichmentReason == identityenrichment.ReasonNoEligibleCollector:
		out = set(NeedsSensor, SuggestSensorOptions, ExplainNoCollectorInNetwork)
		out.SuggestedReason = dismissSentence(in, "where no collector can confirm it")
	case has(identity.ReasonDynamicAddressWithoutDeviceBinding) && address && endpoints && len(in.Owners) == 1 && in.Owners[0].Linkable:
		owner := in.Owners[0]
		out = set(NeedsLinkExisting, SuggestLink, ExplainOwnedByAsset)
		out.LinkAsset = &owner
		out.SuggestedReason = "Linked from Observations: " + seenPhrase(in) + " — already belongs to " + ownerPhrase(owner) + "."
	case has(identity.ReasonDynamicAddressWithoutDeviceBinding) && address && endpoints && len(in.Owners) > 0:
		out = set(NeedsReview, SuggestNone, ExplainOwnedBySeveralAssets)
		out.SuggestedReason = dismissSentence(in, "its identifiers already belong to assets that need comparing first")
	case has(identity.ReasonDynamicAddressWithoutDeviceBinding) && address && endpoints:
		out = set(NeedsReadyToConfirm, SuggestConfirm, ExplainDynamicAddressAnswered)
		out.SuggestedReason = "Confirmed from Observations: " + seenPhrase(in) + "."
	case has(identity.ReasonNoDeviceOrAddressBinding):
		out = set(NeedsLikelyNoise, SuggestDismiss, ExplainNameOnly)
		out.SuggestedReason = dismissSentence(in, "only a name, with no address or service")
	case !address && !endpoints:
		out = set(NeedsLikelyNoise, SuggestDismiss, ExplainNoAddressOrService)
		out.SuggestedReason = dismissSentence(in, "no address or service was seen")
	case stale:
		out = set(NeedsLikelyNoise, SuggestDismiss, ExplainNotSeenRecently)
		out.SuggestedReason = dismissSentence(in, "not seen since "+in.LastSeenAt.UTC().Format("2006-01-02"))
	default:
		out = set(NeedsNone, SuggestNone, ExplainNoSuggestion)
		out.SuggestedReason = dismissSentence(in, "")
	}
	return out
}

// observationNeedsSQL is SuggestObservation's `needs` rule as a SQL CASE over
// an identity_observations row aliased `o`, for filtering, counting and sorting
// a page before it reaches Go. KEEP IT IN LOCKSTEP with SuggestObservation:
// TestIntegration_ObservationNeeds_SQLMatchesGo compares the two over a
// generated matrix and fails on the first disagreement.
//
// The endpoint test checks the JSON type before taking a length because
// jsonb_array_length raises on anything but an array, and a CASE gives no
// guarantee that a sibling AND short-circuits first.
const observationNeedsSQL = `(CASE
 WHEN o.state <> 'unresolved' THEN 'none'
 WHEN 'network_scope_unresolved' = ANY(o.admission_reasons) THEN 'needs_network'
 WHEN 'unverified_relayed_advertisement' = ANY(o.admission_reasons)
   OR o.enrichment_reason = 'no_eligible_collector_in_target_network' THEN 'needs_sensor'
 WHEN 'dynamic_address_without_device_binding' = ANY(o.admission_reasons)
   AND ` + observationHasAddressSQL + ` AND ` + observationHasEndpointSQL + ` THEN (CASE ` + observationOwnershipSQL + `
     WHEN 0 THEN 'ready_to_confirm' WHEN 1 THEN 'link_existing' ELSE 'needs_review' END)
 WHEN 'no_device_or_address_binding' = ANY(o.admission_reasons)
   OR (NOT ` + observationHasAddressSQL + ` AND NOT ` + observationHasEndpointSQL + `)
   OR o.last_seen_at < now() - interval '30 days' THEN 'likely_noise'
 ELSE 'none' END)`

// observationOwnersSQL is the DISTINCT existing assets that own an identifier
// of the observation's evidence — the same lookup DecideIdentityObservation
// refuses a Confirm on (repo.FindByIdentifier: tenant, kind, value, scope with
// NULL read as ”). Evidence is stored with normalized identifiers, so its
// values compare as they are. `linkable` mirrors what the Link decision
// accepts: not deleted, not archived or denied.
//
// The JSON type is checked before the array is expanded because
// jsonb_array_elements raises on anything but an array.
const observationOwnersSQL = `(SELECT DISTINCT ai.asset_id,
    COALESCE(NULLIF(a.display_name,''), NULLIF(a.hostname,''), '') AS name,
    (a.id IS NOT NULL AND a.deleted_at IS NULL AND a.asset_status NOT IN ('archived','denied')) AS linkable
  FROM jsonb_array_elements(CASE WHEN jsonb_typeof(o.evidence->'identifiers') = 'array' THEN o.evidence->'identifiers' ELSE '[]'::jsonb END) x
  JOIN asset_identifiers ai ON ai.tenant_id = o.tenant_id AND ai.kind = x->>'kind' AND ai.value = x->>'value'
   AND coalesce(ai.scope,'') = coalesce(x->>'scope','')
  LEFT JOIN assets a ON a.tenant_id = ai.tenant_id AND a.id = ai.asset_id)`

// observationOwnershipSQL collapses the owners to 0 (none), 1 (exactly one,
// and it can be linked) or 2 (anything else: several, or one that cannot be
// linked), matching the three outcomes of the dynamic-address branch.
const observationOwnershipSQL = `(SELECT CASE WHEN count(*) = 0 THEN 0 WHEN count(*) = 1 AND bool_and(ow.linkable) THEN 1 ELSE 2 END FROM ` + observationOwnersSQL + ` ow)`

// observationOwnersJSONSQL is the owners as a JSON array for the read path,
// which hands them to SuggestObservation.
const observationOwnersJSONSQL = `(SELECT COALESCE(jsonb_agg(jsonb_build_object('id', ow.asset_id, 'name', ow.name, 'linkable', ow.linkable) ORDER BY ow.asset_id), '[]'::jsonb) FROM ` + observationOwnersSQL + ` ow)`

const observationHasAddressSQL = `(jsonb_path_exists(o.evidence, '$.identifiers[*] ? (@.kind == "ip_address" && @.value != "")')
   OR jsonb_path_exists(o.evidence, '$.endpoints[*] ? (@.address != "")'))`

const observationHasEndpointSQL = `(COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(o.evidence->'endpoints') = 'array' THEN o.evidence->'endpoints' END), 0) > 0)`

// observationNeedsOrderSQL orders rows by needs in ObservationNeedsValues order.
const observationNeedsOrderSQL = `array_position(ARRAY['ready_to_confirm','link_existing','needs_review','needs_network','needs_sensor','likely_noise','none'], ` + observationNeedsSQL + `)`

// observationAddress is the address an observation was seen at: its
// ip_address identifier, else the first endpoint address. The SQL twin is
// observationHasAddressSQL.
func observationAddress(obs identity.Observation) string {
	for _, id := range obs.Identifiers {
		if id.Kind == identity.KindIPAddress && id.Value != "" {
			return id.Value
		}
	}
	for _, ep := range obs.Endpoints {
		if ep.Address != "" {
			return ep.Address
		}
	}
	return ""
}

// observationHostname is the observation's name, if it carries one.
func observationHostname(obs identity.Observation) string {
	if h := strings.TrimSpace(obs.Hostname); h != "" {
		return h
	}
	for _, id := range obs.Identifiers {
		if (id.Kind == identity.KindHostname || id.Kind == identity.KindFQDN) && strings.TrimSpace(id.Value) != "" {
			return strings.TrimSpace(id.Value)
		}
	}
	return ""
}

// maxSentenceServices bounds the services named in a sentence; the rest are
// counted. A reason is capped at 2000 characters by the decision endpoints and
// a sentence the person cannot read at a glance is not a suggestion.
const maxSentenceServices = 4

// servicesPhrase renders endpoints as "SSH 22 and TLS 8443".
func servicesPhrase(eps []identity.EndpointObservation) string {
	seen := map[string]bool{}
	var parts []string
	for _, ep := range eps {
		label := strings.ToUpper(strings.TrimSpace(ep.Protocol))
		if label == "" {
			label = strings.TrimSpace(ep.ServiceName)
		}
		if label == "" {
			label = strings.ToUpper(strings.TrimSpace(ep.Transport))
		}
		if label == "" || label == "NONE" {
			label = "Port"
		}
		if ep.Port > 0 {
			label += " " + strconv.Itoa(ep.Port)
		}
		if !seen[label] {
			seen[label] = true
			parts = append(parts, label)
		}
	}
	if len(parts) > maxSentenceServices {
		more := len(parts) - maxSentenceServices
		parts = append(parts[:maxSentenceServices], fmt.Sprintf("%d more", more))
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}

// clip keeps a free-text value (a hostname somebody chose) from dominating a
// sentence.
func clip(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// seenPhrase is "SSH 22 and TLS 8443 seen at 192.0.2.17 (printer) on Office
// LAN (Platform sensor)" — what, where, on which named network, from which
// named source. Never a UUID: names come resolved, and an unnamed network is
// left out rather than shown as its id.
func seenPhrase(in ObservationSuggestionInput) string {
	what := servicesPhrase(in.Evidence.Endpoints)
	if what == "" {
		what = "A device"
	}
	var b strings.Builder
	b.WriteString(what)
	b.WriteString(" seen")
	addr, host := observationAddress(in.Evidence), clip(observationHostname(in.Evidence), 80)
	switch {
	case addr != "" && host != "":
		fmt.Fprintf(&b, " at %s (%s)", addr, host)
	case addr != "":
		fmt.Fprintf(&b, " at %s", addr)
	case host != "":
		fmt.Fprintf(&b, " as %s", host)
	}
	if in.NetworkName != "" {
		fmt.Fprintf(&b, " on %s", clip(in.NetworkName, 80))
	}
	if in.SourceName != "" {
		fmt.Fprintf(&b, " (%s)", clip(in.SourceName, 80))
	}
	return b.String()
}

// ownerPhrase names the asset a link suggestion points at. An unnamed asset is
// "an existing asset", never its id.
func ownerPhrase(o ObservationOwner) string {
	if n := strings.TrimSpace(o.Name); n != "" {
		return clip(n, 80)
	}
	return "an existing asset"
}

// dismissSentence is the reason proposed for dismissing the row: what was seen,
// then why it is being let go.
func dismissSentence(in ObservationSuggestionInput, why string) string {
	s := "Dismissed from Observations: " + seenPhrase(in)
	if why != "" {
		s += " — " + why
	}
	return s + "."
}

// identifierLabels names each identifier kind in plain words.
var identifierLabels = map[identity.Kind]string{
	identity.KindHostname:              "Hostname",
	identity.KindFQDN:                  "DNS name",
	identity.KindIPAddress:             "IP address",
	identity.KindMACAddress:            "MAC address",
	identity.KindSSHHostKeyFingerprint: "SSH host key",
	identity.KindSerialNumber:          "Serial number",
	identity.KindAgentID:               "Agent",
	identity.KindSensorID:              "Sensor",
	identity.KindCloudResourceID:       "Cloud resource",
	identity.KindCMDBSysID:             "CMDB record",
	identity.KindDeclarationID:         "Operator declaration",
	identity.KindName:                  "Name",
}

// identifierOrder puts what a person recognises a device by first.
var identifierOrder = map[identity.Kind]int{
	identity.KindHostname: 0, identity.KindFQDN: 1, identity.KindIPAddress: 2, identity.KindMACAddress: 3,
	identity.KindSSHHostKeyFingerprint: 4, identity.KindSerialNumber: 5,
}

// displayLimit is the length above which an identifier value is shortened for
// display. An IPv6 address fits; a SHA256 host key fingerprint does not.
const displayLimit = 40

func shortenForDisplay(v string) string {
	r := []rune(v)
	if len(r) <= displayLimit {
		return v
	}
	return string(r[:20]) + "…" + string(r[len(r)-8:])
}

// summarizeObservation lists the observation's identifiers in readable form.
func summarizeObservation(obs identity.Observation) []ObservationIdentifierSummary {
	out := []ObservationIdentifierSummary{}
	seen := map[string]bool{}
	add := func(kind identity.Kind, value string) {
		value = strings.TrimSpace(value)
		key := string(kind) + "\x00" + strings.ToLower(value)
		if value == "" || seen[key] {
			return
		}
		seen[key] = true
		label, ok := identifierLabels[kind]
		if !ok {
			label = strings.ToUpper(string(kind[:1])) + strings.ReplaceAll(string(kind[1:]), "_", " ")
		}
		out = append(out, ObservationIdentifierSummary{Kind: string(kind), Label: label, Value: shortenForDisplay(value)})
	}
	if h := strings.TrimSpace(obs.Hostname); h != "" {
		kind := identity.KindHostname
		if strings.Contains(strings.TrimSuffix(h, "."), ".") {
			kind = identity.KindFQDN
		}
		add(kind, h)
	}
	for _, id := range obs.Identifiers {
		add(id.Kind, id.Value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi, ok := identifierOrder[identity.Kind(out[i].Kind)]
		if !ok {
			oi = len(identifierOrder)
		}
		oj, ok := identifierOrder[identity.Kind(out[j].Kind)]
		if !ok {
			oj = len(identifierOrder)
		}
		return oi < oj
	})
	return out
}

// sourceSensorRefSQL matches a source_ref that names one of the tenant's own
// collectors — `sensor:<id>`, `scan:<id>`, `agent:<id>`, and the qualified
// forms `sensor:pcap:<id>` / `sensor:identity-dns:<id>` — capturing the
// trailing UUID for the sensors join in observationReadFrom.
const sourceSensorRefSQL = `'^(?:sensor|scan|agent)(?::[a-z-]+)?:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'`

// observationSourceName labels where an observation came from: the collector's
// configured name when the ref names one of this tenant's collectors, else a
// fixed label for the kind of source. It never returns the raw ref, which
// carries UUIDs and internal spellings.
func observationSourceName(sourceKind, sourceRef, sensorName string) string {
	if strings.TrimSpace(sensorName) != "" {
		return strings.TrimSpace(sensorName)
	}
	ref := strings.ToLower(strings.TrimSpace(sourceRef))
	head, rest, _ := strings.Cut(ref, ":")
	switch head {
	case "sensor":
		switch {
		case rest == "pcap" || strings.HasPrefix(rest, "pcap:"):
			return "Packet capture"
		case strings.HasPrefix(rest, "identity-"):
			return "Identity check"
		}
		return "Sensor"
	case "scan":
		return "Discovery scan"
	case "agent":
		return "Device agent"
	case "cloud":
		if rest != "" {
			return "Cloud discovery (" + strings.ToUpper(rest) + ")"
		}
		return "Cloud discovery"
	case "interrogation":
		return "Device interrogation"
	case "cmdb":
		return "CMDB import"
	case "netbox":
		return "NetBox import"
	case identity.SpreadsheetImportSourceRef:
		return "Spreadsheet import"
	case "operator":
		return "Operator"
	case "manual":
		return "Manual entry"
	case "approvals":
		return "Approvals"
	}
	switch identity.SourceKind(sourceKind) {
	case identity.SourceImported:
		return "Imported source"
	case identity.SourceDeclared:
		return "Declared source"
	case identity.SourceInferred:
		return "Inferred"
	default:
		return "Collector"
	}
}

// annotateObservation fills the review fields of one read row. `now` is passed
// in so a page is judged against one instant.
func annotateObservation(o *IdentityObservation, sensorName string, owners []ObservationOwner, now time.Time) {
	var evidence identity.Observation
	// Evidence that will not parse is a storage fault; it is judged as empty
	// evidence (nothing to confirm from) rather than failing the page.
	_ = json.Unmarshal(o.Evidence, &evidence)
	o.SourceName = observationSourceName(o.SourceKind, o.SourceRef, sensorName)
	network := ""
	if o.NetworkName != nil {
		network = *o.NetworkName
	}
	s := SuggestObservation(ObservationSuggestionInput{
		State: o.State, AdmissionReasons: o.AdmissionReasons, EnrichmentReason: o.EnrichmentReason,
		Evidence: evidence, LastSeenAt: o.LastSeenAt, Owners: owners, NetworkName: network, SourceName: o.SourceName,
	}, now)
	o.Needs, o.SuggestedAction, o.ExplanationCode, o.SuggestedReason = s.Needs, s.SuggestedAction, s.ExplanationCode, s.SuggestedReason
	o.LinkAsset = s.LinkAsset
	o.Summary = summarizeObservation(evidence)
}
