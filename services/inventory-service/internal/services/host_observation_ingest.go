package services

// The host-observation consumer (asset-inventory workstream 2.5, consumer half).
//
// A host observation is a passive statement that a device exists on a segment,
// with whatever identity the frame carried: a MAC, the addresses bound to it,
// the names it answers to, the manufacturer its OUI is registered to, and — for
// a switch or a phone that advertises itself — that device's own name and model.
// The producer half (sensor + pcap-processor, via shared/hostobs) has been
// emitting them since; discovery-processor held them at this boundary
// until this file existed.
//
// What makes it a separate builder rather than a branch inside
// discoveryObservation: almost nothing a crypto finding carries is present here.
// There is no port, no protocol version, no cipher suite, no endpoint, and
// often no address at all. What there IS instead — a MAC that identifies on its
// own, a set of names the host answered to, a vendor from the OUI table — has no
// equivalent on the crypto path. Threading both through one builder would mean a
// function whose every other line asks which kind it is holding.
//
// # The three things this must not do
//
// Each of these is why the rows were held back rather than let through, and each
// has a test that fails if it comes back.
//
//  1. **No resolver, ever.** The names in the payload ARE the measurement —
//     what the host called itself over DHCP, mDNS or NetBIOS. A reverse lookup
//     is a different claim from a different source, and the names are LAN-only:
//     resolving them sends the customer's internal host names to whatever
//     resolver the pod is configured with, from a feature whose whole premise
//     (and the reason it is on by default for air-gapped profiles) is that it
//     sends nothing onto the wire.
//     TestIntegration_HostObservation_IngestNeverResolves is the guard.
//  2. **Never external_connections.** That table records a CONNECTION between
//     two endpoints with a protocol and a cipher. A host observation has no
//     flow, no far end and no cryptography. An observation with no address
//     carries the documented dest_ip of 0.0.0.0, which is not RFC 1918, so the
//     ownership classifier called it `third_party` and the ingest wrote it
//     there — a row for a connection that never happened.
//  3. **Never a guessed class.** `_ipp._tcp` means printer and LLDP
//     `bridge+router` means a device that both bridges and routes, but those are
//     classification RULES and they live in a curated table (ADR-0004 D6), not
//     in a switch statement here. Workstream 2.10b wired that table in: the
//     evidence goes to shared/classify, a class it decides is recorded with
//     `class_source_kind: rule` and the id of the rule that argued it, and a
//     class it does NOT decide — including the case where two rules disagree —
//     leaves the asset `unknown_host`, coarse and true, which is the same choice
//     the PQC classifier's `unclassified` bucket makes.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// KindHostObservation is the IngestFinding.Kind marker for a passive
// host-presence row. It matches discovery-processor's converter constant and
// shared/approval's rule vocabulary; TestHostObservationKindSpellingIsShared
// pins the three together.
const KindHostObservation = "host_observation"

// hostObservationOwnership is the network ownership a passively observed host
// is recorded with.
//
// `unknown` — an address we have not placed in a registered segment — rather
// than `internal`, because that is exactly what we know. It is emphatically not
// `third_party`: that value means "a public endpoint something here connected
// OUT to", which is a statement about a flow, and it is the value the ordinary
// classifier returns for an observation whose dest_ip is 0.0.0.0 (not RFC 1918)
// or whose address is public but unregistered. Both are the classifier
// answering a question nobody asked it — a device on a segment we are watching
// is not a third party at any address.
//
// discovery-processor applies the same override before evaluating auto-approval
// (third_party can never auto-approve), so the two services agree.
const hostObservationOwnership = identity.OwnershipUnknown

// hostObservationPayload decodes the observation out of a finding's raw data.
//
// The payload is the `host_observation` key, put there by discovery-processor's
// converter exactly as shared/hostobs emitted it. It is round-tripped through
// JSON rather than type-asserted field by field because the typed struct is the
// contract: a field the producer renames stops arriving, loudly, instead of
// being read as an empty interface value.
func hostObservationPayload(f IngestFinding) (*hostobs.HostObservation, bool) {
	if f.RawData == nil {
		return nil, false
	}
	raw, ok := f.RawData["host_observation"]
	if !ok || raw == nil {
		return nil, false
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var obs hostobs.HostObservation
	if err := json.Unmarshal(blob, &obs); err != nil {
		return nil, false
	}
	return &obs, true
}

// isHostObservation reports whether a finding is a passive host-presence row.
//
// The KIND is the only thing consulted. The payload's presence is deliberately
// NOT part of the test: a finding marked `host_observation` whose payload is
// missing or unreadable must be REFUSED, not quietly re-routed onto the crypto
// path where every one of the three hazards above is waiting. "We could not read
// it" and "it is a crypto finding" are different answers.
func isHostObservation(f IngestFinding) bool {
	return f.Kind == KindHostObservation
}

// hostObservationObservation builds the identification-engine observation for a
// passively observed host.
//
// Identifier kinds are ADR-0002 D3's, mapped from the payload as the wire
// contract's consumer-obligations table says:
//
//	mac          → mac_address   (unscoped: a MAC is globally unique)
//	fqdns[]      → fqdn          (unscoped: a qualified name is globally unique)
//	hostnames[]  → hostname      (scoped by segment)
//	addresses[]  → ip_address    (scoped by ITS OWN segment)
//
// A MAC ALONE IS ENOUGH. That is the case this whole path exists for: an ARP
// frame from a device that answers no name and has not been given an address
// still says "this thing is here, and here is its hardware address", and
// `unknown_host` lists mac_address second in its identifier precedence so the
// engine can match on it. An observation carrying NOTHING attachable is still
// refused — errNoIdentifiers — because an asset nothing can ever match again
// becomes a new asset on every coalescing window.
func (s *AssetService) hostObservationObservation(tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) (identity.Observation, error) {
	obs := identity.Observation{
		TenantID:   tenantID.String(),
		Source:     hostObservationSource(f),
		ObservedAt: hostObservationTime(f, ho),
		Confidence: hostObservationConfidence(f, ho),
		Network: identity.Network{
			Ownership: hostObservationOwnership,
			Type:      findingNetworkType(f),
		},
		// Coarse and true, and the FLOOR rather than the answer. Workstream
		// 2.10b hands this observation to the curated rule table before it is
		// resolved (see ingestHostObservation); when the rules decide a class
		// this is replaced, with `class_source_kind: rule` and a
		// `class_source_ref` naming the row. When they do not — or when they
		// contradict each other — it stands, which is the same honesty as the
		// PQC classifier's `unclassified` bucket.
		ClassHint: assetclass.KeyUnknownHost,
	}

	// The scope weak identifiers live in. Addresses are scoped individually
	// below — a host with an address in two segments is a real thing, and
	// scoping both to whichever one happened to be first would make one of them
	// identify in a segment it is not in.
	primaryAddr := hostObservationPrimaryAddress(ho)
	bestName := hostObservationBestName(ho)
	nameScope, nameScopeDynamic := s.observationScope(tenantID, primaryAddr, bestName)
	obs.Network.SegmentID = nameScope
	dynamic := map[string]bool{}
	if nameScopeDynamic {
		dynamic[nameScope] = true
	}

	if mac := strings.TrimSpace(ho.MAC); mac != "" {
		if ho.MACLocallyAdministered {
			// The U/L bit is set: a randomised iOS/Android Wi-Fi address, a
			// virtual NIC, or a spoofed one. It is not a stable key — the device
			// rotates it — and attaching it would create a fresh asset on every
			// rotation, each holding a MAC that will never be seen again.
			//
			// It is dropped as an IDENTIFIER rather than attached weakly,
			// because identifier confidence does not affect whether a kind votes
			// (Engine.kindVotes reads scope, not confidence), so "attach it with
			// low confidence" would be indistinguishable from attaching it. The
			// observation is then identified by its names and addresses if it
			// carries any, and refused if it does not — which is the honest
			// outcome for a frame whose only identity is a number that changes.
			//
			// The value is still RECORDED, as an attribute, so the row is
			// explicable to a human looking at why no asset appeared.
			log.Printf("[AssetService] host observation %s: MAC %s is locally administered; not used as an identifier (it rotates)",
				hostObservationLabel(ho), mac)
		} else {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindMACAddress, Value: mac, Confidence: 1,
			})
		}
	}

	// An FQDN is globally unique and needs no scope; a short name identifies
	// only within one. The producer has already filed each name under the right
	// heading (shared/hostobs addName), so this does not re-derive it — and it
	// must not: "an IP is never a hostname" is enforced at the source, where a
	// name that parses as an address never becomes a name at all.
	for _, fqdn := range ho.FQDNs {
		if v := strings.TrimSpace(fqdn); v != "" && !isIPLiteral(v) {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindFQDN, Value: v, Confidence: 1,
			})
		}
	}
	for _, name := range ho.Hostnames {
		if v := strings.TrimSpace(name); v != "" && !isIPLiteral(v) {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindHostname, Value: v, Scope: nameScope, Confidence: 1,
			})
		}
	}

	for _, addr := range ho.Addresses {
		if !addr.IsValid() || addr.IsUnspecified() {
			// 0.0.0.0 is the `dest_ip NOT NULL` column compromise, not an
			// address. shared/hostobs already refuses to record it, so this is
			// belt and braces against a hand-built payload.
			continue
		}
		v := addr.String()
		scope, scopeDynamic := s.observationScope(tenantID, &v, nil)
		if scopeDynamic {
			// An address handed out by DHCP is today's lease and tomorrow's
			// other host. The identifier is still RECORDED — it is true, and it
			// is what the asset's primary_address is taken from — but naming the
			// scope here is what stops it DECIDING a match (Engine.kindVotes).
			dynamic[scope] = true
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindIPAddress, Value: v, Scope: scope, Confidence: 1,
		})
	}
	if len(dynamic) > 0 {
		obs.DynamicScopes = dynamic
	}

	// Display name and hostname are context, not identity: the authoritative
	// list is Identifiers. A host with no name at all displays as its address,
	// and one with neither displays as its MAC — which is the only thing we were
	// told about it, and better than a blank row in Approvals.
	if bestName != nil {
		obs.Hostname = strings.ToLower(*bestName)
		obs.DisplayName = obs.Hostname
	} else if primaryAddr != nil {
		obs.DisplayName = *primaryAddr
	} else if ho.MAC != "" {
		obs.DisplayName = ho.MAC
	}

	// NO ENDPOINTS. A passive frame proves an address is bound to this host,
	// which the ip_address identifier already records and which the engine turns
	// into the asset's primary_address. An asset_endpoints row is a claim about a
	// reachable FACE — an address/port/transport something could connect to —
	// and nothing connected to anything here. `port = 0` in the stored row means
	// "not an endpoint", and this is what honouring that looks like.

	clean, rejected := obs.Sanitize()
	for _, r := range rejected {
		// One malformed identifier must not lose the whole observation, but the
		// reject is logged rather than dropped.
		log.Printf("[AssetService] host observation %s: dropped a %s identifier: %v",
			hostObservationLabel(ho), r.Identifier.Kind, r.Err)
	}
	if len(clean.Identifiers) == 0 {
		return identity.Observation{}, fmt.Errorf("%w: host observation %s", errNoIdentifiers, hostObservationLabel(ho))
	}
	return clean, nil
}

// isIPLiteral reports whether a name is really an address written down.
//
// AN IP IS NEVER A HOSTNAME (ADR-0002 D3). A name identifier holding "10.0.0.5"
// would be matched against other NAMES, never against the ip_address identifier
// for the same value — so one host reached by both would become two assets, and
// the address-in-a-name-slot would be scoped as a hostname and vote in a dynamic
// segment where the real ip_address identifier is forbidden to.
//
// shared/hostobs will not produce one (its names come from DNS/NetBIOS name
// fields), so this is a second lock on a door that is already shut. It costs a
// parse per name and removes the possibility of a hand-built or future payload
// walking through.
func isIPLiteral(name string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(name))
	return err == nil
}

// hostObservationPrimaryAddress returns the first real address, or nil when the
// observation carries none — which is a normal and expected case (an LLDP frame
// with only a chassis MAC, an ARP probe from a host that has not been given an
// address yet).
func hostObservationPrimaryAddress(ho *hostobs.HostObservation) *string {
	for _, a := range ho.Addresses {
		if a.IsValid() && !a.IsUnspecified() {
			v := a.String()
			return &v
		}
	}
	return nil
}

// hostObservationBestName picks the most specific name, preferring a qualified
// one: it is the one a CMDB can join on. Nil when the host answered to none.
func hostObservationBestName(ho *hostobs.HostObservation) *string {
	for _, n := range ho.FQDNs {
		if v := strings.TrimSpace(n); v != "" {
			return &v
		}
	}
	for _, n := range ho.Hostnames {
		if v := strings.TrimSpace(n); v != "" {
			return &v
		}
	}
	return nil
}

// hostObservationSource attributes the observation to the capture that made it.
//
// Mode is always PASSIVE: every decoder behind a host observation reads frames
// that were going to be on the wire anyway. The ref distinguishes the standalone
// sensor from the platform's own capture, because "which sensor told us this" is
// the question an operator asks of a surprising asset, and because the two are
// different fact producers (shared/facts `sensor` vs `platform-sensor`).
func hostObservationSource(f IngestFinding) identity.Source {
	ref := "sensor"
	if hostObservationIsPlatformCapture(f) {
		ref = "sensor:pcap"
	}
	if id := strings.TrimSpace(derefString(f.SourceSensorID)); id != "" {
		ref += ":" + id
	}
	return identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: identity.ModePassive}
}

// hostObservationIsPlatformCapture reports whether the row came from the
// platform's own capture (an uploaded PCAP, processed in-cluster) rather than
// from a sensor on the customer's network.
//
// Read from `discovery_method`, which the two producers write differently and
// deliberately: the sensor writes `passive_host_observation`, pcap-processor
// writes `pcap_upload`.
func hostObservationIsPlatformCapture(f IngestFinding) bool {
	switch strings.ToLower(rawDataString(f.RawData, "discovery_method")) {
	case "pcap_upload", "pcap":
		return true
	}
	return false
}

// hostObservationFactProducer is the shared/facts producer key the observation's
// facts are written under.
//
// It must be one the registry lists for every key in the payload, or
// UpsertFacts refuses the write — which is the correct failure (it means two
// subsystems disagree about who owns a fact) and is why this is derived rather
// than hard-coded to one value.
func hostObservationFactProducer(f IngestFinding) string {
	if hostObservationIsPlatformCapture(f) {
		return "platform-sensor"
	}
	return "sensor"
}

// hostObservationTime is when the host was seen.
//
// The payload's own `observed_at` wins: it is the capture timestamp of the
// latest frame that contributed, which is the measurement. The finding's
// envelope timestamp is the fallback, and a zero time is left zero so the engine
// stamps its own clock rather than this inventing one.
func hostObservationTime(f IngestFinding, ho *hostobs.HostObservation) time.Time {
	if !ho.ObservedAt.IsZero() {
		return ho.ObservedAt.UTC()
	}
	return findingObservedAt(f)
}

// hostObservationConfidence is how directly the subject stated its own identity.
//
// The producer already graded it — shared/hostobs.Confidence, the one ladder the
// sensor and pcap-processor both use — and the value travelled here on the row.
// Reading it back rather than re-deriving is the point: a second ladder here
// would be a second opinion about one measurement, and the two would drift the
// way the pcap path's flat 0.85 drifted from the sensor's grading.
//
// Recomputing from the payload is the fallback for a row that carries no
// confidence at all (zero, which on this scale means NOT ASSESSED). That is not
// a second opinion — it is the same function, applied to the same observation,
// one step later.
func hostObservationConfidence(f IngestFinding, ho *hostobs.HostObservation) float64 {
	if c := findingConfidence(f); c > 0 {
		return c
	}
	return hostobs.Confidence(ho)
}

// hostObservationLabel renders an observation for a log line, most specific
// identity first.
func hostObservationLabel(ho *hostobs.HostObservation) string {
	if ho == nil {
		return "(nil)"
	}
	if n := hostObservationBestName(ho); n != nil {
		return *n
	}
	if ho.MAC != "" {
		return ho.MAC
	}
	if a := hostObservationPrimaryAddress(ho); a != nil {
		return *a
	}
	return "(no identity)"
}

// hostObservationFacts projects the payload's registered-key map onto the rows
// asset_facts stores.
//
// The map is written AS GIVEN. shared/hostobs already restricted it to keys the
// registry lists the sensor producers for (hw.vendor, hw.model,
// net.mdns_services), UpsertFacts re-checks both the key and the producer, and
// re-deriving anything here would be a second opinion about a measurement
// somebody else made.
//
// # What is deliberately not written
//
//   - **net.neighbors.** There is none in the payload and there never will be. A
//     captured LLDP or CDP frame proves the ADVERTISER exists; it does not
//     establish that the advertiser is attached to the sensor's host, because a
//     sensor is normally fed by a mirror or SPAN port and the frame arrived by
//     being COPIED there. Synthesising one from `capture_interface` or an
//     `lldp_port_id` attribute would attach a fabricated edge to the sensor's own
//     asset, and mirror placement makes that the common case rather than the rare
//     one.
//   - **net.interfaces.** For the same reason plus two more. `capture_interface`
//     names the SENSOR's interface, not the observed host's — writing it as the
//     subject's interface list would attribute one machine's NIC to another. An
//     `lldp_port_id` is the advertiser's own port, but it is ONE port, and
//     net.interfaces is documented as "every network interface the device has":
//     a one-element list built from the single port that happened to send a frame
//     is a claim about completeness that nothing measured. And the registry does
//     not list `sensor` as a producer for the key at all, so the write would be
//     refused — correctly, as the registry saying the same thing.
//   - **attributes.** Decoder-specific and deliberately unregistered; the wire
//     contract calls them evidence, not statements. They travel in the asset's
//     metadata (see hostObservationMetadata) where a human and a future
//     classifier can read them, and not into asset_facts, which is the contract
//     for what the platform stores AS A FACT.
func hostObservationFacts(ho *hostobs.HostObservation, source identity.Source, observedAt time.Time, confidence float64) []pgidentity.Fact {
	if len(ho.Facts) == 0 {
		return nil
	}
	out := make([]pgidentity.Fact, 0, len(ho.Facts))
	for key, value := range ho.Facts {
		out = append(out, pgidentity.Fact{
			Key:   key,
			Value: value,
			// MEASURED, not inferred: a frame stated this. An inferred fact
			// would owe a model id and a confidence (ADR-0005 D2), and there is
			// no model here — the OUI table is a lookup, not a judgement.
			SourceKind: identity.SourceMeasured,
			SourceRef:  source.Ref,
			Confidence: confidence,
			ObservedAt: observedAt,
		})
	}
	return out
}

// hostObservationMetadata is the asset-level record of where this came from and
// what the frames carried that is not a fact.
//
// `attributes` lands here rather than in asset_facts on purpose — see
// hostObservationFacts. The locally-administered MAC lands here too: it is not
// an identifier (it rotates) but dropping it silently would leave an asset in
// Approvals with no explanation of what was actually seen.
func hostObservationMetadata(f IngestFinding, ho *hostobs.HostObservation) models.JSONB {
	out := discoverySourceMetadata(f)
	out["discovery_kind"] = KindHostObservation
	if len(ho.Sources) > 0 {
		out["host_observation_sources"] = ho.Sources
	}
	if len(ho.Attributes) > 0 {
		out["host_observation_attributes"] = ho.Attributes
	}
	if ho.MAC != "" && ho.MACLocallyAdministered {
		out["host_observation_local_mac"] = ho.MAC
	}
	return out
}

// ingestHostObservation turns one host observation into an asset, or explains
// why it did not.
//
// The whole unit — the asset, its identifiers, its facts, its context and its
// status — lands in ONE transaction, the engine's. One observation is one fact
// about the world; splitting it would leave an asset whose history says it was
// created and whose facts say nothing was measured, and no later run repairs
// that because the next observation MATCHES the asset that exists and never
// takes the create path again.
func (s *AssetService) ingestHostObservation(ctx context.Context, tenantID uuid.UUID, f IngestFinding, assetStatus string) (identity.Resolution, error) {
	ho, ok := hostObservationPayload(f)
	if !ok {
		return identity.Resolution{}, fmt.Errorf("finding is marked %s but carries no readable host_observation payload", KindHostObservation)
	}

	obs, err := s.hostObservationObservation(tenantID, f, ho)
	if err != nil {
		return identity.Resolution{}, err
	}

	// The rules, over what the frames actually carried (workstream 2.10b). This
	// is the path row 7 of the 2.5 note was waiting on: the OUI vendor, the
	// stated model, the mDNS service types and the LLDP/CDP capability bits were
	// all already being decoded and stored, and none of them could reach a class
	// because there was nowhere honest to record one. `class_source_kind: rule`
	// is that place.
	classProp := s.applyClassProposal(ctx, &obs, hostObservationClassEvidence(ho))

	facts := hostObservationFacts(ho, obs.Source, obs.ObservedAt, obs.Confidence)
	ctxInput := models.AssetInput{
		Metadata: hostObservationMetadata(f, ho),
	}
	ownership := hostObservationOwnership
	ctxInput.AssetOwnership = &ownership
	if tags, _ := s.getTagsForAsset(tenantID, hostObservationPrimaryAddress(ho), hostObservationBestName(ho)); len(tags) > 0 {
		ctxInput.Tags = mergeTags(models.JSONB{}, tags)
	}

	return s.resolveObservationWithRepo(ctx, obs, func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error {
		if res.Asset.Zero() {
			// The identity floor: every identifier belongs to somebody else and
			// none could decide, so the engine opened a merge proposal and wrote
			// nothing. There is no asset to hang facts or context on.
			return nil
		}
		assetID, perr := uuid.Parse(res.Asset.ID)
		if perr != nil {
			return fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, perr)
		}
		if cerr := s.applyAssetContext(tx, tenantID, assetID, ctxInput, obs.Source, res.Outcome); cerr != nil {
			return cerr
		}
		if len(facts) > 0 {
			// On the ENGINE's repository, so the facts share its transaction.
			// Going through s.identityRepo here would open a second transaction
			// on the pool while this one still holds the asset row uncommitted,
			// and UpsertFacts' assertAssetExists would not be able to see it.
			if ferr := repo.UpsertFacts(ctx, res.Asset, hostObservationFactProducer(f), facts); ferr != nil {
				return fmt.Errorf("writing host-observation facts: %w", ferr)
			}
		}
		if cerr := s.recordClassOutcome(ctx, tx, tenantID, assetID, res.Outcome, classProp); cerr != nil {
			return cerr
		}
		if res.Outcome != identity.OutcomeConflict && assetStatus != "" && assetStatus != identity.StatusPendingApproval {
			return s.setAssetStatus(tx, tenantID, assetID, assetStatus, obs.Source)
		}
		return nil
	})
}
