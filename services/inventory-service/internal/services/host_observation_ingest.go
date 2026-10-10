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
// own, a set of names the host answered to, a vendor resolved from its OUI — has no
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
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
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

// How a passively observed host is identified (hostObservationSighting states
// it; identity.Intake scopes and grades it).
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

// classHintForSelfReport turns a sensor's own registered platform/profile
// into a class HINT — the FLOOR an observation starts from, same status as
// assetclass.KeyUnknownHost, and still overridable by the curated rule table
// (applyClassProposal) below it. It is NOT an applied classification:
// class_source_kind stays whatever the rule table (or nothing) decides, the
// same "propose, do not apply" discipline host_inventory_ingest.go documents
// for the device-agent path ("Never guess a class... turning evidence into a
// class is a RULE's job").
//
// Deliberately a small, explicit heuristic rather than a lookup table: sensor
// profiles today are effectively a single value in practice
// (config.Profile defaults to "datacenter_host" for every sensor install —
// only the unrelated device-agent uses "device_interrogation"), so platform is
// doing almost all of the work. Flagged in the PR for the owner to review;
// widening sensor install profiles to a real workstation/laptop vocabulary
// would make this a straightforward lookup instead of a guess about Windows
// and macOS sensor hosts.
func classHintForSelfReport(ho *hostobs.HostObservation) assetclass.Key {
	if ho == nil || strings.TrimSpace(ho.AgentID) == "" {
		return assetclass.KeyUnknownHost
	}
	platform := strings.ToLower(strings.TrimSpace(ho.Platform))
	profile := strings.ToLower(strings.TrimSpace(ho.Profile))
	switch platform {
	case "linux":
		if profile == "" || strings.Contains(profile, "server") ||
			strings.Contains(profile, "datacenter") || strings.Contains(profile, "cloud") {
			return assetclass.KeyServer
		}
		return assetclass.KeyComputer
	case "windows", "darwin", "macos":
		return assetclass.KeyWorkstation
	default:
		return assetclass.KeyComputer
	}
}

// hostObservationObservation is the observation a host observation resolves
// as: the intake's reading of hostObservationSighting.
func (s *AssetService) hostObservationObservation(tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) (identity.Observation, error) {
	res, err := s.hostObservationIntake(tenantID, f, ho)
	return res.Observation, err
}

// hostObservationIntake builds the sighting a host observation is and runs it
// through the intake. Everything this path used to decide for itself — the
// segment of each address and of the names, which segments are dynamic, the
// admission flags, which MACs and names and addresses are identity at all —
// is the intake's now (intake_adapters.go). What stays is the one check only
// this service can make: whether a self-report's AgentID is a sensor this
// tenant registered AND the sensor that delivered the row.
//
// The result's AttributeEvidence is what the intake withheld as identity but
// kept as evidence (synthetic names, temporary and unscoped link-local IPv6
// addresses); applyHostObservationContext writes it onto the asset.
//
// NO ENDPOINTS. A passive frame proves an address is bound to this host, which
// the ip_address identifier already records; an asset_endpoints row is a claim
// about a reachable face, and nothing connected to anything here.
func (s *AssetService) hostObservationIntake(tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) (identity.IntakeResult, error) {
	return s.hostObservationIntakeIn(nil, tenantID, f, ho)
}

// hostObservationIntakeIn is hostObservationIntake scoped against an import
// request's one segment snapshot ( F4).
func (s *AssetService) hostObservationIntakeIn(segs *importSegments, tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) (identity.IntakeResult, error) {
	verified := false
	if agentID := strings.TrimSpace(ho.AgentID); agentID != "" {
		if sensorID, err := uuid.Parse(agentID); err == nil && s.db != nil && f.SourceSensorID != nil && *f.SourceSensorID == agentID {
			if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				return tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sensors WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL)`, tenantID, sensorID).Scan(&verified)
			}); err != nil {
				return identity.IntakeResult{}, fmt.Errorf("verify sensor identity: %w", err)
			}
		}
	}
	label := "host observation " + hostObservationLabel(ho)
	res, err := s.assessSightingIn(context.Background(), segs, label, hostObservationSighting(tenantID, f, ho, verified))
	if errors.Is(err, identity.ErrNoUsableIdentifier) {
		return res, fmt.Errorf("%w: %s", errNoIdentifiers, label)
	}
	return res, err
}

// genericNames returns the process's generic-hostname decider, building it on
// first use over the identity repository. With no database (the pure-unit-test
// shape, like observationScope) it is nil, which applies the static dictionary
// alone — a nil *identity.GenericNames is usable by design.
func (s *AssetService) genericNames() *identity.GenericNames {
	s.genericNamesOnce.Do(func() {
		if s.db == nil || s.db.DB == nil {
			return
		}
		if _, err := s.identityEngine(); err != nil {
			return
		}
		s.genericNamesVal = identity.NewGenericNames(s.identityRepo)
	})
	return s.genericNamesVal
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

// hostObservationBestName picks the highest-quality name the host answered to.
// First-FQDN-wins kept hex `.local` advertisements in front of a later DHCP
// hostname (`linux-2`). Nil when the host answered to none.
func hostObservationBestName(ho *hostobs.HostObservation) *string {
	names := make([]string, 0, len(ho.FQDNs)+len(ho.Hostnames))
	names = append(names, ho.FQDNs...)
	names = append(names, ho.Hostnames...)
	if v := hostnamequality.Best(names...); v != "" {
		return &v
	}
	return nil
}

// recordSyntheticNames folds names into the asset's `synthetic_names`
// attribute (most recent first, deduplicated, capped at
// hostnamequality.MaxSyntheticNames), on the caller's transaction.
//
// It writes nothing when the list would not change, and it records no history
// and does not touch updated_at: a rotating advertisement re-announces every
// few minutes, and an attribute that exists to EXPLAIN an asset must not fill
// its timeline. (attrlist.Record, shared with device-interrogation and with the
// IPv6 address lists below.)
func recordSyntheticNames(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, names []string) error {
	return attrlist.Record(ctx, tx, tenantID.String(), assetID.String(), attrlist.KeySyntheticNames, names, hostnamequality.MaxSyntheticNames)
}

// recordAddressEvidence writes the IPv6 evidence the intake withheld as
// identity (attrlist.KeyIPv6Temporary, attrlist.KeyLinkLocal) onto the asset,
// each list capped at attrlist.MaxAddressEvidence, most recent first.
func recordAddressEvidence(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, evidence map[string][]string) error {
	for _, key := range []string{attrlist.KeyIPv6Temporary, attrlist.KeyLinkLocal} {
		if err := attrlist.Record(ctx, tx, tenantID.String(), assetID.String(), key, evidence[key], attrlist.MaxAddressEvidence); err != nil {
			return err
		}
	}
	return nil
}

// hostObservationSource attributes the observation to the capture that made it.
//
// Mode is PASSIVE for every ordinary decoder — arp/dhcp/mdns/lldp/cdp all read
// frames that were going to be on the wire anyway — but ACTIVE for a sensor's
// SELF-report (hostObservationIsSelfReport): os.Hostname() and the host's own
// interface table are not "traffic this device happened to see", they are the
// host measuring itself, which identity.ModeActive is documented to rank above
// ModePassive when two measured values disagree (shared/identity/reconcile.go).
// The ref distinguishes the standalone sensor from the platform's own capture,
// because "which sensor told us this" is the question an operator asks of a
// surprising asset, and because the two are different fact producers
// (shared/facts `sensor` vs `platform-sensor`).
func hostObservationSource(f IngestFinding) identity.Source {
	ref := "sensor"
	if hostObservationIsPlatformCapture(f) {
		ref = "sensor:pcap"
	}
	if id := strings.TrimSpace(derefString(f.SourceSensorID)); id != "" {
		ref += ":" + id
	}
	mode := identity.ModePassive
	if hostObservationIsSelfReport(f) {
		mode = identity.ModeActive
	}
	return identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: mode}
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

// hostObservationIsSelfReport reports whether the row is a sensor's SELF-report
// of the host it runs on (asset-inventory decision 9) rather than a passive
// capture of some OTHER host. Read the same way
// hostObservationIsPlatformCapture reads its own marker: sensor-manager's
// services/self_observation.go writes `discovery_method: "sensor_self_report"`,
// distinct from the sensor's own passive `passive_host_observation` and
// pcap-processor's `pcap_upload`.
func hostObservationIsSelfReport(f IngestFinding) bool {
	return strings.ToLower(rawDataString(f.RawData, "discovery_method")) == "sensor_self_report"
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
// The map is written AS GIVEN, with one exception decided before this runs:
// hw.vendor. shared/hostobs restricts the map to keys the registry lists the
// sensor producers for (hw.vendor, hw.model, net.mdns_services), UpsertFacts
// re-checks both the key and the producer, and re-deriving anything here would
// be a second opinion about a measurement somebody else made. hw.vendor was
// never a measurement — it was a sensor-side OUI table lookup — so when the
// platform's full IEEE registry answers for the MAC, resolveHostObservationVendor
// removes it from this map and it is written once, as the `enricher` producer's
// fact (oui_vendor.go). It reaches this map only from an older sensor, for a
// prefix the registry does not determine.
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
			// no model here.
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
	if ho.MAC != "" {
		if proto, ok := hostobs.VirtualMACProtocol(ho.MAC); ok || ho.MACVirtual {
			// The virtual router MAC, kept the same way: not an identifier,
			// but not lost either.
			out["host_observation_virtual_mac"] = ho.MAC
			if proto != "" {
				out["host_observation_virtual_mac_protocol"] = proto
			}
		}
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
	return s.ingestHostObservationIn(ctx, nil, tenantID, f, assetStatus)
}

// ingestHostObservationIn is ingestHostObservation answering its segment
// questions from an import request's one read of them ( F4).
func (s *AssetService) ingestHostObservationIn(ctx context.Context, segs *importSegments, tenantID uuid.UUID, f IngestFinding, assetStatus string) (identity.Resolution, error) {
	ho, ok := hostObservationPayload(f)
	if !ok {
		return identity.Resolution{}, fmt.Errorf("finding is marked %s but carries no readable host_observation payload", KindHostObservation)
	}
	// The platform's OUI answer, before anything reads the vendor: the class
	// evidence below and the facts applyHostObservationContext writes both see
	// the registry's manufacturer when it has one (oui_vendor.go).
	resolveHostObservationVendor(ho)

	intake, err := s.hostObservationIntakeIn(segs, tenantID, f, ho)
	if err != nil {
		return identity.Resolution{}, err
	}
	obs := intake.Observation

	// The rules, over what the frames actually carried (workstream 2.10b). This
	// is the path row 7 of the 2.5 note was waiting on: the OUI vendor, the
	// stated model, the mDNS service types and the LLDP/CDP capability bits were
	// all already being decoded and stored, and none of them could reach a class
	// because there was nowhere honest to record one. `class_source_kind: rule`
	// is that place.
	classProp := s.applyClassProposal(ctx, &obs, hostObservationClassEvidence(ho))
	ctxInput := s.hostObservationContextInputIn(segs, tenantID, f, ho)

	res, rerr := s.resolveObservationWithRepo(ctx, obs, func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error {
		if res.Asset.Zero() {
			if res.ObservationID == "" {
				return nil
			}
			// Keep the typed passive evidence beyond raw-discovery retention.
			// Arbitrary raw metadata is excluded from the retained payload.
			safeHost := retainedHostEvidence(ho)
			retained := IngestFinding{Kind: KindHostObservation, SourceSensorID: f.SourceSensorID,
				RawData: map[string]interface{}{"host_observation": safeHost, "source": rawDataString(f.RawData, "source"),
					"discovery_method": rawDataString(f.RawData, "discovery_method"), "confidence_score": obs.Confidence,
					"discovery_id": obs.Admission.ReceiptID, "collector_version": obs.Admission.CollectorVersion,
					"observed_at": obs.ObservedAt.Format(time.RFC3339Nano)}}
			payload, err := json.Marshal(retained)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload)
			 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, tenantID, res.ObservationID, identity.ObservationReceiptKey(obs), string(payload))
			return err
		}
		return s.applyHostObservationContext(ctx, repo, tx, tenantID, f, ho, obs, intake.AttributeEvidence, res, assetStatus, classProp, ctxInput)
	})
	if rerr == nil {
		// After the observation has landed, and outside its transaction: what a
		// DHCP ACK says about the SEGMENT is a note about the network, not part
		// of the one fact about the host that the transaction above keeps whole.
		if s.inferDHCPPosture(ctx, tenantID, ho, obs.ObservedAt) {
			// The note changed a segment's posture, which the request's
			// segment snapshot carries: the next finding reads it afresh.
			segs.invalidate()
		}
	}
	return res, rerr
}

// dhcpInferenceThrottle is how long an inferred posture is left alone once
// written. A busy segment sees an ACK every few minutes; the answer does not
// change that fast, and a write per ACK is a hot row for no information.
const dhcpInferenceThrottle = 24 * time.Hour

// dhcpAssignedAddresses returns the IPv4 addresses a sighting shows a DHCP
// server ASSIGNING, or none.
//
// Only an ACK counts. A DISCOVER or REQUEST is a client asking, and its
// address is the one it would like ([hostobs.DecodeDHCP] marks that
// `dhcp_address_requested_only`); a segment is not proven to lease addresses
// by a client wishing for one. An OFFER may never be taken. The ACK is the
// server committing the lease. IPv6 is left out: DHCPv4 is what this decoder
// reads, and an address of another family in a coalesced observation came from
// some other source.
func dhcpAssignedAddresses(ho *hostobs.HostObservation) []netip.Addr {
	if ho == nil || (!slices.Contains(ho.Sources, hostobs.SourceDHCP) && ho.Source != hostobs.SourceDHCP) {
		return nil
	}
	if kind, _ := ho.Attributes["dhcp_message_type"].(string); kind != "ack" {
		return nil
	}
	if requestedOnly, _ := ho.Attributes["dhcp_address_requested_only"].(bool); requestedOnly {
		return nil
	}
	var out []netip.Addr
	for _, a := range ho.Addresses {
		if a.IsValid() && a.Is4() && !a.IsUnspecified() {
			out = append(out, a)
		}
	}
	return out
}

// inferDHCPPosture records, on the segment covering an address a DHCP ACK
// assigned, that the network hands out addresses — at the LOWEST rank, below
// what a device measured and what an operator said.
//
// Best effort, and it must stay that way. The observation this rides on has
// already been resolved and committed; a failure here costs one note about a
// segment, which the next ACK repeats, and must never turn into a failed
// ingest that the sensor then retries. It is logged, not returned.
//
// It reports whether it wrote a posture, so an import request holding a
// segment snapshot knows to read it again.
func (s *AssetService) inferDHCPPosture(ctx context.Context, tenantID uuid.UUID, ho *hostobs.HostObservation, observedAt time.Time) (wrote bool) {
	addrs := dhcpAssignedAddresses(ho)
	if len(addrs) == 0 || s.db == nil || s.db.DB == nil {
		return false
	}
	now := time.Now()
	if observedAt.IsZero() || observedAt.After(now) {
		// A clock ahead of ours would make the evidence look newer than the
		// throttle window for as long as the skew lasts.
		observedAt = now
	}
	if now.Sub(observedAt) > dhcpInferenceThrottle {
		// A backlog replay. Too old to say anything about the network today,
		// and each one would otherwise clear the throttle and write.
		return
	}
	done := map[string]bool{}
	for _, addr := range addrs {
		if _, err := s.identityEngine(); err != nil {
			log.Printf("[AssetService] tenant %s: recording inferred DHCP posture skipped: %v", tenantID, err)
			return
		}
		scope, _, err := s.identityRepo.ScopeForAddress(ctx, tenantID.String(), addr, "")
		if err != nil {
			log.Printf("[AssetService] tenant %s: resolving the segment of DHCP-assigned %s failed (the observation is unaffected): %v", tenantID, addr, err)
			continue
		}
		segmentID, err := uuid.Parse(scope)
		if err != nil || done[scope] {
			// The tenant default scope is not a segment; there is nothing to mark.
			continue
		}
		done[scope] = true
		err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
			r, e := pgidentity.RecordSegmentPosture(ctx, tx, tenantID.String(), segmentID.String(),
				pgidentity.PostureInferred, true, pgidentity.PostureEvidence{ObservedAt: observedAt},
				pgidentity.SkipIfSourceStatedSince(now.Add(-dhcpInferenceThrottle)))
			wrote = wrote || (e == nil && r.Written)
			return e
		})
		if err != nil {
			log.Printf("[AssetService] tenant %s: recording inferred DHCP posture for segment %s failed (the observation is unaffected): %v", tenantID, segmentID, err)
		}
	}
	return wrote
}

// Retain decoder-owned fields and regenerate registered facts. Unrecognized
// metadata is not evidence and must not become a long-lived credential store.
func retainedHostEvidence(ho *hostobs.HostObservation) *hostobs.HostObservation {
	copy := *ho
	copy.Attributes = make(map[string]interface{})
	for _, key := range []string{"virtual_mac_protocol", "mdns_relayed", "mdns_service_port", "capture_interface",
		"dhcp_vendor_class", "dhcp_param_request_list", "dhcp_address_requested_only", "dhcp_message_type",
		"lldp_chassis_id", "lldp_port_id", "lldp_port_description", "lldp_system_description", "lldp_capabilities", "lldp_med_manufacturer",
		"cdp_port_id", "cdp_capabilities", "cdp_software_version", "cdp_platform", "arp_gratuitous", "arp_probe", "arp_operation"} {
		if value, ok := ho.Attributes[key]; ok {
			copy.Attributes[key] = value
		}
	}
	copy.Finalize()
	return &copy
}

func (s *AssetService) hostObservationContextInput(tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) models.AssetInput {
	return s.hostObservationContextInputIn(nil, tenantID, f, ho)
}

func (s *AssetService) hostObservationContextInputIn(segs *importSegments, tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation) models.AssetInput {

	ctxInput := models.AssetInput{
		Metadata: hostObservationMetadata(f, ho),
	}
	ownership := hostObservationOwnership
	ctxInput.AssetOwnership = &ownership
	if tags, _ := s.getTagsForAssetIn(segs, tenantID, hostObservationPrimaryAddress(ho), hostObservationBestName(ho)); len(tags) > 0 {
		ctxInput.Tags = mergeTags(models.JSONB{}, tags)
	}

	return ctxInput
}

// materializeRetainedHostObservation applies the original typed evidence to the
// explicitly resolved asset. It never creates another asset or claims aliases.
func (s *AssetService) materializeRetainedHostObservation(ctx context.Context, tenantID, assetID uuid.UUID, f IngestFinding) error {
	ho, ok := hostObservationPayload(f)
	if !ok {
		return fmt.Errorf("retained host observation has no typed payload")
	}
	resolveHostObservationVendor(ho)
	intake, err := s.hostObservationIntake(tenantID, f, ho)
	if err != nil {
		return err
	}
	obs := intake.Observation
	classProp := s.applyClassProposal(ctx, &obs, hostObservationClassEvidence(ho))
	ctxInput := s.hostObservationContextInput(tenantID, f, ho)
	repo := pgidentity.New(s.db.DB.DB)
	return repo.RunInTx(ctx, tenantID.String(), func(bound *pgidentity.Repository) error {
		res := identity.Resolution{Outcome: identity.OutcomeMatched, Asset: identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}}
		return s.applyHostObservationContext(ctx, bound, s.sqlxOver(bound.Tx()), tenantID, f, ho, obs, intake.AttributeEvidence, res, "", classProp, ctxInput)
	})
}

func (s *AssetService) applyHostObservationContext(ctx context.Context, repo *pgidentity.Repository, tx *sqlx.Tx, tenantID uuid.UUID,
	f IngestFinding, ho *hostobs.HostObservation, obs identity.Observation, evidence map[string][]string, res identity.Resolution, assetStatus string, classProp classify.ClassProposal, ctxInput models.AssetInput) error {

	facts := hostObservationFacts(ho, obs.Source, obs.ObservedAt, obs.Confidence)
	assetID, perr := uuid.Parse(res.Asset.ID)
	if perr != nil {
		return fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, perr)
	}
	if res.Outcome != identity.OutcomeConflict {
		if err := repo.ProjectSegmentLocation(ctx, res.Asset, obs.Network.SegmentID, obs.Source); err != nil {
			return err
		}
	}
	if cerr := s.applyAssetContext(tx, tenantID, assetID, ctxInput, obs.Source, res.Outcome); cerr != nil {
		return cerr
	}
	// What the intake withheld as identity and kept as evidence: synthetic
	// names ( D1) and rotating or unscoped IPv6 addresses ( D2).
	if serr := recordSyntheticNames(ctx, tx, tenantID, assetID, hostnamequality.MergeSyntheticNames(evidence[attrlist.KeySyntheticNames], nil)); serr != nil {
		return serr
	}
	if aerr := recordAddressEvidence(ctx, tx, tenantID, assetID, evidence); aerr != nil {
		return aerr
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
	// The registry-resolved vendor, as the enricher's fact (oui_vendor.go).
	// Only when resolveHostObservationVendor put the registry's answer on the
	// observation: a vendor that merely arrived on the wire (an older sensor's
	// own table, for a prefix the registry does not determine) stays the
	// sensor's fact above.
	if rv := registryVendorForObservation(ho); rv != "" && ho.Vendor == rv {
		if _, verr := applyRegistryVendorFact(ctx, repo, tx, res.Asset, rv, obs.ObservedAt); verr != nil {
			return fmt.Errorf("writing the OUI-resolved vendor: %w", verr)
		}
	}
	// The class, LAST among this observation's writes and before the
	// self-report's own upgrade below. This is the point the accumulated
	// evidence is read at, deliberately: the engine attached this
	// observation's identifiers (its MAC) during Resolve, before this callback
	// ran; the facts above (hw.model, net.mdns_services, the registry vendor)
	// and the metadata applyAssetContext merged (host_observation_attributes)
	// are written on this same transaction. Read any earlier and the classifier
	// would miss the observation's own facts as stored evidence; read on any
	// other transaction and it would not see them at all.
	//
	// A sensor's SELF-report that names a class (classHintForSelfReport) is the
	// host measuring itself, which outranks a rule (ADR-0002 D4), and
	// upgradeUnknownHostClass applies it below. A promotion here would move the
	// asset off the floor first and that measured class would then never land,
	// so on that path the rules only propose. upgradeUnknownHostClass is left
	// exactly as it was.
	selfReportClasses := strings.TrimSpace(ho.AgentID) != "" && obs.Admission.Authoritative &&
		classHintForSelfReport(ho) != assetclass.KeyUnknownHost
	if _, cerr := s.classOutcomeForResolution(ctx, tx, tenantID, assetID, res.Outcome, classProp,
		hostObservationClassEvidence(ho), !selfReportClasses); cerr != nil {
		return cerr
	}
	if agentID := strings.TrimSpace(ho.AgentID); agentID != "" && obs.Admission.Authoritative {
		// Link the sensor to the asset its own self-report resolved to —
		// in the SAME transaction as everything else this observation
		// wrote, so the link is atomic with the asset it points at. This
		// is also the RETRO-LINK path: an existing anonymous unknown_host
		// asset holding only this host's MAC/IP (a real deployment shape:
		// seen passively by another sensor before this one ever reported
		// itself) is exactly what res.Asset already is when the engine
		// matched on mac_address/ip_address, so linking here covers both
		// "created fresh" and "matched existing" without a separate code
		// path.
		//
		// `sensors` belongs to sensor-manager, not this service, but both
		// read/write the one shared database — sensorrouting.Store
		// already SELECTs from `sensors` for the same reason (see its
		// TenantSensors). agentID is the sensor's own id (it set AgentID
		// to sensorID.String() — see sensor-manager's
		// selfHostObservation), so no separate lookup is needed.
		if sensorID, perr := uuid.Parse(agentID); perr == nil {
			if lerr := s.linkSensorAsset(tx, tenantID, sensorID, assetID); lerr != nil {
				return fmt.Errorf("linking sensor %s to its host asset: %w", sensorID, lerr)
			}
		}
		// Upgrade the class on the RETRO-LINK path (asset MATCHED an
		// existing row rather than being created): classForCreate's
		// ClassHint only ever applies at creation, by design — an
		// observation must not overwrite a class an asset already HAS,
		// the same invariant classproposal documents ("It never sets a
		// class on an existing asset... a rule that changed its mind six
		// months after somebody approved a class would be a silent
		// rewrite"). This is the one narrow, deliberate exception: it
		// fires ONLY while the asset's class is still the unassigned
		// floor (unknown_host) — nothing has been decided yet, by a rule,
		// a human, or anything else — and the evidence is the sensor's
		// own self-report, not a guess. Flagged for the owner in the PR:
		// this reaches past the ordinary class-proposal review queue on
		// the reasoning that "nothing was ever decided" is different from
		// "something was decided and this disagrees."
		if hint := classHintForSelfReport(ho); hint != assetclass.KeyUnknownHost {
			if cerr := upgradeUnknownHostClass(ctx, tx, tenantID, assetID, hint, "sensor:"+agentID); cerr != nil {
				return fmt.Errorf("upgrading class for sensor %s's host asset: %w", agentID, cerr)
			}
		}
	}
	if res.Outcome != identity.OutcomeConflict && assetStatus != "" && assetStatus != identity.StatusPendingApproval {
		return s.setStatusUnlessArchived(tx, tenantID, assetID, assetStatus, obs.Source)
	}
	return nil
}

// linkSensorAsset records that sensorID's own host resolved to assetID — the
// "sensors.asset_id" link the sensor-routing "never scan yourself" guard
// reads (services/inventory-service/internal/sensorrouting.Store.TenantSensors)
// and the Sensors & Agents page's "Host" line reads. tenant_id is part of the
// predicate as the repo's belt-and-braces rule requires even though sensors
// is not RLS-scoped through this service's connection.
func (s *AssetService) linkSensorAsset(tx *sqlx.Tx, tenantID, sensorID, assetID uuid.UUID) error {
	_, err := tx.Exec(
		`UPDATE sensors SET asset_id = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`,
		assetID, sensorID, tenantID,
	)
	return err
}

// upgradeUnknownHostClass moves an asset off the unassigned unknown_host
// floor onto hint, source-kind `measured` (a self-report is the host
// measuring itself, ADR-0002 D4's precedence — see hostObservationSource's
// Mode: ModeActive for the same reasoning). The `class_key = 'unknown_host'`
// predicate is the whole safety property: it is a no-op the moment anything
// — a rule, a human, an import — has ever set a real class, same shape as
// applyProposedClass (class_proposal_service.go) which this mirrors for the
// one case that never goes through Approvals.
func upgradeUnknownHostClass(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, hint assetclass.Key, sourceRef string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE assets
		   SET class_key = $3,
		       class_path = $4,
		       class_source_kind = 'measured',
		       class_source_ref = $5,
		       class_confidence = 1,
		       updated_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND class_key = 'unknown_host'
           AND class_source_kind IS DISTINCT FROM 'declared'`,
		tenantID, assetID, string(hint), classPathForKey(string(hint)), sourceRef,
	)
	return err
}
