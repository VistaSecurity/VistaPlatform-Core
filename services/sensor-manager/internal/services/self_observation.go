package services

// Sensor self-observation (asset-inventory decision 9, morning
// notes).
//
// Before this existed, the host a sensor runs ON was only ever seen
// PASSIVELY — an ARP or mDNS frame some OTHER sensor happened to capture of
// it — so it landed in inventory as an anonymous `unknown_host` carrying
// nothing but a MAC and an IP address, even though the `sensors` row for that
// same host already held its name, platform, profile and interfaces. Verified
// in the lab: a sensor's own host asset showed up as
// `<sensor's LAN address> · unknown_host · monitoring`.
//
// The fix reuses the device-agent's pattern: shared/identity's KindAgentID is
// "a host agent's own installation id: the strongest identifier we have,
// because we issued it" (shared/identity/identifier.go), and
// device-interrogation-service already turns an agent's own host inventory
// into a named asset this way. A sensor is not a device agent — it has no
// command channel and does not run interrogations — but its heartbeat can
// carry the same kind of self-report: hostname, FQDN, OS/arch and per-NIC
// MACs (sensor/internal/hostid.Build).
//
// This file turns that report into ONE host_observation discovery through the
// EXACT SAME sensor_discoveries → discovery-processor →
// inventory-service/host_observation_ingest.go pipeline every passive
// ARP/mDNS/LLDP/CDP observation already travels — StoreDiscoveries below is
// the same method SubmitDiscoveries calls for a sensor's ordinary uploads.
// Deliberately NOT a second, bespoke path into inventory: a host observation
// consumer that has to reason about two shapes of "host exists" evidence is
// exactly the kind of parallel-opinion bug CLAUDE.md's "catalogue drives risk
// scoring" and "PQC readiness: denylist, not allowlist" sections warn about
// for other subsystems.

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// selfObservationInterval bounds how often an UNCHANGED self-observation is
// re-ingested. A heartbeat fires roughly every 30s (the sensor's default
// ReportingInterval); re-running the identification engine that often for a
// host block that has not moved would be pure overhead on inventory-service
// with nothing to show for it. A CHANGED block (new interface, renamed host)
// is always emitted immediately regardless of how recently the last one was
// sent — see EmitSelfObservationIfDue.
const selfObservationInterval = time.Hour

// EmitSelfObservationIfDue is called from both RegisterSensor and Heartbeat
// (registration's own send is unthrottled — it only ever happens once) with
// the SAME throttle state (sensors.self_observation_hash /
// self_observation_at), so whichever call is due wins and the other is a
// cheap no-op.
//
// Never returns an error the caller must act on: a self-observation is
// best-effort telemetry about the sensor's own host, and losing one must
// never fail a heartbeat or a registration a tenant is waiting on. Failures
// are logged.
func (s *SensorService) EmitSelfObservationIfDue(sensorID uuid.UUID, host *models.HostIdentity) {
	if host == nil {
		return
	}
	hash := selfObservationHash(host)

	var platform, profile *string
	var storedHash *string
	var lastAt *time.Time
	err := s.bypassDB.QueryRow(`
		SELECT platform, profile, self_observation_hash, self_observation_at
		FROM sensors WHERE id = $1`, sensorID,
	).Scan(&platform, &profile, &storedHash, &lastAt)
	if err != nil {
		log.Printf("[SensorService] self-observation: could not read sensor %s: %v", sensorID, err)
		return
	}

	changed := storedHash == nil || *storedHash != hash
	stale := lastAt == nil || time.Since(*lastAt) >= selfObservationInterval
	if !changed && !stale {
		return
	}

	ho := selfHostObservation(sensorID, derefString(platform), derefString(profile), host)
	if !ho.Identifies() {
		// Unreachable in practice: AgentID alone always identifies (Key()
		// checks it first). Defensive rather than a panic — a self-report that
		// somehow carries neither an id nor any address/name is one this
		// method should skip, not crash the heartbeat over.
		return
	}

	discovery := selfObservationDiscovery(ho)
	batch := &models.DiscoveryBatch{
		SensorID:    sensorID,
		Discoveries: []models.SensorDiscoveryInput{*discovery},
		Timestamp:   discovery.Timestamp,
		Count:       1,
	}
	if err := s.StoreDiscoveries(batch); err != nil {
		log.Printf("[SensorService] self-observation: failed to store for sensor %s: %v", sensorID, err)
		return
	}

	if _, err := s.bypassDB.Exec(
		`UPDATE sensors SET self_observation_hash = $1, self_observation_at = $2 WHERE id = $3`,
		hash, time.Now().UTC(), sensorID,
	); err != nil {
		// The observation itself already landed; only the throttle bookkeeping
		// failed. Worst case the next beat re-ingests the same content sooner
		// than an hour, which is a wasted resolve, not a data-quality bug.
		log.Printf("[SensorService] self-observation: failed to record throttle state for sensor %s: %v", sensorID, err)
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// selfHostObservation renders the sensor's Host block as a
// shared/hostobs.HostObservation, the same payload shape every passive
// decoder produces.
//
// AgentID is the sensor's own id — identity.KindAgentID, the strongest
// identifier kind there is, so this can never mis-merge with an unrelated
// host that happens to share an address. Platform/Profile travel as raw
// evidence for inventory-service's class HINT (never an applied
// classification here — see that consumer's classHintForSelfReport); mapping
// them to a class key is a decision the identification engine's caller makes,
// not sensor-manager, the same separation host_inventory_ingest.go documents
// for the device-agent path ("never guess a class").
func selfHostObservation(sensorID uuid.UUID, platform, profile string, host *models.HostIdentity) *hostobs.HostObservation {
	ho := &hostobs.HostObservation{
		ObservedAt: time.Now().UTC(),
		AgentID:    sensorID.String(),
		Platform:   platform,
		Profile:    profile,
	}

	if name := strings.ToLower(strings.TrimSpace(host.Hostname)); name != "" && !strings.Contains(name, ".") {
		ho.Hostnames = append(ho.Hostnames, name)
	}
	if fqdn := strings.ToLower(strings.TrimSpace(host.FQDN)); fqdn != "" {
		ho.FQDNs = append(ho.FQDNs, fqdn)
	}

	// hostobs.HostObservation carries a single MAC (see its file header); a
	// host with several physical NICs is identified fully by AgentID
	// regardless, so picking one is best-effort SECONDARY evidence (it is what
	// lets an existing MAC/IP-only unknown_host asset be retro-matched), not
	// the primary identity. The interface flagged primary — the one the
	// sensor reaches the control plane from — wins; otherwise the first
	// interface that reported a usable MAC.
	var mac string
	for _, iface := range host.Interfaces {
		if iface.MAC == "" {
			continue
		}
		if iface.IsPrimary {
			mac = iface.MAC
			break
		}
		if mac == "" {
			mac = iface.MAC
		}
	}
	ho.MAC = mac

	for _, iface := range host.Interfaces {
		addr, err := netip.ParseAddr(strings.TrimSpace(iface.Address))
		if err != nil || !addr.IsValid() {
			continue
		}
		ho.Addresses = append(ho.Addresses, addr)
	}

	ho.Finalize()
	return ho
}

// selfObservationDiscovery renders a self-observation the way
// sensor/internal/capture's hostObservationDiscovery renders a passive one —
// same envelope shape, same `sensor_discoveries.dest_ip`/`port` column
// conventions (0.0.0.0 / 0 mean "not applicable", never fabricated) — with a
// DISTINCT discovery_method so the consumer can tell a self-report from a
// passive capture apart (hostObservationIsSelfReport reads it, the same way
// hostObservationIsPlatformCapture already reads pcap-processor's
// "pcap_upload").
//
// Confidence is 1 — not run through hostobs.Confidence's arp/dhcp/mdns
// ladder, which grades HOW DIRECTLY a subject stated its own identity over a
// captured frame. A host naming itself via os.Hostname() is not on that
// ladder at all; it is the most direct statement of identity there is, and
// forcing it through the ladder's "unrecognised source" floor (0.60) would
// understate it.
func selfObservationDiscovery(ho *hostobs.HostObservation) *models.SensorDiscoveryInput {
	destIP := "0.0.0.0"
	if len(ho.Addresses) > 0 {
		destIP = ho.Addresses[0].String()
	}

	raw := map[string]interface{}{
		"discovery_type":   "host_observation",
		"host_observation": ho,
	}
	name := selfBestName(ho)
	if name != "" {
		raw["hostname"] = name
	}

	return &models.SensorDiscoveryInput{
		Protocol:        "HOST",
		DestIP:          destIP,
		Hostname:        name,
		DiscoveryMethod: "sensor_self_report",
		DiscoveryType:   "host_observation",
		Confidence:      1,
		RawMetadata:     raw,
		Timestamp:       ho.ObservedAt,
	}
}

// selfBestName picks the most specific name for the hostname column: a
// qualified name beats a short one, the same preference
// sensor/internal/capture's bestName applies to a passive observation.
func selfBestName(ho *hostobs.HostObservation) string {
	if len(ho.FQDNs) > 0 {
		return ho.FQDNs[0]
	}
	if len(ho.Hostnames) > 0 {
		return ho.Hostnames[0]
	}
	return ""
}

// selfObservationHash renders a stable fingerprint of a Host block for the
// throttle above, independent of shared/network.InterfaceAddress ordering
// (which is OS-defined and has been observed to vary between calls on an
// unchanged host).
func selfObservationHash(host *models.HostIdentity) string {
	if host == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(
		selfInterfaceFingerprint(host) + "|" +
			strings.ToLower(strings.TrimSpace(host.Hostname)) + "|" +
			strings.ToLower(strings.TrimSpace(host.FQDN)) + "|" +
			strings.ToLower(strings.TrimSpace(host.OS)) + "|" +
			strings.ToLower(strings.TrimSpace(host.Arch)),
	))
	return hex.EncodeToString(sum[:])
}

func selfInterfaceFingerprint(host *models.HostIdentity) string {
	addrs := make([]string, 0, len(host.Interfaces))
	for _, iface := range host.Interfaces {
		addrs = append(addrs, iface.Address+"/"+iface.MAC)
	}
	sort.Strings(addrs)
	return strings.Join(addrs, ",")
}
