package capture

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// Passive host observation (asset-inventory ADR-0004 D2).
//
// The sensor sees every ARP, DHCP, mDNS, NetBIOS, LLDP and CDP frame on its
// segment and, until this, recorded none of them. Decoding them costs nothing
// extra on the wire and produces the identity material a general asset
// inventory needs: a MAC, the addresses bound to it, the names a host answers
// to, the manufacturer its OUI is registered to, and — when a switch or a phone
// advertises itself over LLDP or CDP — that device's own name and model.
//
// # Why this runs on its own goroutine
//
// The crypto paths are the sensor's job of record. A host-observation decoder
// that blocked a capture worker would delay a TLS handshake's reassembly, and
// a segment with a chatty mDNS responder would make that happen constantly. So
// the capture worker does the cheapest possible classification, copies the few
// hundred bytes the decoder needs, and hands the frame to a BOUNDED channel.
// When the channel is full the frame is DROPPED and counted — never queued,
// never blocked. The drop counter goes out on the heartbeat, because a
// pipeline silently discarding half the segment is precisely the "reports
// success while doing nothing" failure mode CLAUDE.md warns about.
//
// # Why frames are coalesced
//
// One host produces hundreds of identical ARP frames a minute. Emitting a
// discovery per frame would drown the batch and tell the platform the same
// thing over and over. Observations about one subject are merged over a window
// (default 60s) and emitted once, carrying everything every decoder learned —
// the MAC from ARP, the hostname from DHCP, the service types from mDNS.

const (
	// hostObsQueueDepth is the bounded hand-off between the capture workers and
	// the decode goroutine.
	hostObsQueueDepth = 512

	// hostObsMaxPayload caps what is copied out of a frame. Every protocol
	// decoded here is a small control-plane message; an LLDPDU is a few hundred
	// bytes and a CDP frame with a 10 KB banner is already truncated by the
	// decoder. Copying more would only move the cost of a hostile frame from
	// the network to the sensor's heap.
	hostObsMaxPayload = 2048

	// hostObsFlushInterval is how often closed coalescing windows are swept.
	hostObsFlushInterval = 5 * time.Second
)

// hostObsFrame is the minimum the capture worker extracts before handing off.
//
// The payload is COPIED. gopacket's decoded slices alias the buffer libpcap
// hands back, and that buffer is reused for the next packet — retaining the
// slice across a channel would hand the decoder whatever arrived afterwards.
type hostObsFrame struct {
	kind    hostobs.Kind
	payload []byte
	srcMAC  string
	srcAddr netip.Addr
	iface   string
	at      time.Time
}

// hostObsPipeline decodes classified frames, coalesces them per subject and
// emits discoveries.
type hostObsPipeline struct {
	sensorID string
	frames   chan hostObsFrame
	out      chan<- *models.CryptoDiscovery
	// decoders says which kinds are switched on. The DECISION lives in
	// shared/hostobs so the sensor and pcap-processor cannot disagree about
	// it; this field just carries the runtime's answer.
	decoders  hostobs.Config
	coalescer *hostobs.Coalescer
	window    time.Duration

	wg sync.WaitGroup

	// Counters, all atomic and all surfaced on the heartbeat.
	offered   int64 // frames classified as decodable
	queueDrop int64 // dropped because the hand-off channel was full
	decoded   int64 // frames a decoder turned into an observation
	malformed int64 // frames a decoder rejected as malformed
	emitted   int64 // discoveries sent downstream
	emitDrop  int64 // discoveries dropped because the discovery channel was full
}

func newHostObsPipeline(sensorID string, out chan<- *models.CryptoDiscovery, window time.Duration, decoders hostobs.Config) *hostObsPipeline {
	if window <= 0 {
		window = hostobs.DefaultCoalesceWindow
	}
	return &hostObsPipeline{
		sensorID:  sensorID,
		frames:    make(chan hostObsFrame, hostObsQueueDepth),
		out:       out,
		decoders:  decoders,
		coalescer: hostobs.NewCoalescer(window, hostobs.DefaultCoalesceCapacity),
		window:    window,
	}
}

// hostObsConfig reads the enabled decoder set out of the sensor's config.
//
// One function, used by BOTH the pipeline and the BPF filter builder, so the
// filter can never ask for packets the classifier will refuse or refuse
// packets the filter asked for.
func hostObsConfig(cfg *config.Config) hostobs.Config {
	return hostobs.Config{DNS: cfg.Capture.HostObservationDNS}
}

// enabledWord renders a toggle for the startup log.
func enabledWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// Start runs the decode loop and the window sweeper until ctx is cancelled.
func (p *hostObsPipeline) Start(ctx context.Context) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(hostObsFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Shutdown drains rather than discards. Frames already handed
				// off are decoded, and every open window is emitted: a host
				// seen thirty seconds before shutdown was still seen, and
				// throwing that away would make a sensor restart look like a
				// segment going quiet.
				for {
					select {
					case f := <-p.frames:
						p.decode(f)
						continue
					default:
					}
					break
				}
				p.emitAll(p.coalescer.Drain())
				return
			case f := <-p.frames:
				p.decode(f)
			case now := <-ticker.C:
				p.emitAll(p.coalescer.Expired(now))
			}
		}
	}()
}

// Stop waits for the decode loop to finish its final drain.
func (p *hostObsPipeline) Stop() { p.wg.Wait() }

// Offer classifies a captured packet and hands it off, non-blocking.
//
// Called from the capture worker on EVERY packet, so the first thing it does
// is the cheapest test that can rule a frame out.
func (p *hostObsPipeline) Offer(packet gopacket.Packet, iface string) {
	f, ok := classifyHostObs(packet, iface)
	if !ok {
		return
	}
	// A kind the runtime has switched off is dropped here as well as filtered
	// out of the BPF expression. Two gates rather than one because the filter
	// is advisory in a way the classifier is not: an operator can widen it, a
	// driver can ignore it, and a frame that arrives anyway must not be
	// decoded by something nobody turned on.
	if !p.decoders.Enabled(f.kind) {
		return
	}
	atomic.AddInt64(&p.offered, 1)
	select {
	case p.frames <- f:
	default:
		atomic.AddInt64(&p.queueDrop, 1)
	}
}

func (p *hostObsPipeline) decode(f hostObsFrame) {
	frame := hostobs.Frame{
		Payload:   f.payload,
		SrcMAC:    f.srcMAC,
		SrcAddr:   f.srcAddr,
		Interface: f.iface,
		At:        f.at,
	}

	// The decoder switch lives in shared/hostobs, not here. Shared decode with
	// per-runtime dispatch is the shape that gated the OT UDP probers on an
	// open TCP port and had to be fixed twice.
	obs, err := hostobs.Decode(f.kind, frame)
	if err != nil {
		// ErrNotApplicable is the normal case — most frames on a segment say
		// nothing we record — and is deliberately not counted as a fault.
		// Only a frame that failed to parse is.
		if errors.Is(err, hostobs.ErrMalformed) {
			atomic.AddInt64(&p.malformed, 1)
		}
		return
	}
	if obs == nil {
		return
	}
	atomic.AddInt64(&p.decoded, 1)
	p.coalescer.Add(obs)
}

func (p *hostObsPipeline) emitAll(observations []*hostobs.HostObservation) {
	for _, obs := range observations {
		d := hostObservationDiscovery(p.sensorID, obs)
		if d == nil {
			continue
		}
		select {
		case p.out <- d:
			atomic.AddInt64(&p.emitted, 1)
		default:
			atomic.AddInt64(&p.emitDrop, 1)
			log.Printf("Warning: Discovery channel full, dropping host observation")
		}
	}
}

// Metrics returns the heartbeat view of this pipeline.
func (p *hostObsPipeline) Metrics() map[string]interface{} {
	return map[string]interface{}{
		"host_observations_offered":   atomic.LoadInt64(&p.offered),
		"host_observations_decoded":   atomic.LoadInt64(&p.decoded),
		"host_observations_emitted":   atomic.LoadInt64(&p.emitted),
		"host_observations_malformed": atomic.LoadInt64(&p.malformed),
		// Two distinct drops, kept apart because they mean different things: a
		// queue drop is the sensor shedding load ahead of the decoder, an emit
		// drop is the reporting path backing up behind it.
		"host_observations_queue_dropped":    atomic.LoadInt64(&p.queueDrop),
		"host_observations_emit_dropped":     atomic.LoadInt64(&p.emitDrop),
		"host_observations_coalesce_dropped": p.coalescer.Dropped(),
		"host_observations_pending":          p.coalescer.Pending(),
	}
}

// hostObservationDiscovery renders a coalesced observation as a discovery row.
//
// The column shapes it has to satisfy, and what they force:
//
//	sensor_discoveries.dest_ip  inet NOT NULL — so an observation with no
//	    address at all (an LLDP frame carrying only a chassis MAC, an ARP probe)
//	    is written as the unspecified address 0.0.0.0, which the wire contract
//	    documents as "no address observed; identify by MAC". Inventing a
//	    plausible address would be worse than saying nothing.
//	sensor_discoveries.port     integer NOT NULL — so 0, which for a host
//	    observation means "not an endpoint" rather than "port zero". There IS
//	    no port: the subject is a host, not a service on one.
func hostObservationDiscovery(sensorID string, obs *hostobs.HostObservation) *models.CryptoDiscovery {
	if obs == nil || !obs.Identifies() {
		return nil
	}

	destIP := "0.0.0.0"
	if len(obs.Addresses) > 0 {
		destIP = obs.Addresses[0].String()
	}

	raw := map[string]interface{}{
		"discovery_type":   "host_observation",
		"host_observation": obs,
	}
	// sensor-manager fills sensor_discoveries.hostname from this key, so the
	// column gets the most specific name the observation carried.
	if name := bestName(obs); name != "" {
		raw["hostname"] = name
	}
	// The capture interface, recorded the same way every other sensor discovery
	// records it. Provenance for where the observation was made — NOT a claim
	// that the subject is attached to that interface, which a mirror or SPAN
	// port would make false.
	if iface, ok := obs.Attributes["capture_interface"].(string); ok && iface != "" {
		raw["interface"] = iface
	}

	return &models.CryptoDiscovery{
		ID:       generateDiscoveryID(),
		SensorID: sensorID,
		// The capture timestamp of the latest frame that contributed, not the
		// time the window closed.
		Timestamp: obs.ObservedAt,
		DestIP:    destIP,
		Port:      0,
		Protocol:  "HOST",
		// Distinct from the crypto paths' "passive" so a consumer can tell at
		// a glance which pipeline a row came from without parsing metadata.
		DiscoveryMethod: "passive_host_observation",
		DiscoveryType:   "host_observation",
		Confidence:      hostObsConfidence(obs),
		RawMetadata:     raw,
		CreatedAt:       time.Now(),
	}
}

// bestName picks the most specific name for the hostname column: a fully
// qualified name beats a short one, because it is the one a CMDB can join on.
func bestName(obs *hostobs.HostObservation) string {
	if len(obs.FQDNs) > 0 {
		return obs.FQDNs[0]
	}
	if len(obs.Hostnames) > 0 {
		return obs.Hostnames[0]
	}
	return ""
}

// hostObsConfidence grades how directly the subject stated its own identity.
//
// The ladder itself lives in shared/hostobs, because pcap-processor grades the
// same observations and wrote a flat 0.85 for every one of them — so the same
// capture replayed through the two runtimes produced two different confidences
// for one host. This is the sensor's one call into it.
func hostObsConfidence(obs *hostobs.HostObservation) float64 {
	return hostobs.Confidence(obs)
}

// classifyHostObs pulls the fields shared/hostobs needs out of a gopacket
// packet and asks IT which decoder they belong to.
//
// The gopacket plumbing is per-runtime because pcap-processor's is too; the
// DECISION is not. Nothing here knows that mDNS is on 5353 or that CDP is
// SNAP-framed — those live in shared/hostobs beside the decoders and the BPF
// terms, so a protocol added there reaches both capture paths at once.
func classifyHostObs(packet gopacket.Packet, iface string) (hostObsFrame, bool) {
	at := packet.Metadata().Timestamp
	if at.IsZero() {
		at = time.Now()
	}

	var srcMAC string
	if eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		srcMAC = eth.SrcMAC.String()
		if kind, body := hostobs.ClassifyEther(uint16(eth.EthernetType), eth.Payload); kind != hostobs.KindNone {
			return hostObsFrame{
				kind: kind, payload: copyPayload(body),
				srcMAC: srcMAC, iface: iface, at: at,
			}, true
		}
	}

	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || len(udp.Payload) == 0 {
		return hostObsFrame{}, false
	}
	kind := hostobs.ClassifyUDP(uint16(udp.SrcPort), uint16(udp.DstPort))
	if kind == hostobs.KindNone {
		return hostObsFrame{}, false
	}

	var srcAddr netip.Addr
	if nl := packet.NetworkLayer(); nl != nil {
		srcAddr, _ = netip.ParseAddr(nl.NetworkFlow().Src().String())
	}

	return hostObsFrame{
		kind: kind, payload: copyPayload(udp.Payload),
		srcMAC: srcMAC, srcAddr: srcAddr, iface: iface, at: at,
	}, true
}

func copyPayload(b []byte) []byte {
	if len(b) > hostObsMaxPayload {
		b = b[:hostObsMaxPayload]
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
