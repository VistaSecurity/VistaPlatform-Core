package processor

import (
	"errors"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// Passive host observation over an uploaded capture file.
//
// This is the same feature the live sensor runs, over the same decoders, with
// the same emitted shape — the Discovery Pipeline Principles require the two
// runtimes to share source, and shared/hostobs owns both the decoders and the
// decision of which frame goes to which one. What differs here is only the
// plumbing either side of that: a file has no BPF filter (everything in the
// capture is offered), no latency budget (a batch job may decode inline), and a
// definite end (the coalescer is drained once, at EOF).
//
// A PCAP upload is often the ONLY view a customer can give us of a segment we
// will never put a sensor on — an air-gapped OT cell, a third party's network
// during an assessment — so the host inventory it yields is disproportionately
// valuable relative to the effort of decoding it.

// hostObsCollector accumulates host observations across a capture file.
type hostObsCollector struct {
	// decoders is the zero Config: every decoder except DNS.
	//
	// A file has no BPF filter to shed UDP 53 with, so the classifier is the
	// only gate here — but the reason to shed it is the same one the live
	// sensor has. An answer names what was asked, so decoding a capture's DNS
	// would turn an uploaded file into a record of which names that network
	// resolved, which is not what the uploader was asked for. If it is ever
	// wanted it belongs behind a per-upload choice, not a default.
	decoders  hostobs.Config
	coalescer *hostobs.Coalescer
	decoded   int
	malformed int
}

// newHostObsCollector builds a collector for one file.
//
// The coalescing window is deliberately LONG. In a live sensor the window
// trades freshness against row count; in a file there is no freshness to trade,
// the timestamps are whatever the capture holds (they may span days), and one
// row per host for the whole file is exactly what a reader wants. A window
// larger than any plausible capture makes Drain at EOF the only thing that ever
// emits.
func newHostObsCollector() *hostObsCollector {
	return &hostObsCollector{
		coalescer: hostobs.NewCoalescer(365*24*time.Hour, hostobs.DefaultCoalesceCapacity),
	}
}

// Offer classifies one packet from the file and decodes it inline.
//
// Inline rather than on a goroutine, unlike the sensor: a file is a batch job
// with no handshake reassembly waiting on the same core, so the bounded-channel
// hand-off the sensor needs would buy nothing and add a failure mode.
func (c *hostObsCollector) Offer(packet gopacket.Packet) {
	kind, payload, srcMAC, srcAddr := classifyHostObs(packet)
	if !c.decoders.Enabled(kind) {
		return
	}

	at := packet.Metadata().Timestamp
	obs, err := hostobs.Decode(kind, hostobs.Frame{
		// The payload is NOT copied. PacketSource.NoCopy is on for file
		// processing, so these bytes alias the read buffer — which is safe
		// only because the decoder runs right here and keeps nothing that
		// points back into it. Moving this call onto a goroutine would make
		// the copy mandatory.
		Payload: payload,
		SrcMAC:  srcMAC,
		SrcAddr: srcAddr,
		// Interface stays empty: a capture file has no interface the platform
		// can name, so the observations it produces carry no
		// `capture_interface` attribute rather than a fabricated one.
		At: at,
	})
	if err != nil {
		if errors.Is(err, hostobs.ErrMalformed) {
			c.malformed++
		}
		return
	}
	if obs == nil {
		return
	}
	c.decoded++
	c.coalescer.Add(obs)
}

// Discoveries drains the collector into the shape the rest of the pipeline
// carries. Called once, at end of file.
func (c *hostObsCollector) Discoveries() []CryptoDiscovery {
	merged := c.coalescer.Drain()
	out := make([]CryptoDiscovery, 0, len(merged))
	for _, obs := range merged {
		if !obs.Identifies() {
			continue
		}
		out = append(out, CryptoDiscovery{
			// dest_ip is inet NOT NULL. An observation with no address at all
			// (an LLDP frame carrying only a chassis MAC) is written as the
			// unspecified address, which the wire contract documents as "no
			// address observed; identify by MAC".
			DestIP: primaryAddress(obs),
			// port is integer NOT NULL, and a host is not an endpoint: 0 here
			// means "no port", not "port zero".
			DestPort:        0,
			Protocol:        "HOST",
			DiscoveryMethod: "pcap_upload",
			DiscoveryType:   "host_observation",
			Timestamp:       obs.ObservedAt,
			HostObservation: obs,
		})
	}
	return out
}

// primaryAddress is the address a host observation is filed under.
func primaryAddress(obs *hostobs.HostObservation) string {
	if len(obs.Addresses) > 0 {
		return obs.Addresses[0].String()
	}
	return "0.0.0.0"
}

// classifyHostObs pulls the fields shared/hostobs needs out of a gopacket
// packet and asks IT which decoder they belong to.
//
// Mirrors the sensor's function of the same name. The gopacket plumbing is
// per-runtime; the decision of which protocol matters, and on which port, is
// not — it lives in shared/hostobs, so a decoder added there reaches this path
// and the sensor's together.
func classifyHostObs(packet gopacket.Packet) (hostobs.Kind, []byte, string, netip.Addr) {
	var srcMAC string
	if eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		srcMAC = eth.SrcMAC.String()
		if kind, body := hostobs.ClassifyEther(uint16(eth.EthernetType), eth.Payload); kind != hostobs.KindNone {
			return kind, body, srcMAC, netip.Addr{}
		}
	}

	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || len(udp.Payload) == 0 {
		return hostobs.KindNone, nil, srcMAC, netip.Addr{}
	}
	kind := hostobs.ClassifyUDP(uint16(udp.SrcPort), uint16(udp.DstPort))
	if kind == hostobs.KindNone {
		return hostobs.KindNone, nil, srcMAC, netip.Addr{}
	}

	var srcAddr netip.Addr
	if nl := packet.NetworkLayer(); nl != nil {
		srcAddr, _ = netip.ParseAddr(nl.NetworkFlow().Src().String())
	}
	return kind, udp.Payload, srcMAC, srcAddr
}

// hostObsBestName picks the most specific name for the hostname column.
func hostObsBestName(obs *hostobs.HostObservation) string {
	if len(obs.FQDNs) > 0 {
		return obs.FQDNs[0]
	}
	if len(obs.Hostnames) > 0 {
		return obs.Hostnames[0]
	}
	return ""
}

// pipelineConfidence is the confidence stamped on a discovery's
// `sensor_discoveries` row.
//
// A host observation is graded by shared/hostobs — the same ladder the live
// sensor uses — because this row and a live sensor's row for the same host go
// into the same table, are read by the same auto-approval rules, and become the
// same asset. Before this, every row this function writes carried a flat 0.85,
// so replaying a capture produced a DIFFERENT confidence for a host than
// watching it live did: an LLDP advertisement graded 0.95 by the sensor arrived
// here as 0.85, and a DNS answer graded 0.60 arrived as 0.85 as well. A rule
// reading `confidence >= 0.9` fired on one and not the other, and a rule reading
// `confidence >= 0.8` fired on a DNS answer it was never meant to.
//
// Crypto discoveries keep the existing 0.85. That value is not graded by
// anything here — the PCAP path measures what it measures — and changing it
// would be a separate decision about a separate pipeline.
func pipelineConfidence(d CryptoDiscovery) float64 {
	if d.HostObservation != nil {
		return hostobs.Confidence(d.HostObservation)
	}
	return 0.85
}
