package services

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// A scan target must be a BARE host. Nothing downstream splits host from port:
// cluster-sensor's validateNmapTarget rejects ':' as an illegal character and
// the standalone sensor hands the whole string to net.LookupIP. A "host:port"
// target is therefore dropped with nothing but a log line, while the asset has
// already been stamped as freshly scanned — the classic silent success. The
// port travels in the job's Ports field instead.

// activeScanFallbackPorts are probed only when an asset records no port of its
// own. They preserve the pre-fix behaviour (TLS on 443/8443) for portless
// assets rather than widening every scan.
var activeScanFallbackPorts = []int{443, 8443}

// activeScanProbeProtocols is the set of protocols an Active Scan may request.
// It is deliberately narrow:
//   - both scan runtimes have a prober registered for TLS and SSH on any port
//     (shared/discovery probe_tls.go / probe_ssh.go);
//   - OT/ICS protocols are NOT included — those are gated by the
//     ot_active_probing tier flag via the job's separate ot_probe_protocols
//     field, and smuggling them in through Protocols would bypass that gate.
var activeScanProbeProtocols = []string{"SSH", "TLS"}

// tlsWrappedConfigProtocols maps a recorded crypto-configuration protocol onto
// the canonical "TLS" prober. Canonicalized per shareddisc.CanonicalProtocolName.
var tlsWrappedConfigProtocols = map[string]bool{
	"TLS": true, "SSL": true, "HTTPS": true,
	"LDAPS": true, "SMTPS": true, "IMAPS": true, "POP3S": true, "FTPS": true,
}

// probeableProtocol maps a protocol string recorded on a crypto configuration
// onto the protocol name an Active Scan can actually request, or "" when the
// value carries no probeable signal (e.g. "tcp", "udp", "unknown").
func probeableProtocol(protocol string) string {
	switch canonical := shareddisc.CanonicalProtocolName(protocol); {
	case canonical == "SSH":
		return "SSH"
	case tlsWrappedConfigProtocols[canonical]:
		return "TLS"
	default:
		return ""
	}
}

// scanStamp is an asset's freshness value as it stood BEFORE an Active Scan
// optimistically stamped it. Captured so a failed dispatch can restore the
// exact prior value instead of guessing one.
type scanStamp struct {
	assetID       uuid.UUID
	lastScannedAt sql.NullTime
}

// planStampRestore splits captured stamps into the two restore groups:
// assets whose last_scanned_at was NULL (restore to NULL — they were genuinely
// never scanned and belong back on the Active Scan list) and assets that had a
// real timestamp (restore that exact instant — their scan history is real and
// must not be erased by a scan that merely failed to dispatch today).
//
// Timestamps are rendered RFC3339Nano so they survive the text form of the
// ::timestamptz[] array with full precision and an explicit offset.
func planStampRestore(prior []scanStamp) (nullIDs []uuid.UUID, tsIDs []string, tsValues []string) {
	for _, stamp := range prior {
		if stamp.lastScannedAt.Valid {
			tsIDs = append(tsIDs, stamp.assetID.String())
			tsValues = append(tsValues, stamp.lastScannedAt.Time.Format(time.RFC3339Nano))
			continue
		}
		nullIDs = append(nullIDs, stamp.assetID)
	}
	return nullIDs, tsIDs, tsValues
}

// activeScanAsset is one asset resolved into probe coordinates.
type activeScanAsset struct {
	id   uuid.UUID
	host string // BARE host — an IP or hostname, never "host:port"
	port int    // 0 when the asset records no port
	// configProtocols are the protocol values already recorded against this
	// asset's crypto configurations — the best available evidence of what it
	// actually speaks.
	configProtocols []string
}

// activeScanBatch is one dispatchable discovery job: the assets that share a
// scan shape, plus the ports and protocols to probe them with.
type activeScanBatch struct {
	assetIDs  []uuid.UUID
	targets   []string
	ports     []int
	protocols []string
}

// deriveActiveScanProtocols decides what to probe an asset with, instead of
// assuming TLS. Evidence, best first:
//  1. the protocols recorded on the asset's own crypto configurations;
//  2. what its port is well known to speak (shared PortSpeaks).
//
// Falls back to TLS when nothing is known, matching
// shareddisc.ProtocolsForPort's own fallback — most crypto-bearing listeners
// speak TLS, and this is what the pre-fix code always sent.
func deriveActiveScanProtocols(port int, configProtocols []string) []string {
	seen := make(map[string]bool, 2)
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	for _, p := range configProtocols {
		add(probeableProtocol(p))
	}
	if port > 0 {
		for _, p := range activeScanProbeProtocols {
			if shareddisc.PortSpeaks(port, p) {
				add(p)
			}
		}
	}
	if len(out) == 0 {
		add("TLS")
	}

	sort.Strings(out) // deterministic — the list is also a batch grouping key
	return out
}

// maxActiveScanTargetsPerJob mirrors the 1000-target cap enforced by both
// CreateJob implementations; batches larger than this are chunked.
const maxActiveScanTargetsPerJob = 1000

// planActiveScanBatches groups assets into discovery jobs by their scan shape
// (ports × protocols).
//
// Grouping matters because cluster-sensor's CreateJob writes one target row per
// input carrying ALL of the job's protocols × ALL of its ports. Pouring every
// asset's port into one job would make the scan a cartesian product: N assets ×
// P distinct ports × Q protocols, so probing 50 assets on 10 distinct ports
// would mean 500 port probes, 450 of them against ports the asset does not even
// listen on. Grouping keeps each job homogeneous, so total probe work stays
// proportional to the number of assets (one port, one or two protocols each).
//
// Assets with no addressable host are dropped here and reported by the caller,
// which is what keeps the freshness stamp honest.
func planActiveScanBatches(assets []activeScanAsset) []activeScanBatch {
	// Accumulator for one scan shape. Assets are keyed by host because two
	// assets can share a host and port (e.g. one record per service on a box):
	// cluster-sensor writes one target row per input, so emitting the host twice
	// scans it twice for nothing. Every asset still rides along under its host —
	// each one gets stamped, and each one must land in the job that probes it.
	type shape struct {
		ports        []int
		protocols    []string
		hosts        []string // deduped, insertion-ordered
		assetsByHost map[string][]uuid.UUID
	}

	var order []string
	byKey := make(map[string]*shape)

	for _, a := range assets {
		if a.host == "" {
			continue
		}
		ports := activeScanFallbackPorts
		if a.port > 0 {
			ports = []int{a.port}
		}
		protocols := deriveActiveScanProtocols(a.port, a.configProtocols)

		key := fmt.Sprintf("%v|%s", ports, strings.Join(protocols, ","))
		sh, ok := byKey[key]
		if !ok {
			sh = &shape{
				// Copy the ports slice: for portless assets it would otherwise
				// alias the package-level activeScanFallbackPorts, handing
				// callers a struct that shares storage with a package var.
				ports:        append([]int(nil), ports...),
				protocols:    protocols,
				assetsByHost: make(map[string][]uuid.UUID),
			}
			byKey[key] = sh
			order = append(order, key)
		}
		if _, seen := sh.assetsByHost[a.host]; !seen {
			sh.hosts = append(sh.hosts, a.host)
		}
		sh.assetsByHost[a.host] = append(sh.assetsByHost[a.host], a.id)
	}

	var out []activeScanBatch
	for _, key := range order {
		sh := byKey[key]
		// Chunk on TARGET count — that is what CreateJob caps. Each chunk carries
		// the assets belonging to its own hosts, so every asset is stamped by
		// exactly the job that probes it.
		for start := 0; start < len(sh.hosts); start += maxActiveScanTargetsPerJob {
			end := start + maxActiveScanTargetsPerJob
			if end > len(sh.hosts) {
				end = len(sh.hosts)
			}
			hosts := sh.hosts[start:end]
			var assetIDs []uuid.UUID
			for _, h := range hosts {
				assetIDs = append(assetIDs, sh.assetsByHost[h]...)
			}
			out = append(out, activeScanBatch{
				assetIDs:  assetIDs,
				targets:   hosts,
				ports:     sh.ports,
				protocols: sh.protocols,
			})
		}
	}
	return out
}
