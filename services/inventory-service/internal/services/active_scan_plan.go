package services

import (
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
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

// No protocol is chosen here. An Active Scan is a planned job on the shared
// scan engine ( WP4), which identifies the service from what answers on
// each port: it reads a banner, sends at most one TLS hello to a silent port,
// and runs the SSH handshake only when the banner says SSH (spec V7). OT/ICS
// probes run only through a job's explicit ot_probe_protocols opt-in, which an
// Active Scan never sends.

// activeScanAsset is one asset resolved into probe coordinates.
type activeScanAsset struct {
	id   uuid.UUID
	name string // what a person calls it: the hostname, else the host
	host string // BARE host — an IP or hostname, never "host:port"
	port int    // 0 when the asset records no port
	// sni are the names the asset is known by, offered as SNI to a TLS port of
	// its address that refuses a nameless handshake (autoscan.SNICandidates).
	sni []string
}

// activeScanBatch is one dispatchable discovery job: the assets that share a
// port list, plus those ports.
type activeScanBatch struct {
	assetIDs []uuid.UUID
	targets  []string
	ports    []int
	// assetsByHost keys the same assets by target host, so a batch split
	// across executors stamps each asset by the job that actually
	// probes its host.
	assetsByHost map[string][]uuid.UUID
	// sniByHost is the names to offer for each target that is an ADDRESS (a
	// hostname target presents its own name already): the union over the assets
	// sharing it, bounded.
	sniByHost map[string][]string
}

// subset returns the part of this batch covering only the given hosts.
func (b activeScanBatch) subset(hosts []string) activeScanBatch {
	out := activeScanBatch{ports: b.ports, assetsByHost: make(map[string][]uuid.UUID, len(hosts)), sniByHost: map[string][]string{}}
	for _, h := range hosts {
		if names, ok := b.sniByHost[h]; ok {
			out.sniByHost[h] = names
		}
		assets, ok := b.assetsByHost[h]
		if !ok {
			continue
		}
		out.targets = append(out.targets, h)
		out.assetIDs = append(out.assetIDs, assets...)
		out.assetsByHost[h] = assets
	}
	return out
}

// maxActiveScanTargetsPerJob mirrors the 1000-target cap enforced by both
// CreateJob implementations; batches larger than this are chunked.
const maxActiveScanTargetsPerJob = 1000

// planActiveScanBatches groups assets into discovery jobs by their port list.
//
// Grouping matters because a job scans ALL of its ports on EVERY target.
// Pouring every asset's port into one job would make the scan a cartesian
// product: probing 50 assets on 10 distinct ports would mean 500 port probes,
// 450 of them against ports the asset does not even listen on. Grouping keeps
// each job homogeneous, so total probe work stays proportional to the number
// of assets (one port each, or the two fallback ports).
//
// Assets with no addressable host are dropped here and reported by the caller,
// which is what keeps the freshness stamp honest.
func planActiveScanBatches(assets []activeScanAsset) []activeScanBatch {
	// Accumulator for one port list. Assets are keyed by host because two
	// assets can share a host and port (e.g. one record per service on a box):
	// cluster-sensor writes one target row per input, so emitting the host twice
	// scans it twice for nothing. Every asset still rides along under its host —
	// each one gets stamped, and each one must land in the job that probes it.
	type shape struct {
		ports        []int
		hosts        []string // deduped, insertion-ordered
		assetsByHost map[string][]uuid.UUID
		sniByHost    map[string][]string
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

		key := fmt.Sprintf("%v", ports)
		sh, ok := byKey[key]
		if !ok {
			sh = &shape{
				// Copy the ports slice: for portless assets it would otherwise
				// alias the package-level activeScanFallbackPorts, handing
				// callers a struct that shares storage with a package var.
				ports:        append([]int(nil), ports...),
				assetsByHost: make(map[string][]uuid.UUID),
				sniByHost:    make(map[string][]string),
			}
			byKey[key] = sh
			order = append(order, key)
		}
		if _, seen := sh.assetsByHost[a.host]; !seen {
			sh.hosts = append(sh.hosts, a.host)
		}
		sh.assetsByHost[a.host] = append(sh.assetsByHost[a.host], a.id)
		if len(a.sni) > 0 && net.ParseIP(a.host) != nil {
			sh.sniByHost[a.host] = autoscan.MergeSNICandidates(sh.sniByHost[a.host], a.sni)
		}
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
			byHost := make(map[string][]uuid.UUID, len(hosts))
			sniByHost := map[string][]string{}
			for _, h := range hosts {
				assetIDs = append(assetIDs, sh.assetsByHost[h]...)
				byHost[h] = sh.assetsByHost[h]
				if names, ok := sh.sniByHost[h]; ok {
					sniByHost[h] = names
				}
			}
			out = append(out, activeScanBatch{
				assetIDs:     assetIDs,
				targets:      hosts,
				ports:        sh.ports,
				assetsByHost: byHost,
				sniByHost:    sniByHost,
			})
		}
	}
	return out
}

// activeScanJobOptions builds the probe options an Active Scan job carries.
//
// It deliberately does NOT carry result_sink="sensor_discoveries". That option
// used to be what routed a job's findings into the ingestion queue, and Active
// Scan was the only caller that ever set it — so every other discovery job's
// findings never reached inventory without a browser posting them back.
// cluster-sensor now mirrors EVERY job unconditionally, which makes the option
// inert, so it is gone rather than left as a switch that no longer switches
// anything.
//
// active_scan survives because it still does something: it stamps provenance
// (discovery_source) on the mirrored rows. It does not gate the mirror.
func activeScanJobOptions() map[string]interface{} {
	return map[string]interface{}{
		"active_scan": true,
	}
}
