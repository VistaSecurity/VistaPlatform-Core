package paritytest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
)

// Golden is the ground truth for one case: the findings a complete scan of
// that listener should persist, restricted to the fields the fixture controls
// and so can state without running any path. Keys are the Normalize namespace.
//
//   - TLS: one TLS finding with the negotiated (highest) version, EVERY version
//     the server accepts, the pinned cipher suite where the fixture pins one,
//     the served chain's fingerprints in chain order, a validation status of
//     untrusted_ca (the chain anchors in the fixture's own root; the probe
//     targets an IP, so a hostname mismatch would be a wrong answer), and
//     server_requests_client_cert=true when the server asks for one — under
//     the key the sensor's TLS enricher already writes it with; and the two
//     key-exchange support flags (classical always true; PQC hybrid true for
//     a TLS 1.3 server that keeps Go's default hybrid group).
//   - SSH: one SSH finding with the fixture's banner, host key type and
//     fingerprint.
//   - closed and silent ports: no crypto finding.
func Golden(c *Case) map[string]Fields {
	switch c.Kind {
	case KindTLS:
		f := Fields{
			"row.protocol":                strconv.Quote(cryptoparse.NormalizeProtocol("TLS")),
			"meta.version":                js(discovery.TLSVersionName(c.TLSMax)),
			"meta.tls_versions":           js(acceptedVersions(c.TLSMin, c.TLSMax)),
			"meta.cert_validation_status": js("untrusted_ca"),
		}
		if c.CipherSuite != 0 {
			f["meta.cipher_suite"] = js(discovery.CipherSuiteName(c.CipherSuite))
		}
		for i, fp := range c.ChainSHA256 {
			f["cert["+strconv.Itoa(i)+"].fingerprint_sha256"] = js(fp)
			f["cert["+strconv.Itoa(i)+"].chain_order"] = js(i)
		}
		if c.ClientCertAsked {
			f["meta.server_requests_client_cert"] = js(true)
		}
		// Every fixture TLS server accepts a classical group (X25519 and P-256
		// are always on); a TLS 1.3 server supports the hybrid group unless the
		// case removed it, and a TLS 1.2-only server cannot use it at all.
		f["meta.tls_supports_classical_kex"] = js(true)
		f["meta.tls_supports_pqc_hybrid_kex"] = js(c.TLSMax == tls.VersionTLS13 && !c.ClassicalKexOnly)
		return map[string]Fields{f["row.protocol"]: f}
	case KindSSH:
		f := Fields{
			"row.protocol":                  strconv.Quote(cryptoparse.NormalizeProtocol("SSH")),
			"meta.ssh_banner":               js(SSHServerVersion),
			"meta.ssh_host_key_type":        js(c.HostKeyType),
			"meta.ssh_host_key_fingerprint": js(c.HostKeyFingerprint),
		}
		return map[string]Fields{f["row.protocol"]: f}
	}
	return nil
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// acceptedVersions lists the versions a server configured min..max accepts,
// highest first — the order the legacy enumeration reports them in.
func acceptedVersions(lo, hi uint16) []string {
	var out []string
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
		if v >= lo && v <= hi {
			out = append(out, discovery.TLSVersionName(v))
		}
	}
	return out
}

// ParityJobID is the job every path's rows are attributed to. The engine and
// the Platform Sensor stamp it as metadata job_id through
// jobunits.MirrorMetadata; the legacy sensor stamps the job it ran. One value,
// so the key compares equal and only its presence matters.
const ParityJobID = "parity-job"

// RunEngine runs the shared engine — exactly as a planned job's unit runs on
// either runtime: UnitEngine at the normal pace, no OT opt-in — against ports
// on addr, and returns the rows it would mirror into sensor_discoveries
// (jobunits.Findings → MirrorMetadata under ParityJobID, stamped as an Active
// Scan: every caller the legacy paths serve sets the active_scan option, and
// the legacy sensor stamps every job that way). guard is the outbound fetch
// guard: the Platform Sensor's work units pass dispatchguard.PlatformFetchGuard,
// a tenant sensor passes nil.
func RunEngine(ctx context.Context, addr string, ports []int, guard discovery.AddressGuard) ([]Persisted, time.Duration, error) {
	start := time.Now()
	eng, err := discovery.NewUnitEngine(discovery.PaceNormal, nil, guard)
	if err != nil {
		return nil, 0, err
	}
	ps, err := discovery.NewPortSet(ports...)
	if err != nil {
		return nil, 0, err
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, 0, err
	}
	out, err := eng.Run(ctx, discovery.UnitInput{Addr: a, TCP: ps})
	if err != nil {
		return nil, 0, err
	}
	elapsed := time.Since(start)
	var rows []Persisted
	for _, f := range jobunits.Findings(addr, "", out) {
		if !f.Mirror {
			continue
		}
		rows = append(rows, Persisted{
			Protocol: f.Protocol, Port: f.Port, Confidence: f.Confidence, Hostname: f.Hostname,
			Metadata: jobunits.MirrorMetadata(f.Data, true, ParityJobID),
		})
	}
	return rows, elapsed, nil
}
