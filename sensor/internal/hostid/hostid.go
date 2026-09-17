// Package hostid builds the sensor's own host identity — the block reported
// on registration and (throttled) on heartbeat so sensor-manager can turn the
// host the sensor runs ON into a named, classed asset instead of the
// anonymous `unknown_host` a passive ARP/mDNS observation of it produces
// (asset-inventory decision 9, morning notes).
//
// Everything here is pure Go and CGO-free, like every package the sensor
// cross-compiles with libpcap disabled (CLAUDE.md, "Shared x509 extraction").
// os.Hostname(), runtime.GOOS/GOARCH and net.Interfaces() are all stdlib calls
// available on every platform the sensor ships for.
package hostid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// fqdnLookupTimeout bounds the one background resolution this package ever
// does. It must never be on the heartbeat's critical path — a heartbeat fires
// every ReportingInterval (default 30s) and a sensor blocked in a DNS lookup
// for even a few seconds on a segment with a slow or unreachable resolver
// would fall behind its own cadence.
const fqdnLookupTimeout = 3 * time.Second

var (
	fqdnMu      sync.RWMutex
	fqdnCache   string
	fqdnStarted sync.Once
)

// StartFQDNResolution kicks off a one-shot, best-effort FQDN lookup in the
// background. Call it once, at sensor startup (a second call is a no-op).
// Until it completes — or if it never succeeds, which is the common case for
// a host with no reverse/forward DNS entry — [Build] reports FQDN as "",
// which is a true statement ("no qualified name could be resolved cheaply"),
// not a placeholder.
func StartFQDNResolution() {
	fqdnStarted.Do(func() {
		go func() {
			if fqdn := resolveFQDN(); fqdn != "" {
				fqdnMu.Lock()
				fqdnCache = fqdn
				fqdnMu.Unlock()
			}
		}()
	})
}

// CachedFQDN returns whatever [StartFQDNResolution] has resolved so far. Safe
// to call before StartFQDNResolution or before it finishes; both return "".
func CachedFQDN() string {
	fqdnMu.RLock()
	defer fqdnMu.RUnlock()
	return fqdnCache
}

// resolveFQDN tries a CNAME lookup of the local hostname, bounded by
// fqdnLookupTimeout. Most hosts on a private segment have no CNAME for their
// own short name, in which case the resolver returns the name unchanged (no
// dot beyond the TLD) or an error; either way this returns "" rather than
// reporting the short name back as if it were qualified.
func resolveFQDN() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), fqdnLookupTimeout)
	defer cancel()

	cname, err := net.DefaultResolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return ""
	}
	cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if cname == "" || !strings.Contains(cname, ".") {
		return ""
	}
	return cname
}

// Build assembles a fresh HostIdentity. primaryIP is the same hint
// shared/network.HostAddresses already takes elsewhere in the sensor (the
// address the kernel uses to reach the control plane), so the flagged primary
// interface here matches the one the heartbeat's own Interfaces field flags.
//
// Everything except FQDN is computed fresh and is cheap: os.Hostname() and
// net.Interfaces() are local syscalls, never DNS. FQDN comes from the
// package-level cache [StartFQDNResolution] fills in the background.
func Build(primaryIP string) *models.HostIdentity {
	hostname, _ := os.Hostname()
	return &models.HostIdentity{
		Hostname:   strings.TrimSpace(hostname),
		FQDN:       CachedFQDN(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Interfaces: sharednetwork.HostAddresses(primaryIP),
	}
}

// Hash renders a stable fingerprint of a HostIdentity for the heartbeat's
// own throttle (send the block again only when it changed, or an hour has
// passed — see cmd/main.go's sendHeartbeat). nil hashes the same as an empty
// identity, so a sensor that has never built one and one that built an empty
// one compare equal.
//
// Interfaces is sorted onto a copy before marshalling: net.Interfaces()
// ordering is OS-defined and has been observed to vary between calls on the
// same unchanged host, which would otherwise make the hash flap and defeat
// the throttle it exists to drive.
func Hash(h *models.HostIdentity) string {
	if h == nil {
		h = &models.HostIdentity{}
	}
	sorted := *h
	if len(h.Interfaces) > 0 {
		sorted.Interfaces = append([]sharednetwork.InterfaceAddress(nil), h.Interfaces...)
		sort.Slice(sorted.Interfaces, func(i, j int) bool {
			a, b := sorted.Interfaces[i], sorted.Interfaces[j]
			if a.Address != b.Address {
				return a.Address < b.Address
			}
			return a.InterfaceName < b.InterfaceName
		})
	}
	blob, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
