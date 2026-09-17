package hostinventory

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Platform values the collector recognises. Spelled as GOOS does, so a local
// collection can compare against runtime.GOOS without a translation table.
const (
	PlatformLinux   = "linux"
	PlatformDarwin  = "darwin"
	PlatformWindows = "windows"
)

// Options configure one collection.
type Options struct {
	// Mode is local or remote. It is recorded on the Report and emitted as the
	// agent.mode fact; it also gates the one documented local-only fallback.
	Mode Mode
	// AgentID is stamped on the Report in LOCAL mode only. Supplying it in
	// remote mode is a caller error: the agent is not the host being described.
	AgentID string
	// Platform overrides detection. Tests pin it; a caller that already knows
	// (a local collection reading runtime.GOOS) may supply it to save a probe.
	Platform string
	// Now supplies the collection timestamp. Nil means time.Now. Tests set it
	// so a golden Report is byte-stable.
	Now func() time.Time
	// LocalInterfaceFallback permits the ONE documented divergence between the
	// two modes: when `ip -j addr` cannot run, a local collection may read
	// net.Interfaces() instead. Off by default, and it only fires after the
	// command has already failed. The fallback is recorded as a step error, so
	// it is visible in the Report rather than silently papering over a gap.
	LocalInterfaceFallback bool
	// MaxPackages bounds the package list. 0 means the package-set default.
	MaxPackages int
	// MaxCertsPerStore bounds how many certificates are summarised per store.
	// 0 means the default.
	MaxCertsPerStore int
	// CollectConnections is an explicit privacy opt-in. A remote-peer list can
	// reveal browsing and application activity, so ordinary host inventory does
	// not collect it merely because the agent was upgraded.
	CollectConnections bool
	// MaxConnections bounds the coalesced remote-peer set. Zero uses the
	// package default. The local ephemeral port is excluded before this cap.
	MaxConnections int
}

const (
	defaultMaxPackages      = 20000
	defaultMaxCertsPerStore = 500
	defaultMaxConnections   = 256
	defaultMaxBoundUDP      = 256
)

func (o Options) maxPackages() int {
	if o.MaxPackages > 0 {
		return o.MaxPackages
	}
	return defaultMaxPackages
}

func (o Options) maxConnections() int {
	if o.MaxConnections > 0 {
		return o.MaxConnections
	}
	return defaultMaxConnections
}

func (o Options) maxCertsPerStore() int {
	if o.MaxCertsPerStore > 0 {
		return o.MaxCertsPerStore
	}
	return defaultMaxCertsPerStore
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// Collect runs the whole host-inventory command set through r and returns what
// it learned.
//
// It returns a Report and an error only when nothing at all could be
// established — a transport that will not answer, or a platform it cannot
// recognise. Every other failure is a SECTION failure: the Report comes back
// with that section empty, Sections[section] == SectionFailed and an entry in
// Errors. A partial inventory is worth having; a partial inventory that reads
// as a complete one is not, which is what Sections exists to prevent.
func Collect(ctx context.Context, r Runner, opts Options) (*Report, error) {
	if r == nil {
		return nil, fmt.Errorf("hostinventory: nil runner")
	}
	if opts.Mode == "" {
		opts.Mode = ModeLocal
	}
	rep := &Report{
		Collected: opts.now(),
		Mode:      opts.Mode,
		Sections:  make(map[string]string),
	}
	// The agent's own id identifies the agent's own host and nothing else.
	// Stamping it on a remote target's report would hand two assets one
	// identity, which is the merge bug the identification engine cannot undo.
	if opts.Mode == ModeLocal {
		rep.AgentID = opts.AgentID
	}

	platform := opts.Platform
	if platform == "" {
		detected, err := DetectPlatform(ctx, r)
		if err != nil {
			rep.fail(SectionPlatformDet, err)
			return rep, fmt.Errorf("hostinventory: could not determine the target platform: %w", err)
		}
		platform = detected
	}
	rep.Platform = platform
	rep.mark(SectionPlatformDet, SectionOK)

	switch platform {
	case PlatformLinux:
		collectLinux(ctx, r, rep, opts)
	case PlatformDarwin:
		collectDarwin(ctx, r, rep, opts)
	case PlatformWindows:
		collectWindows(ctx, r, rep, opts)
	default:
		return rep, fmt.Errorf("hostinventory: unsupported platform %q", platform)
	}

	return rep, nil
}

// DetectPlatform asks the target what it is.
//
// `uname -s` first because it answers on Linux and macOS and is absent on
// Windows; a PowerShell probe second. Both transports run the same two probes
// in the same order, so detection cannot be the thing that makes local and
// remote disagree.
func DetectPlatform(ctx context.Context, r Runner) (string, error) {
	out, _, exit, err := r.Run(ctx, []string{"uname", "-s"})
	if err == nil && exit == 0 {
		switch strings.ToLower(strings.TrimSpace(string(out))) {
		case "linux":
			return PlatformLinux, nil
		case "darwin":
			return PlatformDarwin, nil
		}
	}

	// No uname, or an answer we do not know. Ask PowerShell.
	psOut, _, psExit, psErr := r.Run(ctx, powershellArgv(`Write-Output $PSVersionTable.Platform`))
	if psErr == nil && psExit == 0 {
		// Windows PowerShell 5.1 leaves $PSVersionTable.Platform unset, so an
		// EMPTY answer from a command that SUCCEEDED is itself the Windows
		// signal. PowerShell 7 on Windows answers "Win32NT".
		v := strings.TrimSpace(string(psOut))
		if v == "" || strings.EqualFold(v, "Win32NT") {
			return PlatformWindows, nil
		}
		// PowerShell 7 on Unix answers "Unix" — but uname answered first there,
		// so reaching this means uname is missing on a Unix host. Say so rather
		// than claiming Windows.
		return "", fmt.Errorf("hostinventory: target reports PowerShell platform %q but has no usable uname", v)
	}

	if err != nil {
		return "", fmt.Errorf("uname: %w", err)
	}
	return "", fmt.Errorf("uname exited %d and no PowerShell host answered", exit)
}

// runText runs a command and returns its trimmed stdout, or an error when the
// transport failed or the command exited non-zero.
//
// A non-zero exit is turned into an error HERE rather than in the Runner
// because at this level it means "this step produced nothing usable", which is
// exactly a step failure. The Runner keeps the distinction so a caller that
// wants to treat exit 1 as an answer still can — probeCommand does.
func runText(ctx context.Context, r Runner, argv []string) (string, error) {
	out, errOut, exit, err := r.Run(ctx, argv)
	if err != nil {
		return "", fmt.Errorf("%s: %w", argv[0], err)
	}
	if exit != 0 {
		msg := strings.TrimSpace(string(errOut))
		if msg == "" {
			msg = "no stderr"
		}
		if len(msg) > maxErrorMessage {
			msg = msg[:maxErrorMessage]
		}
		return "", fmt.Errorf("%s exited %d: %s", argv[0], exit, msg)
	}
	return string(out), nil
}

// commandPresent reports whether a command exists and answered, without
// treating its absence as a failure. Used where several package managers are
// possible and only one of them is the right answer for the host.
func commandPresent(ctx context.Context, r Runner, argv []string) (string, bool) {
	out, _, exit, err := r.Run(ctx, argv)
	if err != nil || exit != 0 {
		return "", false
	}
	return string(out), true
}

// localInterfaces reads the host's own interfaces through net.Interfaces().
//
// The ONE place this package consults the local machine rather than the
// Runner, permitted only in local mode, only behind an explicit option, and
// only after `ip -j addr` has already failed. Every other divergence between
// the two modes would be a bug.
func localInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifaces))
	for _, ifc := range ifaces {
		entry := Interface{
			Name:    ifc.Name,
			MAC:     normaliseMAC(ifc.HardwareAddr.String()),
			State:   interfaceState(ifc.Flags&net.FlagUp != 0),
			Virtual: isVirtualInterface(ifc.Name, ifc.Flags&net.FlagLoopback != 0),
		}
		addrs, addrErr := ifc.Addrs()
		if addrErr == nil {
			for _, a := range addrs {
				entry.Addresses = append(entry.Addresses, a.String())
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

func interfaceState(up bool) string {
	if up {
		return "up"
	}
	return "down"
}
