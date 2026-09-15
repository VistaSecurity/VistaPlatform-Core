package hostinventory

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// The macOS command set.
var (
	darwinCmdSwVers   = []string{"sw_vers"}
	darwinCmdKernel   = []string{"uname", "-r"}
	darwinCmdNodename = []string{"uname", "-n"}
	darwinCmdHostname = []string{"hostname", "-f"}

	darwinCmdHardware = []string{"system_profiler", "SPHardwareDataType", "-json"}

	darwinCmdPkgutil = []string{"pkgutil", "--pkgs"}
	darwinCmdApps    = []string{"find", "/Applications", "-maxdepth", "3", "-name", "Info.plist", "-type", "f"}

	darwinCmdLsof     = []string{"lsof", "-nP", "-iTCP", "-sTCP:LISTEN"}
	darwinCmdIfconfig = []string{"ifconfig", "-a"}
)

// darwinCertStorePaths are the FILE-based trust stores macOS exposes.
//
// The System and login Keychains are deliberately NOT read. Reading a keychain
// means `security` prompting for, or being granted, access to a store that also
// holds private keys and passwords — a different capability with a different
// risk profile, and not one a host inventory needs to take on.
var darwinCertStorePaths = []string{
	"/etc/ssl/cert.pem",
	"/private/etc/ssl/certs",
}

// maxDarwinApps bounds the /Applications scan — one ReadFile per bundle.
const maxDarwinApps = 250

func collectDarwin(ctx context.Context, r Runner, rep *Report, opts Options) {
	collectDarwinHost(ctx, r, rep)
	collectDarwinHardware(ctx, r, rep)
	collectDarwinInterfaces(ctx, r, rep, opts)
	collectDarwinPackages(ctx, r, rep, opts)
	collectDarwinListeners(ctx, r, rep)
	collectCertStoresUnix(ctx, r, rep, darwinCertStorePaths, opts)
}

func collectDarwinHost(ctx context.Context, r Runner, rep *Report) {
	var problems []string

	if out, err := runText(ctx, r, darwinCmdSwVers); err == nil {
		name, version, build := ParseSwVers([]byte(out))
		rep.Host.OS = name
		rep.Host.OSVersion = version
		// The build is the identifier beneath the marketing version — the same
		// role the kernel release plays on Linux — but the kernel release is
		// what os.kernel is registered to mean, so the build rides in neither
		// place unless uname fails.
		if build != "" && rep.Host.Kernel == "" {
			rep.Host.Kernel = build
		}
	} else {
		problems = append(problems, err.Error())
	}

	if out, err := runText(ctx, r, darwinCmdKernel); err == nil {
		rep.Host.Kernel = strings.TrimSpace(out)
	} else {
		problems = append(problems, err.Error())
	}

	if out, err := runText(ctx, r, darwinCmdNodename); err == nil {
		// macOS nodenames commonly carry ".local" from mDNS. Keep the short
		// name here; the FQDN probe below decides whether there is a real one.
		short, _ := splitFQDN(strings.TrimSpace(out))
		rep.Host.Hostname = short
	} else {
		problems = append(problems, err.Error())
	}

	if out, err := runText(ctx, r, darwinCmdHostname); err == nil {
		if short, domain := splitFQDN(out); domain != "" && !strings.EqualFold(domain, "local") {
			// ".local" is mDNS, not a DNS domain. Recording it as an FQDN would
			// give every Mac on every network the same domain.
			rep.Host.FQDN = short + "." + domain
			rep.Host.Domain = domain
		}
	}

	if len(problems) > 0 {
		rep.fail(SectionHost, errors.New(strings.Join(problems, "; ")))
		return
	}
	rep.mark(SectionHost, SectionOK)
}

// ParseSwVers parses `sw_vers` key/value output.
func ParseSwVers(b []byte) (name, version, build string) {
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ProductName":
			name = value
		case "ProductVersion":
			version = value
		case "BuildVersion":
			build = value
		}
	}
	return name, version, build
}

// darwinHardware mirrors the shape `system_profiler SPHardwareDataType -json`
// returns. Typed, with json tags, so every field Apple adds is discarded
// structurally — the cloud collectors are safe for exactly this reason.
type darwinHardware struct {
	SPHardwareDataType []struct {
		MachineModel  string `json:"machine_model"`
		MachineName   string `json:"machine_name"`
		ModelNumber   string `json:"model_number"`
		SerialNumber  string `json:"serial_number"`
		PlatformUUID  string `json:"platform_UUID"`
		ProvisionUDID string `json:"provisioning_UDID"`
		BootROM       string `json:"boot_rom_version"`
	} `json:"SPHardwareDataType"`
}

func collectDarwinHardware(ctx context.Context, r Runner, rep *Report) {
	out, err := runText(ctx, r, darwinCmdHardware)
	if err != nil {
		rep.fail(SectionHardware, err)
		return
	}
	hw, perr := ParseDarwinHardware([]byte(out))
	if perr != nil {
		rep.fail(SectionHardware, perr)
		return
	}
	rep.Hardware = hw
	rep.mark(SectionHardware, SectionOK)
}

// ParseDarwinHardware projects system_profiler's hardware block.
//
// provisioning_UDID is deliberately not collected. It is a per-device
// enrolment identifier that ties the machine to an MDM tenancy, and the
// platform UUID and serial already identify the machine.
func ParseDarwinHardware(b []byte) (Hardware, error) {
	var raw darwinHardware
	if err := json.Unmarshal(b, &raw); err != nil {
		return Hardware{}, fmt.Errorf("system_profiler: %w", err)
	}
	if len(raw.SPHardwareDataType) == 0 {
		return Hardware{}, errors.New("system_profiler returned no hardware entry")
	}
	e := raw.SPHardwareDataType[0]
	model := strings.TrimSpace(e.MachineName)
	if model == "" {
		model = strings.TrimSpace(e.MachineModel)
	}
	return Hardware{
		// Every machine running macOS is Apple hardware. This is a derived
		// value, not a measured one, and it is marked as such where the fact is
		// emitted (ConfidenceDerived in observations.go).
		Vendor:   "Apple Inc.",
		Model:    model,
		Serial:   sanitiseDMI(e.SerialNumber),
		UUID:     sanitiseDMI(e.PlatformUUID),
		Firmware: strings.TrimSpace(e.BootROM),
	}, nil
}

func collectDarwinInterfaces(ctx context.Context, r Runner, rep *Report, opts Options) {
	out, err := runText(ctx, r, darwinCmdIfconfig)
	if err == nil {
		rep.Interfaces = ParseIfconfig([]byte(out))
		rep.mark(SectionInterfaces, SectionOK)
		return
	}
	if opts.Mode == ModeLocal && opts.LocalInterfaceFallback {
		if ifaces, lerr := localInterfaces(); lerr == nil {
			rep.Interfaces = ifaces
			rep.mark(SectionInterfaces, SectionOK)
			rep.Errors = append(rep.Errors, StepError{
				Step:    SectionInterfaces,
				Message: fmt.Sprintf("ifconfig unavailable (%v); used the local net.Interfaces() fallback", err),
			})
			return
		}
	}
	rep.fail(SectionInterfaces, err)
}

// ParseIfconfig parses BSD `ifconfig -a` output.
func ParseIfconfig(b []byte) []Interface {
	var out []Interface
	var cur *Interface
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			name, rest, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			cur = &Interface{
				Name:    strings.TrimSpace(name),
				State:   "unknown",
				Virtual: isVirtualInterface(name, strings.Contains(rest, "LOOPBACK")),
			}
			continue
		}
		if cur == nil {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "ether", "lladdr":
			cur.MAC = normaliseMAC(f[1])
		case "inet":
			// `inet 198.51.100.10 netmask 0xffffff00 broadcast ...`
			cur.Addresses = append(cur.Addresses, f[1]+maskSuffix(f))
		case "inet6":
			addr := f[1]
			if z := strings.Index(addr, "%"); z >= 0 {
				addr = addr[:z]
			}
			cur.Addresses = append(cur.Addresses, addr+prefixlenSuffix(f))
		case "status:":
			switch strings.TrimSpace(f[1]) {
			case "active":
				cur.State = "up"
			case "inactive":
				cur.State = "down"
			}
		}
	}
	flush()
	return out
}

// maskSuffix turns ifconfig's `netmask 0xffffff00` into "/24". An unparseable
// mask yields no suffix: /32 would claim the interface serves one host and /24
// would invent a segment, and both are statements the host did not make.
func maskSuffix(fields []string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] != "netmask" {
			continue
		}
		raw := strings.TrimPrefix(fields[i+1], "0x")
		v, err := strconv.ParseUint(raw, 16, 32)
		if err != nil {
			return ""
		}
		bits := 0
		for b := 31; b >= 0; b-- {
			if v&(1<<uint(b)) == 0 {
				break
			}
			bits++
		}
		return "/" + strconv.Itoa(bits)
	}
	return ""
}

// prefixlenSuffix turns ifconfig's `prefixlen 64` into "/64".
func prefixlenSuffix(fields []string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "prefixlen" {
			if _, err := strconv.Atoi(fields[i+1]); err == nil {
				return "/" + fields[i+1]
			}
			return ""
		}
	}
	return ""
}

func collectDarwinPackages(ctx context.Context, r Runner, rep *Report, opts Options) {
	var pkgs []Package
	var problems []string

	// Receipts: every installer package that has ever been applied. Names only
	// — `pkgutil --pkgs` prints no version, and asking for one is a command per
	// package. An absent version is honest; a fabricated one is not.
	if out, err := runText(ctx, r, darwinCmdPkgutil); err == nil {
		pkgs = append(pkgs, ParsePkgutil([]byte(out))...)
	} else {
		problems = append(problems, err.Error())
	}

	// Applications: the bundles a user would name if asked what is installed.
	if out, err := runText(ctx, r, darwinCmdApps); err == nil {
		plists := strings.Split(strings.TrimSpace(out), "\n")
		binary := 0
		for i, p := range plists {
			p = strings.TrimSpace(p)
			if p == "" || i >= maxDarwinApps {
				continue
			}
			b, rerr := r.ReadFile(ctx, p)
			if rerr != nil {
				continue
			}
			app, ok := ParseInfoPlist(b, p)
			if !ok {
				// A binary plist. Recorded as a count, not decoded: a bplist
				// parser is a real dependency and guessing at the bytes is
				// worse than saying how many were skipped.
				binary++
				continue
			}
			pkgs = append(pkgs, app)
		}
		if binary > 0 {
			problems = append(problems, fmt.Sprintf("%d /Applications Info.plist files are binary plists and were not decoded", binary))
		}
	} else {
		problems = append(problems, err.Error())
	}

	rep.Packages = capPackages(pkgs, opts.maxPackages())
	if len(pkgs) == 0 && len(problems) > 0 {
		rep.fail(SectionPackages, errors.New(strings.Join(problems, "; ")))
		return
	}
	rep.mark(SectionPackages, SectionOK)
	if len(problems) > 0 {
		rep.Errors = append(rep.Errors, StepError{Step: SectionPackages, Message: strings.Join(problems, "; ")})
	}
}

// ParsePkgutil parses `pkgutil --pkgs`, one receipt id per line.
func ParsePkgutil(b []byte) []Package {
	var out []Package
	for _, line := range strings.Split(string(b), "\n") {
		id := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if id == "" {
			continue
		}
		out = append(out, Package{Name: id, Manager: "pkgutil"})
	}
	return out
}

// plistDict is the minimal XML plist shape: a flat <dict> of alternating
// <key> and value elements.
type plistDict struct {
	Dict struct {
		Keys   []string `xml:"key"`
		Values []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"dict"`
}

// ParseInfoPlist reads CFBundleName and CFBundleShortVersionString from an
// application's XML Info.plist. ok is false for a binary plist.
//
// Only three keys are read. An Info.plist is a whole application manifest —
// entitlements, URL schemes, bundled tool paths — and none of that is a
// software inventory.
func ParseInfoPlist(b []byte, path string) (Package, bool) {
	if strings.HasPrefix(string(b[:min(8, len(b))]), "bplist") {
		return Package{}, false
	}
	var doc plistDict
	if err := xml.Unmarshal(b, &doc); err != nil {
		return Package{}, false
	}

	// <key> and its value alternate, but the parser collects them into two
	// slices; the value at index i belongs to the key at index i only when the
	// dict is flat, which an Info.plist's top level is.
	get := func(want string) string {
		for i, k := range doc.Dict.Keys {
			if k == want && i < len(doc.Dict.Values) {
				return strings.TrimSpace(doc.Dict.Values[i].Value)
			}
		}
		return ""
	}

	name := get("CFBundleName")
	if name == "" {
		// Fall back to the bundle directory name — "Safari.app" → "Safari".
		// Derived from the path the find returned, not invented.
		app := filepath.Base(filepath.Dir(filepath.Dir(path)))
		name = strings.TrimSuffix(app, ".app")
	}
	if name == "" {
		return Package{}, false
	}
	version := get("CFBundleShortVersionString")
	if version == "" {
		version = get("CFBundleVersion")
	}
	return Package{
		Name:    name,
		Version: version,
		Vendor:  get("CFBundleIdentifier"),
		Manager: "macos_app",
	}, true
}

func collectDarwinListeners(ctx context.Context, r Runner, rep *Report) {
	out, ok := commandPresent(ctx, r, darwinCmdLsof)
	if !ok {
		rep.fail(SectionListeners, errors.New("lsof produced no usable output"))
		return
	}
	rep.Listeners = ParseLsof([]byte(out))
	rep.mark(SectionListeners, SectionOK)
}

// ParseLsof parses `lsof -nP -iTCP -sTCP:LISTEN`.
//
// Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME, where NAME is
// "addr:port (LISTEN)".
func ParseLsof(b []byte) []Listener {
	var out []Listener
	seen := make(map[string]bool)
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		if i == 0 && strings.EqualFold(f[0], "COMMAND") {
			continue
		}
		addr, port, ok := splitHostPortSuffix(strings.TrimSuffix(f[8], "(LISTEN)"))
		if !ok {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		// lsof prints one row per file descriptor, so a server listening on two
		// descriptors of the same socket appears twice.
		key := fmt.Sprintf("%s|%d|%d", addr, port, pid)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Listener{Proto: "tcp", Address: addr, Port: port, Process: f[0], PID: pid})
	}
	return out
}
