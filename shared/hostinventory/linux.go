package hostinventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The Linux command set, in one table so the operator documentation and the
// code cannot disagree about what runs on a customer host.
//
// Every entry is read-only and none takes an argument from outside this file.
// `rpm -qa` is an EXEC, not an rpmdb read: parsing the Berkeley/sqlite database
// directly would need cgo and would break on the next rpm format change.
var (
	linuxCmdKernel   = []string{"uname", "-r"}
	linuxCmdNodename = []string{"uname", "-n"}
	linuxCmdFQDN     = []string{"hostname", "-f"}

	linuxCmdDpkg = []string{"dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\t${Maintainer}\\n"}
	linuxCmdRPM  = []string{"rpm", "-qa", "--queryformat=%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n"}
	linuxCmdAPK  = []string{"apk", "info", "-v"}

	linuxCmdSS          = []string{"ss", "-ltnup"}
	linuxCmdConnections = []string{"ss", "-tnup"}
	linuxCmdIPJ         = []string{"ip", "-j", "addr"}
	linuxCmdArch        = []string{"uname", "-m"}
)

// linuxOSReleasePath is the file that names the distribution. Every systemd-era
// distribution has it, including Alpine.
const linuxOSReleasePath = "/etc/os-release"

// linuxDMIPaths are the SMBIOS fields exposed by the kernel.
//
// product_serial and product_uuid are mode 0400 root-only on every mainstream
// distribution. An agent running unprivileged simply cannot read them, and the
// correct outcome is an ABSENT fact — never an empty string, and never a value
// derived from something else. A serial that is "" for every unprivileged host
// would collapse the whole estate onto one identity.
var linuxDMIPaths = map[string]string{
	"vendor":   "/sys/class/dmi/id/sys_vendor",
	"model":    "/sys/class/dmi/id/product_name",
	"serial":   "/sys/class/dmi/id/product_serial",
	"uuid":     "/sys/class/dmi/id/product_uuid",
	"firmware": "/sys/class/dmi/id/bios_version",
}

// linuxCertStorePaths are the file-based trust stores. DIRECTORIES ONLY — there
// is no NSS/PKCS enumeration here, because reading a token store is a
// different capability with a different risk profile.
var linuxCertStorePaths = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
}

// linuxProcNetTCP are the fallback sources when `ss` is unavailable — a
// minimal container image very often has neither ss nor netstat.
var linuxProcNetTCP = []string{"/proc/net/tcp", "/proc/net/tcp6"}
var linuxProcNetUDP = []string{"/proc/net/udp", "/proc/net/udp6"}

func collectLinux(ctx context.Context, r Runner, rep *Report, opts Options) {
	collectLinuxHost(ctx, r, rep)
	collectLinuxHardware(ctx, r, rep)
	collectLinuxInterfaces(ctx, r, rep, opts)
	collectLinuxPackages(ctx, r, rep, opts)
	collectLinuxListeners(ctx, r, rep)
	collectLinuxConnections(ctx, r, rep, opts)
	collectCertStoresUnix(ctx, r, rep, linuxCertStorePaths, opts)
}

func collectLinuxHost(ctx context.Context, r Runner, rep *Report) {
	var problems []string

	osRelease, err := r.ReadFile(ctx, linuxOSReleasePath)
	if err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", linuxOSReleasePath, err))
	} else {
		name, version := ParseOSRelease(osRelease)
		rep.Host.OS = name
		rep.Host.OSVersion = version
	}

	if kernel, kerr := runText(ctx, r, linuxCmdKernel); kerr == nil {
		rep.Host.Kernel = strings.TrimSpace(kernel)
	} else {
		problems = append(problems, kerr.Error())
	}

	if node, nerr := runText(ctx, r, linuxCmdNodename); nerr == nil {
		// `uname -n` returns whatever is in the kernel's nodename, which on a
		// domain-joined host is often the FULL name. Keep only the short label
		// here: hostname and fqdn are two identifier KINDS, and a host whose
		// hostname and fqdn are the same string offers the identification
		// engine one piece of evidence wearing two hats. The FQDN is set below,
		// from the probe whose job that is.
		short, domain := splitFQDN(strings.TrimSpace(node))
		rep.Host.Hostname = short
		if domain != "" {
			rep.Host.FQDN = short + "." + domain
			rep.Host.Domain = domain
		}
	} else {
		problems = append(problems, nerr.Error())
	}

	// `hostname -f` is allowed to fail: a host with no search domain and no
	// resolvable name genuinely has no FQDN, and that is an answer rather than
	// a gap. It is not counted as a problem for that reason.
	if fqdn, ferr := runText(ctx, r, linuxCmdFQDN); ferr == nil {
		if short, domain := splitFQDN(fqdn); domain != "" {
			rep.Host.FQDN = short + "." + domain
			rep.Host.Domain = domain
			if rep.Host.Hostname == "" {
				rep.Host.Hostname = short
			}
		}
	}

	if len(problems) > 0 {
		rep.fail(SectionHost, errors.New(strings.Join(problems, "; ")))
		return
	}
	rep.mark(SectionHost, SectionOK)
}

// ParseOSRelease extracts the product name and version from an os-release file.
//
// PRETTY_NAME is deliberately NOT used as the product name: it folds name and
// version into one string ("Ubuntu 22.04.3 LTS"), and the EOL catalogue joins
// on them separately. NAME plus VERSION is the pair the registry's os.name /
// os.version keys describe.
func ParseOSRelease(b []byte) (name, version string) {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "NAME":
			name = value
		case "VERSION":
			version = value
		case "VERSION_ID":
			// Only as a fallback: VERSION carries the codename an operator
			// recognises ("22.04.3 LTS (Jammy Jellyfish)"), VERSION_ID is the
			// bare number. Alpine has VERSION_ID and no VERSION.
			if version == "" {
				version = value
			}
		}
	}
	return name, version
}

func collectLinuxHardware(ctx context.Context, r Runner, rep *Report) {
	// Read every DMI field, remember which ones were unreadable, and leave
	// those absent. An unreadable field is NOT an error for the section: an
	// unprivileged agent reading no serial is the expected case on most hosts,
	// and marking the whole section failed for it would make the genuinely
	// broken case invisible.
	var unreadable []string
	read := func(key string) string {
		b, err := r.ReadFile(ctx, linuxDMIPaths[key])
		if err != nil {
			unreadable = append(unreadable, key)
			return ""
		}
		return sanitiseDMI(string(b))
	}

	rep.Hardware.Vendor = read("vendor")
	rep.Hardware.Model = read("model")
	rep.Hardware.Serial = read("serial")
	rep.Hardware.UUID = read("uuid")
	rep.Hardware.Firmware = read("firmware")

	if len(unreadable) == len(linuxDMIPaths) {
		// Nothing at all was readable: no DMI on this kernel (a container, a
		// non-x86 board). That is a failed section, not an empty answer.
		rep.fail(SectionHardware, fmt.Errorf("no DMI field was readable under /sys/class/dmi/id (container, or unprivileged agent)"))
		return
	}
	rep.mark(SectionHardware, SectionOK)
}

// dmiPlaceholders are the strings firmware ships when a field was never
// programmed. They are not serial numbers, and treating them as identities
// merges every unprogrammed board in the estate into one asset.
var dmiPlaceholders = map[string]bool{
	"":                                     true,
	"to be filled by o.e.m.":               true,
	"to be filled by oem":                  true,
	"system serial number":                 true,
	"default string":                       true,
	"not specified":                        true,
	"not applicable":                       true,
	"none":                                 true,
	"unknown":                              true,
	"0":                                    true,
	"o.e.m.":                               true,
	"chassis serial number":                true,
	"00000000-0000-0000-0000-000000000000": true,
}

// sanitiseDMI trims a DMI field and drops the firmware placeholders.
func sanitiseDMI(s string) string {
	v := strings.TrimSpace(s)
	if dmiPlaceholders[strings.ToLower(v)] {
		return ""
	}
	return v
}

func collectLinuxInterfaces(ctx context.Context, r Runner, rep *Report, opts Options) {
	out, err := runText(ctx, r, linuxCmdIPJ)
	if err == nil {
		ifaces, perr := ParseIPJSON([]byte(out))
		if perr == nil {
			rep.Interfaces = ifaces
			rep.mark(SectionInterfaces, SectionOK)
			return
		}
		err = perr
	}

	// The one documented divergence. Local only, opt-in, and only after the
	// command has already failed — and it is STILL recorded as a step error, so
	// a reader can see that the interface list came from a different source
	// than a remote report's would.
	if opts.Mode == ModeLocal && opts.LocalInterfaceFallback {
		if ifaces, lerr := localInterfaces(); lerr == nil {
			rep.Interfaces = ifaces
			rep.mark(SectionInterfaces, SectionOK)
			rep.Errors = append(rep.Errors, StepError{
				Step:    SectionInterfaces,
				Message: fmt.Sprintf("ip -j addr unavailable (%v); used the local net.Interfaces() fallback", err),
			})
			return
		}
	}

	rep.fail(SectionInterfaces, err)
}

// ipJSONAddr mirrors the `ip -j addr` output shape. Typed rather than
// map-walked so an unexpected field is discarded structurally.
type ipJSONAddr struct {
	IFName    string `json:"ifname"`
	Address   string `json:"address"`
	Operstate string `json:"operstate"`
	LinkType  string `json:"link_type"`
	AddrInfo  []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Family    string `json:"family"`
	} `json:"addr_info"`
}

// ParseIPJSON turns `ip -j addr` output into interfaces.
func ParseIPJSON(b []byte) ([]Interface, error) {
	var raw []ipJSONAddr
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("ip -j addr: %w", err)
	}
	out := make([]Interface, 0, len(raw))
	for _, e := range raw {
		if e.IFName == "" {
			continue
		}
		entry := Interface{
			Name:    e.IFName,
			MAC:     normaliseMAC(e.Address),
			State:   normaliseOperstate(e.Operstate),
			Virtual: isVirtualInterface(e.IFName, e.LinkType == "loopback"),
		}
		for _, a := range e.AddrInfo {
			if a.Local == "" {
				continue
			}
			entry.Addresses = append(entry.Addresses, fmt.Sprintf("%s/%d", a.Local, a.PrefixLen))
		}
		out = append(out, entry)
	}
	return out, nil
}

// normaliseOperstate maps the kernel's operstate onto the registry's
// {up, down, unknown} vocabulary. "UNKNOWN" is the kernel's honest answer for
// an interface whose driver does not report carrier — a tunnel, usually — and
// it stays unknown rather than being promoted to up.
func normaliseOperstate(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "UP":
		return "up"
	case "DOWN", "LOWERLAYERDOWN", "NOTPRESENT":
		return "down"
	default:
		return "unknown"
	}
}

func collectLinuxPackages(ctx context.Context, r Runner, rep *Report, opts Options) {
	distro := strings.ToLower(rep.Host.OS)

	if out, ok := commandPresent(ctx, r, linuxCmdDpkg); ok {
		rep.Packages = capPackages(ParseDpkg([]byte(out), debNamespace(distro)), opts.maxPackages())
		rep.mark(SectionPackages, SectionOK)
		return
	}
	if out, ok := commandPresent(ctx, r, linuxCmdRPM); ok {
		rep.Packages = capPackages(ParseRPM([]byte(out), rpmNamespace(distro)), opts.maxPackages())
		rep.mark(SectionPackages, SectionOK)
		return
	}
	if out, ok := commandPresent(ctx, r, linuxCmdAPK); ok {
		arch, _ := commandPresent(ctx, r, linuxCmdArch)
		rep.Packages = capPackages(ParseAPK([]byte(out), strings.TrimSpace(arch)), opts.maxPackages())
		rep.mark(SectionPackages, SectionOK)
		return
	}

	rep.fail(SectionPackages, errors.New("no supported package database found (tried dpkg-query, rpm, apk)"))
}

// capPackages bounds the list, because a Report is carried over HTTP and stored
// as JSONB. Truncation is not silent: the caller marks the section ok only
// because the packages we DID enumerate are real, and sw.package_count reports
// what was kept.
func capPackages(pkgs []Package, limit int) []Package {
	if len(pkgs) <= limit {
		return pkgs
	}
	return pkgs[:limit]
}

// debNamespace picks the purl namespace for a dpkg host. The purl spec wants
// the distribution, and "ubuntu" and "debian" are distinct namespaces with
// distinct version spaces.
func debNamespace(distro string) string {
	switch {
	case strings.Contains(distro, "ubuntu"):
		return "ubuntu"
	case strings.Contains(distro, "debian"):
		return "debian"
	default:
		// A dpkg derivative we do not recognise (Raspbian, Linux Mint, Pop!_OS).
		// No namespace is better than the wrong one: a purl claiming `debian`
		// for a Mint package would match the wrong advisory.
		return ""
	}
}

// rpmNamespace picks the purl namespace for an rpm host.
func rpmNamespace(distro string) string {
	switch {
	case strings.Contains(distro, "red hat"), strings.Contains(distro, "rhel"):
		return "redhat"
	case strings.Contains(distro, "centos"):
		return "centos"
	case strings.Contains(distro, "fedora"):
		return "fedora"
	case strings.Contains(distro, "rocky"):
		return "rocky"
	case strings.Contains(distro, "alma"):
		return "almalinux"
	case strings.Contains(distro, "suse"):
		return "opensuse"
	default:
		return ""
	}
}

// ParseDpkg parses `dpkg-query -W -f=${Package}\t${Version}\t${Architecture}\t${Maintainer}\n`.
func ParseDpkg(b []byte, namespace string) []Package {
	var out []Package
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 || strings.TrimSpace(f[0]) == "" {
			continue
		}
		p := Package{
			Name:    strings.TrimSpace(f[0]),
			Version: strings.TrimSpace(f[1]),
			Manager: "dpkg",
		}
		if len(f) > 2 {
			p.Arch = strings.TrimSpace(f[2])
		}
		if len(f) > 3 {
			p.Vendor = strings.TrimSpace(f[3])
		}
		p.PURL = purlDeb(namespace, p.Name, p.Version, p.Arch)
		out = append(out, p)
	}
	return out
}

// ParseRPM parses `rpm -qa --queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n`.
func ParseRPM(b []byte, namespace string) []Package {
	var out []Package
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 || strings.TrimSpace(f[0]) == "" {
			continue
		}
		p := Package{
			Name:    strings.TrimSpace(f[0]),
			Version: strings.TrimSpace(f[1]),
			Manager: "rpm",
		}
		if len(f) > 2 {
			p.Arch = strings.TrimSpace(f[2])
		}
		if len(f) > 3 {
			v := strings.TrimSpace(f[3])
			// rpm prints the literal "(none)" for an unset vendor.
			if !strings.EqualFold(v, "(none)") {
				p.Vendor = v
			}
		}
		p.PURL = purlRPM(namespace, p.Name, p.Version, p.Arch)
		out = append(out, p)
	}
	return out
}

// ParseAPK parses `apk info -v`, whose lines are `<name>-<version>-r<rel>`.
//
// The split is from the RIGHT, at the last hyphen followed by a digit, because
// a package name may itself contain hyphens (`ca-certificates-bundle-20240226-r0`)
// and splitting from the left would name it "ca".
func ParseAPK(b []byte, arch string) []Package {
	var out []Package
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		name, version := splitAPKLine(line)
		if name == "" {
			continue
		}
		p := Package{
			Name:    name,
			Version: version,
			Arch:    arch,
			Manager: "apk",
			PURL:    purlAPK(name, version, arch),
		}
		out = append(out, p)
	}
	return out
}

// splitAPKLine separates `<name>-<version>-r<rel>`.
func splitAPKLine(line string) (name, version string) {
	// The release suffix is always "-r<digits>". Find it, then find the hyphen
	// before the version that precedes it.
	relIdx := strings.LastIndex(line, "-r")
	if relIdx <= 0 || !allDigits(line[relIdx+2:]) {
		// No recognisable release suffix: take the whole line as a name rather
		// than guessing where a version starts.
		return line, ""
	}
	verIdx := strings.LastIndex(line[:relIdx], "-")
	if verIdx <= 0 {
		return line, ""
	}
	return line[:verIdx], line[verIdx+1:]
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func collectLinuxListeners(ctx context.Context, r Runner, rep *Report) {
	if out, ok := commandPresent(ctx, r, linuxCmdSS); ok {
		rep.Listeners, rep.BoundUDPSockets = ParseSSBindings([]byte(out))
		rep.mark(SectionListeners, SectionOK)
		rep.mark(SectionBoundUDP, SectionOK)
		return
	}

	// `ss` is absent (a distroless or busybox image). /proc/net/tcp still
	// answers, at the cost of the process name — the inode-to-process walk
	// needs /proc/<pid>/fd, which is a per-process read we deliberately do not
	// do. The sockets are recorded with no Process, which is an absent field
	// rather than a wrong one.
	var listeners []Listener
	var failures []string
	for _, path := range linuxProcNetTCP {
		b, err := r.ReadFile(ctx, path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		listeners = append(listeners, ParseProcNetTCP(b)...)
	}
	if len(failures) > 0 {
		// A partial address-family snapshot cannot license endpoint retirement
		// or outbound direction inference. Keep neither half as complete.
		rep.Listeners = nil
		rep.fail(SectionListeners, fmt.Errorf("incomplete /proc/net/tcp snapshot: %s", strings.Join(failures, "; ")))
	} else {
		rep.Listeners = listeners
		rep.mark(SectionListeners, SectionOK)
	}

	var udp []BoundUDPSocket
	var udpFailures []string
	for _, path := range linuxProcNetUDP {
		b, err := r.ReadFile(ctx, path)
		if err != nil {
			udpFailures = append(udpFailures, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		udp = append(udp, ParseProcNetUDPBindings(b)...)
	}
	if len(udpFailures) > 0 {
		// Like TCP, one address family is not a complete snapshot. Publishing it
		// as current would erase bindings from the unread family.
		rep.BoundUDPSockets = nil
		rep.fail(SectionBoundUDP, fmt.Errorf("incomplete /proc/net/udp snapshot: %s", strings.Join(udpFailures, "; ")))
	} else {
		rep.BoundUDPSockets = coalesceBoundUDP(udp)
		rep.mark(SectionBoundUDP, SectionOK)
	}
}

// ParseSS parses `ss -ltnup` output.
//
// TCP LISTEN rows are returned as listeners. UDP UNCONN rows are retained by
// ParseSSBindings as unknown-role bindings; they are not listener claims.
func ParseSS(b []byte) []Listener {
	listeners, _ := ParseSSBindings(b)
	return listeners
}

// ParseSSBindings separates proven TCP listeners from UDP bindings whose role
// ss cannot establish. UNCONN does not mean server: ordinary UDP clients can
// be unconnected and bound to ephemeral ports.
func ParseSSBindings(b []byte) ([]Listener, []BoundUDPSocket) {
	var out []Listener
	var udp []BoundUDPSocket
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Header row: "Netid State Recv-Q Send-Q Local Address:Port ...".
		if i == 0 && strings.EqualFold(fields[0], "Netid") {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		state := strings.ToUpper(fields[1])
		if (proto == "tcp" && state != "LISTEN") || (proto == "udp" && state != "UNCONN") {
			continue
		}
		addr, port, ok := splitHostPortSuffix(fields[4])
		if !ok {
			continue
		}
		l := Listener{Proto: proto, Address: addr, Port: port}
		// The users:(("name",pid=123,fd=4)) column is only present when the
		// caller has privilege. Its absence is an absent process name.
		if idx := strings.Index(line, `users:(("`); idx >= 0 {
			l.Process, l.PID = parseSSUsers(line[idx:])
		}
		if proto == "udp" {
			udp = append(udp, BoundUDPSocket{Address: addr, Port: port, Process: l.Process, PID: l.PID})
		} else {
			out = append(out, l)
		}
	}
	return out, coalesceBoundUDP(udp)
}

// ParseSSConnections reads rows with a concrete peer. It accepts only TCP
// ESTAB and UDP rows with a non-wildcard peer.
func ParseSSConnections(b []byte) []Connection {
	var out []Connection
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || strings.EqualFold(fields[0], "Netid") {
			continue
		}
		proto, state := strings.ToLower(fields[0]), strings.ToUpper(fields[1])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if proto == "tcp" && state != "ESTAB" {
			continue
		}
		local, localPort, lok := splitHostPortSuffix(fields[4])
		remote, remotePort, rok := splitHostPortSuffix(fields[5])
		if !lok || !rok || remote == "0.0.0.0" || remote == "::" || remotePort == 0 {
			continue
		}
		c := Connection{Proto: proto, LocalAddress: local, LocalPort: localPort, RemoteAddress: remote, RemotePort: remotePort}
		if idx := strings.Index(line, `users:(("`); idx >= 0 {
			c.Process, c.PID = parseSSUsers(line[idx:])
		}
		out = append(out, c)
	}
	return out
}

func collectLinuxConnections(ctx context.Context, r Runner, rep *Report, opts Options) {
	if !opts.CollectConnections {
		return
	}
	if !rep.SectionOK(SectionListeners) {
		rep.fail(SectionConnections, errors.New("listener snapshot incomplete; established TCP direction cannot be determined"))
		return
	}
	if out, ok := commandPresent(ctx, r, linuxCmdConnections); ok {
		rep.Connections = coalesceConnections(excludeAcceptedConnections(ParseSSConnections([]byte(out)), rep.Listeners), opts.maxConnections())
		rep.mark(SectionConnections, SectionOK)
		return
	}
	var out []Connection
	var failures []string
	for _, source := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"}} {
		b, err := r.ReadFile(ctx, source.path)
		if err != nil {
			failures = append(failures, source.path+": "+err.Error())
			continue
		}
		out = append(out, ParseProcNetConnections(b, source.proto)...)
	}
	if len(failures) > 0 {
		rep.fail(SectionConnections, errors.New(strings.Join(failures, "; ")))
		return
	}
	rep.Connections = coalesceConnections(excludeAcceptedConnections(out, rep.Listeners), opts.maxConnections())
	rep.mark(SectionConnections, SectionOK)
}

func ParseProcNetUDPBindings(b []byte) []BoundUDPSocket {
	var out []BoundUDPSocket
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		_, remotePort, ok := parseProcHexAddr(f[2])
		if !ok || remotePort != 0 {
			continue
		}
		addr, port, ok := parseProcHexAddr(f[1])
		if ok {
			out = append(out, BoundUDPSocket{Address: addr, Port: port})
		}
	}
	return out
}

func ParseProcNetConnections(b []byte, proto string) []Connection {
	var out []Connection
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if proto == "tcp" && f[3] != "01" {
			continue
		}
		local, localPort, lok := parseProcHexAddr(f[1])
		remote, port, rok := parseProcHexAddr(f[2])
		if lok && rok && port > 0 {
			out = append(out, Connection{Proto: proto, LocalAddress: local, LocalPort: localPort, RemoteAddress: remote, RemotePort: port})
		}
	}
	return out
}

// parseSSUsers pulls the first process name and pid out of ss's users: column.
func parseSSUsers(s string) (string, int) {
	const prefix = `users:(("`
	rest := strings.TrimPrefix(s, prefix)
	name, rest, ok := strings.Cut(rest, `"`)
	if !ok {
		return "", 0
	}
	pidIdx := strings.Index(rest, "pid=")
	if pidIdx < 0 {
		return name, 0
	}
	digits := rest[pidIdx+4:]
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	pid, _ := strconv.Atoi(digits[:end])
	return name, pid
}

// splitHostPortSuffix splits ss's "addr:port" column, which may be
// "0.0.0.0:22", "*:68", "[::]:443" or "[fe80::1]%eth0:546".
func splitHostPortSuffix(s string) (host string, port int, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	host = s[:i]
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	// Drop an IPv6 zone: %eth0 on one host is not the same interface on another.
	if z := strings.Index(host, "%"); z >= 0 {
		host = host[:z]
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	return host, p, true
}

// ParseProcNetTCP parses /proc/net/tcp and /proc/net/tcp6, keeping only the
// rows in state 0A (TCP_LISTEN). Addresses are little-endian hex.
func ParseProcNetTCP(b []byte) []Listener {
	var out []Listener
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		addr, port, ok := parseProcHexAddr(f[1])
		if !ok {
			continue
		}
		out = append(out, Listener{Proto: "tcp", Address: addr, Port: port})
	}
	return out
}

// parseProcHexAddr decodes /proc/net/tcp's "<hex addr>:<hex port>".
func parseProcHexAddr(s string) (string, int, bool) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil {
		return "", 0, false
	}
	switch len(hexAddr) {
	case 8: // IPv4, little-endian within the word
		v, perr := strconv.ParseUint(hexAddr, 16, 64)
		if perr != nil {
			return "", 0, false
		}
		return fmt.Sprintf("%d.%d.%d.%d", byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), int(port64), true
	case 32: // IPv6, four little-endian words
		var raw [16]byte
		for w := 0; w < 4; w++ {
			v, perr := strconv.ParseUint(hexAddr[w*8:w*8+8], 16, 64)
			if perr != nil {
				return "", 0, false
			}
			raw[w*4+0] = byte(v)
			raw[w*4+1] = byte(v >> 8)
			raw[w*4+2] = byte(v >> 16)
			raw[w*4+3] = byte(v >> 24)
		}
		// netip, not a hand-rolled join, because the ADDRESS IS A JOIN KEY and
		// every other producer in the platform spells it canonically. Eight
		// uncompressed groups made ::1 come out as
		// "0000:0000:...:0001", which isLoopback below does not recognise —
		// so a loopback-only IPv6 service reached the report claiming
		// bound_local:false. That is a wrong answer, not a missing one, and it
		// only appears on the fallback path where `ss` is absent.
		//
		// Unmap is deliberate: a dual-stack socket's ::ffff:127.0.0.1 row is
		// about 127.0.0.1, and rendering it as the v4 address is both the
		// truth and the spelling the v4 table would have produced.
		return netip.AddrFrom16(raw).Unmap().String(), int(port64), true
	default:
		return "", 0, false
	}
}
