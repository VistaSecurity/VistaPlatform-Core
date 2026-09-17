package hostinventory

import (
	"strings"
	"testing"
)

// Golden tests for every parser, driven from captured output under testdata/.
//
// The fixtures are realistic rather than minimal on purpose: the interesting
// bugs in this kind of code are all in the rows that do not look like the
// example — a package name that contains a hyphen, an interface with no
// address, a socket bound to a zone-scoped loopback, a vendor field that says
// "(none)".

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		fixture     string
		wantName    string
		wantVersion string
	}{
		{"os-release-ubuntu", "Ubuntu", "22.04.3 LTS (Jammy Jellyfish)"},
		// Alpine has VERSION_ID and no VERSION, which is why the fallback
		// exists at all.
		{"os-release-alpine", "Alpine Linux", "3.20.3"},
		{"os-release-rhel", "Red Hat Enterprise Linux", "9.4 (Plow)"},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			name, version := ParseOSRelease([]byte(fixture(t, "linux", tc.fixture)))
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if version != tc.wantVersion {
				t.Errorf("version = %q, want %q", version, tc.wantVersion)
			}
		})
	}
}

// PRETTY_NAME folds the product and the version into one string and the EOL
// catalogue joins on them separately, so reading it would break the join in a
// way nothing downstream could detect.
func TestParseOSRelease_DoesNotUsePrettyName(t *testing.T) {
	name, _ := ParseOSRelease([]byte(fixture(t, "linux", "os-release-ubuntu")))
	if name != "Ubuntu" {
		t.Fatalf("os.name = %q; PRETTY_NAME must not be the product name", name)
	}
}

func TestParseDpkg(t *testing.T) {
	pkgs := ParseDpkg([]byte(fixture(t, "linux", "dpkg-query.txt")), "ubuntu")
	if len(pkgs) != 7 {
		t.Fatalf("got %d packages, want 7: %+v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	ssl := byName["openssl"]
	if ssl.Version != "3.0.2-0ubuntu1.15" || ssl.Arch != "amd64" || ssl.Manager != "dpkg" {
		t.Errorf("openssl: %+v", ssl)
	}
	if want := "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?arch=amd64"; ssl.PURL != want {
		t.Errorf("openssl purl = %q, want %q", ssl.PURL, want)
	}
	// A version containing an epoch colon must survive escaping intact.
	if got := byName["openssh-server"].PURL; got != "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?arch=amd64" {
		t.Errorf("openssh-server purl = %q", got)
	}
	if byName["adduser"].Arch != "all" {
		t.Errorf("architecture-independent package lost its arch: %+v", byName["adduser"])
	}
}

func TestParseRPM(t *testing.T) {
	pkgs := ParseRPM([]byte(fixture(t, "linux", "rpm-qa.txt")), "redhat")
	if len(pkgs) != 7 {
		t.Fatalf("got %d packages, want 7", len(pkgs))
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	ssl := byName["openssl"]
	if ssl.Version != "3.0.7-27.el9" || ssl.Vendor != "Red Hat, Inc." {
		t.Errorf("openssl: %+v", ssl)
	}
	if want := "pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64"; ssl.PURL != want {
		t.Errorf("openssl purl = %q, want %q", ssl.PURL, want)
	}
	// rpm prints the literal "(none)" for an unset vendor. Storing that string
	// would put a fake vendor name in the inventory.
	if v := byName["local-tooling"].Vendor; v != "" {
		t.Errorf(`vendor "(none)" was stored verbatim as %q`, v)
	}
}

func TestParseAPK(t *testing.T) {
	pkgs := ParseAPK([]byte(fixture(t, "linux", "apk-info.txt")), "x86_64")
	if len(pkgs) != 9 {
		t.Fatalf("got %d packages, want 9", len(pkgs))
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// The whole point of splitting from the right: a name that contains
	// hyphens must not be cut at the first one.
	bundle, ok := byName["ca-certificates-bundle"]
	if !ok {
		t.Fatalf("a hyphenated package name was split wrongly; got names %v", keysOf(byName))
	}
	if bundle.Version != "20240705-r0" {
		t.Errorf("ca-certificates-bundle version = %q", bundle.Version)
	}
	if want := "pkg:apk/alpine/ca-certificates-bundle@20240705-r0?arch=x86_64"; bundle.PURL != want {
		t.Errorf("purl = %q, want %q", bundle.PURL, want)
	}
	if byName["musl"].Version != "1.2.5-r0" {
		t.Errorf("musl: %+v", byName["musl"])
	}
}

func TestParseSS(t *testing.T) {
	listeners, bound := ParseSSBindings([]byte(fixture(t, "linux", "ss-ltnup.txt")))
	if len(listeners) != 5 {
		t.Fatalf("got %d proven TCP listeners, want 5: %+v", len(listeners), listeners)
	}
	var tcp int
	for _, l := range listeners {
		if l.Proto == "tcp" {
			tcp++
		}
	}
	if len(bound) != 3 {
		t.Errorf("got %d unknown-role UDP bindings, want 3 — the evidence was dropped", len(bound))
	}
	if tcp != 5 {
		t.Errorf("got %d tcp listeners, want 5", tcp)
	}

	first := listeners[0]
	if first.Address != "127.0.0.53" {
		t.Errorf("the IPv6/zone suffix survived into the address: %q", first.Address)
	}
	if first.Port != 53 || first.Process != "systemd-resolve" || first.PID != 612 {
		t.Errorf("first listener: %+v", first)
	}

	byPort := map[int]Listener{}
	for _, l := range listeners {
		if l.Proto == "tcp" {
			byPort[l.Port] = l
		}
	}
	if got := byPort[443].Address; got != "0.0.0.0" {
		t.Errorf("the `*` wildcard should normalise to 0.0.0.0, got %q", got)
	}
	if got := byPort[22].Address; got != "0.0.0.0" && got != "::" {
		t.Errorf("port 22: %+v", byPort[22])
	}
	if byPort[5432].Address != "127.0.0.1" || byPort[5432].Process != "postgres" {
		t.Errorf("loopback-only service: %+v", byPort[5432])
	}
}

func TestParseProcNetTCP(t *testing.T) {
	listeners := ParseProcNetTCP([]byte(fixture(t, "linux", "proc-net-tcp.txt")))
	if len(listeners) != 3 {
		t.Fatalf("got %d listeners, want 3 (only the 0A rows): %+v", len(listeners), listeners)
	}
	want := map[string]int{"127.0.0.53": 53, "0.0.0.0": 22, "127.0.0.1": 5432}
	for _, l := range listeners {
		if want[l.Address] != l.Port {
			t.Errorf("unexpected listener %+v", l)
		}
		// /proc gives no owning process, and an absent name is correct — never
		// a guessed one.
		if l.Process != "" {
			t.Errorf("/proc/net/tcp cannot know a process name, got %q", l.Process)
		}
	}
}

// /proc/net/tcp6 rows, whose addresses are four little-endian 32-bit words.
//
// The address is a JOIN KEY, so it has to come out spelled the way every other
// producer spells it. It also decides `bound_local` on the endpoint, and
// `bound_local` is a positive claim: an uncompressed ::1 that isLoopback does
// not recognise does not omit the answer, it publishes the WRONG one — "this
// service is reachable from the network" about a service that is not.
//
// To mutation-test: render the eight groups joined by ":" instead of through
// netip and the first two cases fail.
func TestParseProcNetTCP6_AddressesAreCanonicalAndLoopbackIsRecognised(t *testing.T) {
	const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 30011 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 30012 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 30013 1 0000000000000000 100 0 0 10 0
   3: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 30014 1 0000000000000000 100 0 0 10 0
`
	listeners := ParseProcNetTCP([]byte(tcp6))
	if len(listeners) != 3 {
		t.Fatalf("got %d listeners, want 3 (only the 0A rows): %+v", len(listeners), listeners)
	}

	want := map[int]struct {
		addr  string
		local bool
	}{
		3000: {"::1", true},       // loopback-only, and it must say so
		22:   {"::", false},       // the dual-stack wildcard
		8080: {"127.0.0.1", true}, // a v4-mapped row is about the v4 address
	}
	for _, l := range listeners {
		w, known := want[l.Port]
		if !known {
			t.Errorf("unexpected listener %+v", l)
			continue
		}
		if l.Address != w.addr {
			t.Errorf("port %d address = %q, want the canonical %q", l.Port, l.Address, w.addr)
		}
		if got := isLoopback(l.Address); got != w.local {
			t.Errorf("port %d (%s): bound_local = %v, want %v", l.Port, l.Address, got, w.local)
		}
	}
}

// isLoopback decides a positive claim, so every spelling a producer can emit
// has to reach the same answer.
func TestIsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "127.0.0.53", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"} {
		if !isLoopback(addr) {
			t.Errorf("isLoopback(%q) = false; a loopback-only service would be published as network-reachable", addr)
		}
	}
	for _, addr := range []string{"0.0.0.0", "::", "192.0.2.10", "2001:db8::1", "", "not-an-address"} {
		if isLoopback(addr) {
			t.Errorf("isLoopback(%q) = true; a reachable service would be hidden as host-only", addr)
		}
	}
}

func TestParseIPJSON(t *testing.T) {
	ifaces, err := ParseIPJSON([]byte(fixture(t, "linux", "ip-j-addr.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ifaces) != 4 {
		t.Fatalf("got %d interfaces, want 4", len(ifaces))
	}

	byName := map[string]Interface{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}

	eth0 := byName["eth0"]
	if eth0.MAC != "b4:96:91:1a:2b:3c" || eth0.State != "up" || eth0.Virtual {
		t.Errorf("eth0: %+v", eth0)
	}
	if len(eth0.Addresses) != 2 || eth0.Addresses[0] != "198.51.100.24/24" {
		t.Errorf("eth0 addresses: %v", eth0.Addresses)
	}

	// The loopback's all-zero MAC is a placeholder, not an identity.
	if lo := byName["lo"]; lo.MAC != "" || !lo.Virtual {
		t.Errorf("lo kept a placeholder MAC or was not marked virtual: %+v", lo)
	}
	// The kernel's UNKNOWN operstate must stay unknown, not be promoted to up.
	if lo := byName["lo"]; lo.State != "unknown" {
		t.Errorf("lo state = %q, want unknown", lo.State)
	}
	// A docker bridge MAC is generated per host and must not seed identity.
	if d := byName["docker0"]; !d.Virtual {
		t.Errorf("docker0 was not marked virtual: %+v", d)
	}
	// An interface with no address is still an interface — an endpoint row
	// would never show it.
	if e1 := byName["eth1"]; len(e1.Addresses) != 0 || e1.State != "down" {
		t.Errorf("eth1: %+v", e1)
	}
}

func TestParseSwVers(t *testing.T) {
	name, version, build := ParseSwVers([]byte(fixture(t, "darwin", "sw_vers.txt")))
	if name != "macOS" || version != "14.5" || build != "23F79" {
		t.Errorf("got %q / %q / %q", name, version, build)
	}
}

func TestParseDarwinHardware(t *testing.T) {
	hw, err := ParseDarwinHardware([]byte(fixture(t, "darwin", "system_profiler.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hw.Vendor != "Apple Inc." || hw.Model != "Mac mini" {
		t.Errorf("identity: %+v", hw)
	}
	if hw.Serial != "H2WEXAMPLE01" || hw.UUID != "5D3A2C71-9F44-4E0B-B6A1-7C2E4F8D9012" {
		t.Errorf("identifiers: %+v", hw)
	}
	if hw.Firmware != "10151.121.1" {
		t.Errorf("firmware: %+v", hw)
	}
}

func TestParseIfconfig(t *testing.T) {
	ifaces := ParseIfconfig([]byte(fixture(t, "darwin", "ifconfig.txt")))
	if len(ifaces) != 4 {
		t.Fatalf("got %d interfaces, want 4: %+v", len(ifaces), ifaces)
	}
	byName := map[string]Interface{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}

	en0 := byName["en0"]
	if en0.MAC != "3c:22:fb:1a:2b:3c" || en0.State != "up" {
		t.Errorf("en0: %+v", en0)
	}
	// 0xffffff00 is /24. A mask we cannot read yields no suffix rather than a
	// guessed prefix length.
	if !contains(en0.Addresses, "198.51.100.31/24") {
		t.Errorf("en0 lost its netmask: %v", en0.Addresses)
	}
	if !contains(en0.Addresses, "fe80::1c4f:8a2b:9d1e:4f70/64") {
		t.Errorf("en0 IPv6 zone was not stripped: %v", en0.Addresses)
	}
	if byName["en1"].State != "down" {
		t.Errorf("en1 should be down: %+v", byName["en1"])
	}
	// awdl0 is Apple Wireless Direct Link — a per-boot virtual interface.
	if !byName["awdl0"].Virtual {
		t.Errorf("awdl0 was not marked virtual: %+v", byName["awdl0"])
	}
	if !byName["lo0"].Virtual {
		t.Errorf("lo0 was not marked virtual")
	}
}

func TestParseLsof(t *testing.T) {
	listeners := ParseLsof([]byte(fixture(t, "darwin", "lsof.txt")))
	// Six rows collapse to four services. lsof prints one row per file
	// descriptor, so nginx's single socket appears twice, and launchd's `*:22`
	// appears once per address family — both are one listening service, and an
	// inventory that reported them twice would double-count every open port on
	// every Mac.
	if len(listeners) != 4 {
		t.Fatalf("got %d listeners, want 4 (the duplicate fd rows must collapse): %+v", len(listeners), listeners)
	}
	byPort := map[int]Listener{}
	for _, l := range listeners {
		byPort[l.Port] = l
	}
	if byPort[5432].Address != "127.0.0.1" || byPort[5432].Process != "postgres" {
		t.Errorf("postgres: %+v", byPort[5432])
	}
	if byPort[22].Address != "0.0.0.0" {
		t.Errorf("the `*` wildcard should normalise: %+v", byPort[22])
	}
	if byPort[8443].Process != "nginx" || byPort[8443].PID != 1203 {
		t.Errorf("nginx: %+v", byPort[8443])
	}
}

func TestParsePkgutil(t *testing.T) {
	pkgs := ParsePkgutil([]byte(fixture(t, "darwin", "pkgutil-pkgs.txt")))
	if len(pkgs) != 6 {
		t.Fatalf("got %d receipts, want 6", len(pkgs))
	}
	// pkgutil --pkgs prints no version. An absent version is honest; a
	// fabricated one would poison every advisory match against it.
	for _, p := range pkgs {
		if p.Version != "" {
			t.Errorf("a receipt gained a version from nowhere: %+v", p)
		}
		if p.Manager != "pkgutil" {
			t.Errorf("manager: %+v", p)
		}
		if p.PURL != "" {
			t.Errorf("a macOS receipt has no purl type; got %q", p.PURL)
		}
	}
}

func TestParseInfoPlist(t *testing.T) {
	app, ok := ParseInfoPlist([]byte(fixture(t, "darwin", "Info.plist")), "/Applications/Example Editor.app/Contents/Info.plist")
	if !ok {
		t.Fatal("an XML plist failed to parse")
	}
	if app.Name != "Example Editor" || app.Version != "3.8.1" {
		t.Errorf("app: %+v", app)
	}
	if app.Vendor != "net.example.ExampleEditor" || app.Manager != "macos_app" {
		t.Errorf("app: %+v", app)
	}
}

// A binary plist is reported as undecodable rather than guessed at.
func TestParseInfoPlist_BinaryPlistIsRefusedNotGuessed(t *testing.T) {
	if _, ok := ParseInfoPlist([]byte("bplist00\xd1\x01\x02"), "/Applications/X.app/Contents/Info.plist"); ok {
		t.Fatal("a binary plist was accepted; its bytes cannot be read by this parser")
	}
}

func TestParseWindowsOS(t *testing.T) {
	host, err := ParseWindowsOS([]byte(fixture(t, "windows", "os.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if host.OS != "Microsoft Windows Server 2022 Standard" || host.OSVersion != "10.0.20348" {
		t.Errorf("os: %+v", host)
	}
	if host.Kernel != "20348" {
		t.Errorf("build number should be the kernel-equivalent: %+v", host)
	}
	if host.Hostname != "win-app01" || host.FQDN != "win-app01.corp.example.net" {
		t.Errorf("names: %+v", host)
	}
}

// "WORKGROUP" is not a domain. Gluing it onto a hostname gives every standalone
// machine in the estate the same FQDN — a string that looks like an identity
// and merges unrelated assets.
func TestParseWindowsOS_WorkgroupIsNotADomain(t *testing.T) {
	host, err := ParseWindowsOS([]byte(
		`{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631","BuildNumber":"22631","CSName":"DESKTOP-A1","Domain":"WORKGROUP","PartOfDomain":false}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if host.FQDN != "" || host.Domain != "" {
		t.Fatalf("a workgroup machine was given an FQDN: %+v", host)
	}
	if host.Hostname != "desktop-a1" {
		t.Errorf("hostname was lost too: %+v", host)
	}
}

func TestParseWindowsHardware(t *testing.T) {
	hw, err := ParseWindowsHardware([]byte(fixture(t, "windows", "hardware.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hw.Vendor != "Dell Inc." || hw.Model != "PowerEdge R650" || hw.Serial != "7BQ1EX3" {
		t.Errorf("hardware: %+v", hw)
	}
}

// Firmware ships placeholders for fields that were never programmed. Treating
// one as a serial merges every unprogrammed board into a single asset.
func TestParseWindowsHardware_DropsFirmwarePlaceholders(t *testing.T) {
	hw, err := ParseWindowsHardware([]byte(
		`{"Vendor":"To be filled by O.E.M.","Name":"Default string","UUID":"00000000-0000-0000-0000-000000000000","Serial":"System Serial Number","BIOSVersion":"2.1"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hw.Vendor != "" || hw.Model != "" || hw.Serial != "" || hw.UUID != "" {
		t.Fatalf("a firmware placeholder was stored as an identity: %+v", hw)
	}
}

func TestParseWindowsPackages(t *testing.T) {
	pkgs, err := ParseWindowsPackages([]byte(fixture(t, "windows", "packages.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pkgs) != 5 {
		t.Fatalf("got %d packages, want 5", len(pkgs))
	}
	if pkgs[0].Name != "Microsoft Edge" || pkgs[0].Version != "126.0.2592.87" {
		t.Errorf("first package: %+v", pkgs[0])
	}
	for _, p := range pkgs {
		if p.PURL != "" {
			t.Errorf("there is no purl type for a Windows installed program; got %q on %s", p.PURL, p.Name)
		}
		if p.Manager != "windows_registry" {
			t.Errorf("manager: %+v", p)
		}
	}
}

// PowerShell 5.1's pipeline form collapses a single result to a bare object. A
// host with exactly one installed program is not a host with none.
func TestParseWindowsPackages_AcceptsASingleBareObject(t *testing.T) {
	pkgs, err := ParseWindowsPackages([]byte(`{"Name":"Only Thing","Version":"1.0","Vendor":"Example"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "Only Thing" {
		t.Fatalf("a single-object result was lost: %+v", pkgs)
	}
}

func TestParseWindowsListeners(t *testing.T) {
	listeners, err := ParseWindowsListeners([]byte(fixture(t, "windows", "listeners.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(listeners) != 5 {
		t.Fatalf("got %d proven TCP listeners, want 5", len(listeners))
	}
	var udp int
	for _, l := range listeners {
		if l.Proto == "udp" {
			udp++
		}
	}
	if udp != 0 {
		t.Errorf("got %d UDP listener claims, want 0; Get-NetUDPEndpoint cannot prove role", udp)
	}
	bound, err := ParseWindowsBoundUDP([]byte(fixture(t, "windows", "listeners.json")))
	if err != nil || len(bound) != 2 {
		t.Fatalf("unknown-role UDP bindings = %+v, err=%v; want the two measured endpoints", bound, err)
	}
	byPort := map[int]Listener{}
	for _, l := range listeners {
		byPort[l.Port] = l
	}
	if byPort[5432].Address != "127.0.0.1" || byPort[5432].Process != "postgres" {
		t.Errorf("loopback-only service: %+v", byPort[5432])
	}
	if byPort[22].Process != "sshd" {
		t.Errorf("sshd: %+v", byPort[22])
	}
}

func TestWindowsSocketSnapshotsAcceptValidEmptyResults(t *testing.T) {
	listeners, err := ParseWindowsListeners([]byte("[]"))
	if err != nil || len(listeners) != 0 {
		t.Fatalf("empty TCP listener snapshot = %#v, %v", listeners, err)
	}
	bound, err := ParseWindowsBoundUDP([]byte("[]"))
	if err != nil || len(bound) != 0 {
		t.Fatalf("empty UDP binding snapshot = %#v, %v", bound, err)
	}
	if strings.Contains(psScriptListeners, "-State Listen") || strings.Contains(psScriptConnections, "-State Established") {
		t.Fatal("zero-match Get-NetTCPConnection query can throw instead of serializing an empty snapshot")
	}
}

func TestParseWindowsAdapters(t *testing.T) {
	ifaces, err := ParseWindowsAdapters([]byte(fixture(t, "windows", "adapters.json")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ifaces) != 3 {
		t.Fatalf("got %d adapters, want 3", len(ifaces))
	}
	byName := map[string]Interface{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}
	eth := byName["Ethernet"]
	// Windows spells a MAC with hyphens and upper case; the identifier
	// vocabulary is lower-case colon-separated, and a MAC that does not
	// normalise is a MAC that will never match the same NIC seen elsewhere.
	if eth.MAC != "b4:96:91:1a:2b:3c" {
		t.Errorf("MAC was not normalised: %q", eth.MAC)
	}
	if eth.State != "up" || len(eth.Addresses) != 2 {
		t.Errorf("Ethernet: %+v", eth)
	}
	if byName["Ethernet 2"].State != "down" {
		t.Errorf("a disconnected adapter should be down: %+v", byName["Ethernet 2"])
	}
	if !byName["vEthernet (Default Switch)"].Virtual {
		t.Errorf("a Hyper-V switch was not marked virtual")
	}
}

func TestParseWindowsCertStores(t *testing.T) {
	stores, err := ParseWindowsCertStores([]byte(fixture(t, "windows", "certstores.json")), 500)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(stores) != 3 {
		t.Fatalf("got %d stores, want 3 (Root, CA, My): %+v", len(stores), stores)
	}
	if stores[0].Path != `Cert:\LocalMachine\Root` || stores[0].Count != 2 {
		t.Errorf("Root store: path=%q count=%d", stores[0].Path, stores[0].Count)
	}

	// A 64-character thumbprint IS a SHA-256 hash and is recorded. A
	// 40-character one is SHA-1, and writing it into a field named
	// fingerprint_sha256 would silently fail every join it is meant to serve.
	if got := stores[0].Certs[0].FingerprintSHA256; got != "21819dbfeff0e5743117fbfa8f2591c320021fbcbec50a902933c6d28378e3ab" {
		t.Errorf("SHA-256 thumbprint was not kept: %q", got)
	}
	if got := stores[0].Certs[1].FingerprintSHA256; got != "" {
		t.Errorf("a 40-char SHA-1 thumbprint was stored in the sha256 field: %q", got)
	}
	if stores[0].Certs[1].SubjectDN == "" {
		t.Error("dropping the wrong-algorithm fingerprint must not drop the certificate")
	}
}

func keysOf(m map[string]Package) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
