package hostinventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// The Windows command set.
//
// Every one of these is a PowerShell script sent as `-EncodedCommand <base64>`.
// The encoding is not obfuscation — it is what makes ONE argv work through both
// a POSIX shell (remote, over OpenSSH) and cmd.exe (the Windows OpenSSH default
// shell), because base64 contains nothing either shell wants to interpret. See
// renderArgv in runner.go.
//
// Each script ends in ConvertTo-Json so the parser reads a document rather than
// column-aligned text whose width depends on the console.
//
// `-Depth 3` throughout: the default of 2 flattens a nested property to the
// string "System.Object[]", which silently turns a list into a word.
const (
	// psScriptOS asks for the operating system and the machine's own names.
	psScriptOS = `$ErrorActionPreference='Stop'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{
  Caption      = $os.Caption
  Version      = $os.Version
  BuildNumber  = $os.BuildNumber
  CSName       = $os.CSName
  Domain       = $cs.Domain
  PartOfDomain = $cs.PartOfDomain
} | ConvertTo-Json -Depth 3 -Compress`

	// psScriptHardware asks for the manufacturer's identity of the machine.
	psScriptHardware = `$ErrorActionPreference='Stop'
$p = Get-CimInstance Win32_ComputerSystemProduct
$b = Get-CimInstance Win32_BIOS
[pscustomobject]@{
  Vendor      = $p.Vendor
  Name        = $p.Name
  UUID        = $p.UUID
  Serial      = $b.SerialNumber
  BIOSVersion = $b.SMBIOSBIOSVersion
} | ConvertTo-Json -Depth 3 -Compress`

	// psScriptPackages reads the Uninstall registry keys, both the native and
	// the 32-bit-on-64-bit views. This is the same list Add/Remove Programs
	// shows, and it is a registry READ of four named values — not a wildcard
	// sweep of a key's contents.
	psScriptPackages = `$ErrorActionPreference='SilentlyContinue'
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty -Path $paths |
  Where-Object { $_.DisplayName } |
  Select-Object @{n='Name';e={$_.DisplayName}},
                @{n='Version';e={$_.DisplayVersion}},
                @{n='Vendor';e={$_.Publisher}} |
  Sort-Object Name |
  ConvertTo-Json -Depth 3 -Compress`

	// psScriptListeners asks only for sockets whose listening role Windows can
	// prove. Get-NetUDPEndpoint exposes no peer and UDP has no listen state, so
	// those bindings are collected separately as unknown-role evidence.
	psScriptListeners = `$ErrorActionPreference='Stop'
$rows = @()
$rows += Get-NetTCPConnection |
  Where-Object { $_.State -eq 'Listen' } |
  Select-Object @{n='Proto';e={'tcp'}},
                @{n='Address';e={$_.LocalAddress}},
                @{n='Port';e={$_.LocalPort}},
                @{n='PID';e={$_.OwningProcess}},
                @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress`

	psScriptBoundUDP = `$ErrorActionPreference='Stop'
$rows = Get-NetUDPEndpoint |
  Select-Object @{n='Address';e={$_.LocalAddress}},
                @{n='Port';e={$_.LocalPort}},
                @{n='PID';e={$_.OwningProcess}},
                @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress`

	psScriptConnections = `$ErrorActionPreference='Stop'
$rows = Get-NetTCPConnection |
  Where-Object { $_.State -eq 'Established' } |
  Select-Object @{n='Proto';e={'tcp'}},
                @{n='LocalAddress';e={$_.LocalAddress}},
				@{n='LocalPort';e={$_.LocalPort}},
                @{n='RemoteAddress';e={$_.RemoteAddress}},
                @{n='RemotePort';e={$_.RemotePort}},
                @{n='PID';e={$_.OwningProcess}},
                @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress`

	// psScriptAdapters asks for the network adapters and their addresses.
	psScriptAdapters = `$ErrorActionPreference='SilentlyContinue'
$rows = Get-NetAdapter | ForEach-Object {
  $ifIndex = $_.ifIndex
  [pscustomobject]@{
    Name      = $_.Name
    MAC       = $_.MacAddress
    Status    = $_.Status
    Virtual   = $_.Virtual
    Addresses = @(Get-NetIPAddress -InterfaceIndex $ifIndex |
                  ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress`

	// psScriptCertStores asks the LocalMachine trust stores for THREE
	// properties per certificate.
	//
	// `Get-ChildItem Cert:\...` returns X509Certificate2 objects that can carry
	// a private key and expose Export(). This Select-Object is the projection
	// that makes sure only subject, thumbprint and expiry ever reach the wire —
	// the collector-projection rule, applied to the one Windows API that would
	// otherwise hand us key material for free.
	psScriptCertStoresTemplate = `$ErrorActionPreference='SilentlyContinue'
$rows = @()
foreach ($store in @(%STORES%)) {
  $rows += Get-ChildItem -Path "Cert:\LocalMachine\$store" |
    Select-Object @{n='Store';e={$store}},
                  @{n='Subject';e={$_.Subject}},
                  @{n='Issuer';e={$_.Issuer}},
                  @{n='Thumbprint';e={$_.Thumbprint}},
                  @{n='NotAfter';e={$_.NotAfter.ToUniversalTime().ToString('o')}}
}
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress`
)

// powershellArgv wraps a script as a PowerShell -EncodedCommand invocation.
//
// -NoProfile because a profile can print a banner into stdout and break every
// parser downstream; -NonInteractive because a prompt on a remote session hangs
// until the timeout. The script is UTF-16LE base64, which is the encoding
// -EncodedCommand specifies.
func powershellArgv(script string) []string {
	return []string{
		"powershell", "-NoProfile", "-NonInteractive",
		"-EncodedCommand", encodePowerShell(script),
	}
}

// encodePowerShell renders a script as the UTF-16LE base64 -EncodedCommand
// wants.
func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// windowsCertStoreNames are the LocalMachine stores read, in the order the
// script visits them.
//
//	Root — the machine's trusted roots
//	CA   — its trusted intermediates
//	My   — the certificates the machine itself holds, which is where a server
//	       certificate with an attached private key lives. Only its subject,
//	       issuer, thumbprint and expiry leave the host (psScriptCertStores).
//
// The list is interpolated into the script rather than written twice, so the
// Go-side names and the PowerShell-side names cannot drift.
var windowsCertStoreNames = []string{"Root", "CA", "My"}

// psScriptCertStores is the certificate-store script with the store list
// filled in.
func psScriptCertStores() string {
	quoted := make([]string, 0, len(windowsCertStoreNames))
	for _, s := range windowsCertStoreNames {
		quoted = append(quoted, "'"+s+"'")
	}
	return strings.ReplaceAll(psScriptCertStoresTemplate, "%STORES%", strings.Join(quoted, ","))
}

func collectWindows(ctx context.Context, r Runner, rep *Report, opts Options) {
	collectWindowsHost(ctx, r, rep)
	collectWindowsHardware(ctx, r, rep)
	collectWindowsInterfaces(ctx, r, rep)
	collectWindowsPackages(ctx, r, rep, opts)
	collectWindowsListeners(ctx, r, rep)
	collectWindowsConnections(ctx, r, rep, opts)
	collectWindowsCertStores(ctx, r, rep, opts)
}

// winOS mirrors psScriptOS's output.
type winOS struct {
	Caption      string `json:"Caption"`
	Version      string `json:"Version"`
	BuildNumber  string `json:"BuildNumber"`
	CSName       string `json:"CSName"`
	Domain       string `json:"Domain"`
	PartOfDomain bool   `json:"PartOfDomain"`
}

func collectWindowsHost(ctx context.Context, r Runner, rep *Report) {
	out, err := runText(ctx, r, powershellArgv(psScriptOS))
	if err != nil {
		rep.fail(SectionHost, err)
		return
	}
	host, perr := ParseWindowsOS([]byte(out))
	if perr != nil {
		rep.fail(SectionHost, perr)
		return
	}
	rep.Host = host
	rep.mark(SectionHost, SectionOK)
}

// ParseWindowsOS projects the Win32_OperatingSystem / Win32_ComputerSystem
// answer onto Host.
//
// The FQDN is assembled ONLY when the machine is actually domain-joined.
// Win32_ComputerSystem.Domain holds "WORKGROUP" for a standalone machine, and
// gluing that onto the hostname would give every workgroup machine in the
// estate the same domain — a name that looks like an identity and is not one.
func ParseWindowsOS(b []byte) (Host, error) {
	var raw winOS
	if err := json.Unmarshal(b, &raw); err != nil {
		return Host{}, fmt.Errorf("Win32_OperatingSystem: %w", err)
	}
	h := Host{
		OS:        strings.TrimSpace(raw.Caption),
		OSVersion: strings.TrimSpace(raw.Version),
		Kernel:    strings.TrimSpace(raw.BuildNumber),
		Hostname:  strings.ToLower(strings.TrimSpace(raw.CSName)),
	}
	domain := strings.ToLower(strings.TrimSpace(raw.Domain))
	if raw.PartOfDomain && domain != "" && domain != "workgroup" && h.Hostname != "" {
		h.Domain = domain
		h.FQDN = h.Hostname + "." + domain
	}
	return h, nil
}

// winHardware mirrors psScriptHardware's output.
type winHardware struct {
	Vendor      string `json:"Vendor"`
	Name        string `json:"Name"`
	UUID        string `json:"UUID"`
	Serial      string `json:"Serial"`
	BIOSVersion string `json:"BIOSVersion"`
}

func collectWindowsHardware(ctx context.Context, r Runner, rep *Report) {
	out, err := runText(ctx, r, powershellArgv(psScriptHardware))
	if err != nil {
		rep.fail(SectionHardware, err)
		return
	}
	hw, perr := ParseWindowsHardware([]byte(out))
	if perr != nil {
		rep.fail(SectionHardware, perr)
		return
	}
	rep.Hardware = hw
	rep.mark(SectionHardware, SectionOK)
}

// ParseWindowsHardware projects the SMBIOS answer, dropping the firmware
// placeholders the same way the Linux DMI read does.
func ParseWindowsHardware(b []byte) (Hardware, error) {
	var raw winHardware
	if err := json.Unmarshal(b, &raw); err != nil {
		return Hardware{}, fmt.Errorf("Win32_ComputerSystemProduct: %w", err)
	}
	return Hardware{
		Vendor:   sanitiseDMI(raw.Vendor),
		Model:    sanitiseDMI(raw.Name),
		Serial:   sanitiseDMI(raw.Serial),
		UUID:     sanitiseDMI(raw.UUID),
		Firmware: strings.TrimSpace(raw.BIOSVersion),
	}, nil
}

// winAdapter mirrors psScriptAdapters's output.
type winAdapter struct {
	Name      string   `json:"Name"`
	MAC       string   `json:"MAC"`
	Status    string   `json:"Status"`
	Virtual   bool     `json:"Virtual"`
	Addresses []string `json:"Addresses"`
}

func collectWindowsInterfaces(ctx context.Context, r Runner, rep *Report) {
	out, err := runText(ctx, r, powershellArgv(psScriptAdapters))
	if err != nil {
		rep.fail(SectionInterfaces, err)
		return
	}
	ifaces, perr := ParseWindowsAdapters([]byte(out))
	if perr != nil {
		rep.fail(SectionInterfaces, perr)
		return
	}
	rep.Interfaces = ifaces
	rep.mark(SectionInterfaces, SectionOK)
}

// ParseWindowsAdapters projects Get-NetAdapter.
func ParseWindowsAdapters(b []byte) ([]Interface, error) {
	var raw []winAdapter
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("Get-NetAdapter: %w", err)
	}
	out := make([]Interface, 0, len(raw))
	for _, a := range raw {
		if strings.TrimSpace(a.Name) == "" {
			continue
		}
		entry := Interface{
			Name: a.Name,
			MAC:  normaliseMAC(a.MAC),
			// Get-NetAdapter says Virtual outright for a Hyper-V or loopback
			// adapter; the name heuristic still runs so a container's vEthernet
			// is caught even when the property is absent from an older build.
			Virtual: a.Virtual || isVirtualInterface(a.Name, false),
		}
		switch strings.ToLower(strings.TrimSpace(a.Status)) {
		case "up":
			entry.State = "up"
		case "down", "disconnected", "disabled":
			entry.State = "down"
		default:
			entry.State = "unknown"
		}
		for _, addr := range a.Addresses {
			if strings.TrimSpace(addr) != "" && !strings.HasPrefix(addr, "/") {
				entry.Addresses = append(entry.Addresses, addr)
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// winPackage mirrors psScriptPackages's output.
type winPackage struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
	Vendor  string `json:"Vendor"`
}

func collectWindowsPackages(ctx context.Context, r Runner, rep *Report, opts Options) {
	out, err := runText(ctx, r, powershellArgv(psScriptPackages))
	if err != nil {
		rep.fail(SectionPackages, err)
		return
	}
	pkgs, perr := ParseWindowsPackages([]byte(out))
	if perr != nil {
		rep.fail(SectionPackages, perr)
		return
	}
	rep.Packages = capPackages(pkgs, opts.maxPackages())
	rep.mark(SectionPackages, SectionOK)
}

// ParseWindowsPackages projects the Uninstall registry rows.
//
// No purl: there is no registered purl type for a Windows installed program,
// and minting `pkg:windows/...` would put a string that looks like a join key
// into a column consumers join on. Name, vendor and version carry the identity
// instead.
func ParseWindowsPackages(b []byte) ([]Package, error) {
	raw, err := unmarshalPSArray[winPackage](b)
	if err != nil {
		return nil, fmt.Errorf("uninstall registry: %w", err)
	}
	out := make([]Package, 0, len(raw))
	for _, p := range raw {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		out = append(out, Package{
			Name:    name,
			Version: strings.TrimSpace(p.Version),
			Vendor:  strings.TrimSpace(p.Vendor),
			Manager: "windows_registry",
		})
	}
	return out, nil
}

// winListener mirrors psScriptListeners's output.
type winListener struct {
	Proto   string `json:"Proto"`
	Address string `json:"Address"`
	Port    int    `json:"Port"`
	PID     int    `json:"PID"`
	Process string `json:"Process"`
}

func collectWindowsListeners(ctx context.Context, r Runner, rep *Report) {
	out, err := runText(ctx, r, powershellArgv(psScriptListeners))
	if err != nil {
		rep.fail(SectionListeners, err)
	} else if listeners, perr := ParseWindowsListeners([]byte(out)); perr != nil {
		rep.fail(SectionListeners, perr)
	} else {
		rep.Listeners = listeners
		rep.mark(SectionListeners, SectionOK)
	}

	udpOut, udpErr := runText(ctx, r, powershellArgv(psScriptBoundUDP))
	if udpErr != nil {
		rep.fail(SectionBoundUDP, udpErr)
	} else if sockets, err := ParseWindowsBoundUDP([]byte(udpOut)); err != nil {
		rep.fail(SectionBoundUDP, err)
	} else {
		rep.BoundUDPSockets = coalesceBoundUDP(sockets)
		rep.mark(SectionBoundUDP, SectionOK)
	}
}

// ParseWindowsListeners projects Get-NetTCPConnection / Get-NetUDPEndpoint.
func ParseWindowsListeners(b []byte) ([]Listener, error) {
	raw, err := unmarshalPSArray[winListener](b)
	if err != nil {
		return nil, fmt.Errorf("Get-NetTCPConnection: %w", err)
	}
	out := make([]Listener, 0, len(raw))
	for _, l := range raw {
		proto := strings.ToLower(strings.TrimSpace(l.Proto))
		if proto != "tcp" {
			continue
		}
		if l.Port <= 0 {
			continue
		}
		out = append(out, Listener{
			Proto:   proto,
			Address: strings.TrimSpace(l.Address),
			Port:    l.Port,
			Process: strings.TrimSpace(l.Process),
			PID:     l.PID,
		})
	}
	return out, nil
}

func ParseWindowsBoundUDP(b []byte) ([]BoundUDPSocket, error) {
	raw, err := unmarshalPSArray[winListener](b)
	if err != nil {
		return nil, fmt.Errorf("Get-NetUDPEndpoint: %w", err)
	}
	out := make([]BoundUDPSocket, 0, len(raw))
	for _, s := range raw {
		if p := strings.ToLower(strings.TrimSpace(s.Proto)); p != "" && p != "udp" {
			continue
		}
		out = append(out, BoundUDPSocket{Address: strings.TrimSpace(s.Address), Port: s.Port, Process: strings.TrimSpace(s.Process), PID: s.PID})
	}
	return out, nil
}

type winConnection struct {
	Proto         string `json:"Proto"`
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	PID           int    `json:"PID"`
	Process       string `json:"Process"`
}

func collectWindowsConnections(ctx context.Context, r Runner, rep *Report, opts Options) {
	if !opts.CollectConnections {
		return
	}
	if !rep.SectionOK(SectionListeners) {
		rep.fail(SectionConnections, errors.New("listener snapshot incomplete; established TCP direction cannot be determined"))
		return
	}
	out, err := runText(ctx, r, powershellArgv(psScriptConnections))
	if err != nil {
		rep.fail(SectionConnections, err)
		return
	}
	raw, err := unmarshalPSArray[winConnection]([]byte(out))
	if err != nil {
		rep.fail(SectionConnections, fmt.Errorf("Get-NetTCPConnection established: %w", err))
		return
	}
	connections := make([]Connection, 0, len(raw))
	for _, c := range raw {
		connections = append(connections, Connection{Proto: c.Proto, LocalAddress: c.LocalAddress, LocalPort: c.LocalPort, RemoteAddress: c.RemoteAddress, RemotePort: c.RemotePort, Process: c.Process, PID: c.PID})
	}
	rep.Connections = coalesceConnections(excludeAcceptedConnections(connections, rep.Listeners), opts.maxConnections())
	rep.mark(SectionConnections, SectionOK)
}

// winCert mirrors psScriptCertStores's output.
type winCert struct {
	Store      string `json:"Store"`
	Subject    string `json:"Subject"`
	Issuer     string `json:"Issuer"`
	Thumbprint string `json:"Thumbprint"`
	NotAfter   string `json:"NotAfter"`
}

func collectWindowsCertStores(ctx context.Context, r Runner, rep *Report, opts Options) {
	out, err := runText(ctx, r, powershellArgv(psScriptCertStores()))
	if err != nil {
		rep.fail(SectionCertStores, err)
		return
	}
	stores, perr := ParseWindowsCertStores([]byte(out), opts.maxCertsPerStore())
	if perr != nil {
		rep.fail(SectionCertStores, perr)
		return
	}
	rep.CertStores = stores
	rep.mark(SectionCertStores, SectionOK)
}

// ParseWindowsCertStores groups the certificate rows by store.
//
// The Thumbprint Windows reports is a SHA-1 hash, not SHA-256. It is recorded
// in FingerprintSHA256 ONLY when it is 64 hex characters — which is what a
// SHA-256 thumbprint would be on a host configured for one. A 40-character
// SHA-1 thumbprint is DROPPED rather than written into a field named sha256:
// the field is a join key, and a value of the wrong algorithm in it would fail
// to match the same certificate seen on the wire while looking like it should.
func ParseWindowsCertStores(b []byte, limit int) ([]CertStore, error) {
	raw, err := unmarshalPSArray[winCert](b)
	if err != nil {
		return nil, fmt.Errorf("Cert:\\LocalMachine: %w", err)
	}

	byStore := make(map[string]*CertStore, len(windowsCertStoreNames))
	order := make([]string, 0, len(windowsCertStoreNames))
	for _, c := range raw {
		storeName := strings.TrimSpace(c.Store)
		if storeName == "" {
			continue
		}
		path := `Cert:\LocalMachine\` + storeName
		store, ok := byStore[path]
		if !ok {
			store = &CertStore{Path: path}
			byStore[path] = store
			order = append(order, path)
		}
		store.Count++
		if len(store.Certs) >= limit {
			continue
		}
		entry := Cert{
			SubjectDN: strings.TrimSpace(c.Subject),
			IssuerDN:  strings.TrimSpace(c.Issuer),
			NotAfter:  strings.TrimSpace(c.NotAfter),
		}
		if tp := strings.ToLower(strings.TrimSpace(c.Thumbprint)); len(tp) == 64 {
			entry.FingerprintSHA256 = tp
		}
		store.Certs = append(store.Certs, entry)
	}

	out := make([]CertStore, 0, len(order))
	for _, path := range order {
		out = append(out, *byStore[path])
	}
	return out, nil
}

// unmarshalPSArray decodes a ConvertTo-Json document that is meant to be an
// array.
//
// `ConvertTo-Json -InputObject @($rows)` keeps a single-element result an
// array, and every script here uses that form — but PowerShell 5.1's pipeline
// form collapses one object to a bare `{...}`, and a host with exactly one
// installed program is not a host whose package list should silently be empty.
// A bare object is therefore accepted as a one-element array; empty output is
// an empty list, which is what `@()` renders to on some builds.
func unmarshalPSArray[T any](b []byte) ([]T, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var arr []T
	if err := json.Unmarshal([]byte(trimmed), &arr); err == nil {
		return arr, nil
	}
	var one T
	if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
		return nil, errors.New("output was neither a JSON array nor a JSON object")
	}
	return []T{one}, nil
}
