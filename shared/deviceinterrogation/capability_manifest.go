package deviceinterrogation

import (
	"reflect"

	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// The capability declarations and endpoint lists, one function per collector.
// The vocabulary and the rules are in capabilities.go; the test that holds
// every line here to what the collector actually does is
// capability_conformance_test.go.
//
// Declarations were filled from the code on main, not from the programme
// spec's §A.3 table: where the two disagreed the code won, and the note says
// so. Every Gap names the finding and the slice; Unscheduled is a gap nothing
// in the programme closes yet.

// Collector names for the two interrogators that record no collection
// warnings, and so had no name before this manifest needed one.
const (
	databaseCollector = "database"
	httpCollector     = "http"
)

// collectorManifests maps each interrogator's concrete type to its manifest.
var collectorManifests = map[reflect.Type]func() CollectorManifest{
	reflect.TypeOf(&CiscoInterrogator{}):    ciscoManifest,
	reflect.TypeOf(&FortinetInterrogator{}): fortinetManifest,
	reflect.TypeOf(&PaloAltoInterrogator{}): paloAltoManifest,
	reflect.TypeOf(&F5Interrogator{}):       f5Manifest,
	reflect.TypeOf(&UnifiInterrogator{}):    unifiManifest,
	reflect.TypeOf(&SNMPInterrogator{}):     snmpManifest,
	reflect.TypeOf(&HTTPInterrogator{}):     httpManifest,
	reflect.TypeOf(&DatabaseInterrogator{}): databaseManifest,
}

// Every NotApplicable reason, named. NotApplicable takes an NAReason, and
// TestCollectorCapabilityManifests_NotApplicableReasonsAreNamed fails on any
// reason not listed in notApplicableReasons — so turning a Gap into a
// NotApplicable means picking (or adding) one of these, in the diff.
const (
	naNotSSHManaged      NAReason = "the collector reaches the device over its HTTPS API and opens no SSH session"
	naNotLB              NAReason = "not a load balancer: it states no virtual-server to pool-member dependencies"
	naSQLService         NAReason = "a database server, not a network device: no VLANs, neighbours or managed devices"
	naGenericEndpoint    NAReason = "a generic HTTPS endpoint, not a network device (to be replaced by a TLS-endpoint type, decision Q9)"
	naOSIsSoftware       NAReason = "the device's software is its operating system, recorded as os.name/os.version rather than as firmware"
	naDBHostFacts        NAReason = "the engine is not the host: os.* and hw.* belong to host inventory, not to the SQL session"
	naHTTPHostFacts      NAReason = "a generic HTTPS endpoint reports no system identity"
	naHTTPServedIsMgmt   NAReason = "the one TLS service a generic HTTPS endpoint serves is the endpoint it is reached on, recorded as mgmt.tls_chain"
	naF5NoDHCP           NAReason = "BIG-IP does not serve DHCP on its VLANs; it can only relay it"
	naF5NoSubordinates   NAReason = "a BIG-IP manages no subordinate devices"
	naF5LTMNoVPN         NAReason = "the LTM collector reads no VPN; APM network access is out of its scope"
	naSNMPNoTLS          NAReason = "the device is reached over SNMP; the collector has no TLS management session to probe"
	naSNMPNoSSH          NAReason = "the device is reached over SNMP; the collector opens no SSH session"
	naSNMPNoDHCPMIB      NAReason = "no standard MIB states DHCP server posture, and the collector reads standard MIBs only"
	naSNMPNoManaged      NAReason = "§A.3 n/a: a generic MIB-II agent reports no managed devices (stack members are ENTITY-MIB rows, see K-05)"
	naSNMPNoVPN          NAReason = "standard MIBs carry no VPN configuration"
	naSNMPNoTLSConfig    NAReason = "standard MIBs carry no TLS service configuration"
	naSNMPNoCerts        NAReason = "standard MIBs carry no certificates"
	naDBNoMgmtPlane      NAReason = "no management plane apart from the SQL service, whose TLS is tls.device_served"
	naDBNoSSH            NAReason = "the collector opens a SQL session, not SSH"
	naDBTransportOnAsset NAReason = "the SQL session is the service, not a management plane; its transport is on the asset (protocol TLS or NONE)"
)

// notApplicableReasons is the closed list of reasons.
var notApplicableReasons = []NAReason{
	naNotSSHManaged, naNotLB, naSQLService, naGenericEndpoint, naOSIsSoftware, naDBHostFacts,
	naHTTPHostFacts, naHTTPServedIsMgmt, naF5NoDHCP, naF5NoSubordinates, naF5LTMNoVPN,
	naSNMPNoTLS, naSNMPNoSSH, naSNMPNoDHCPMIB, naSNMPNoManaged, naSNMPNoVPN, naSNMPNoTLSConfig,
	naSNMPNoCerts, naDBNoMgmtPlane, naDBNoSSH, naDBTransportOnAsset,
}

func ciscoManifest() CollectorManifest {
	return CollectorManifest{
		Collector: ciscoCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:      Gap("K-01", "W4.1", "the HTTPS/ASDM management plane is never probed"),
			CapMgmtSSHHostKey:    Supplies(),
			CapMgmtSSHAlgorithms: Gap("K-01", "W4.1", "banner and host key only; kex, cipher and MAC are not recorded"),
			CapVLANAddressing:    Gap("K-02", "W4.2", "`show vlan brief` gives id and name; the VLAN interfaces (SVIs) are not read"),
			CapVLANDHCP:          Gap("K-02", "W4.2"),
			CapIPv6:              Gap("C-09", "W3.8"),
			CapNeighborEdges:     Supplies(),
			CapNeighborPosture:   Supplies(),
			CapEndpointPeers:     Gap("K-04", "W4.8", "ARP is read as a fact only"),
			CapAdmissionEvidence: Gap("P-16", "W4.7"),
			CapManagedSubjects:   Gap("K-05", "W4.9", "WLC access points and stack members"),
			CapLBDependencies:    NotApplicable(naNotLB),
			CapVPNCrypto:         Supplies("proven by REAL IOS `show crypto ipsec sa detail` and ASA IPsec and IKEv1 captures, plus the hand-written IKEv2 table; every row is placed on the interrogated device, UDP 500/4500, with the peer as vpn_peer_address (P-07, W1.5)"),
			CapVPNTunnelEdges:    Gap("K-09", "W4.4", "the remote peer is vpn_peer_address metadata on the device's own VPN rows (W1.5); no tunnel edge yet"),
			// Proven only by HAND-WRITTEN fixtures (the configured `ssl cipher`
			// lines): no real capture of an ASA's SSL settings is in the corpus.
			// The `show webvpn` asset is not counted — it carries only the
			// converter's defaulted "TLS 1.2" (P-04), and `show webvpn` is not an
			// ASA exec command at all (`show running-config webvpn` is).
			CapDeviceServedTLS:      Supplies("configured `ssl cipher` lists only, proven by hand-written fixtures; the WebVPN asset is a defaulted version (P-04, W1.2)"),
			CapCertificateInventory: Gap("M-06", "W2.4", "no certificate is collected (P-13)"),
			CapCollectionWarnings:   Supplies(),

			FactCapability(facts.KeyOSName):               Supplies(),
			FactCapability(facts.KeyOSVersion):            Supplies(),
			FactCapability(facts.KeyHWVendor):             Supplies(),
			FactCapability(facts.KeyHWModel):              Supplies(),
			FactCapability(facts.KeyHWSerial):             Supplies(),
			FactCapability(facts.KeyHWFirmwareVersion):    NotApplicable(naOSIsSoftware),
			FactCapability(facts.KeyNetUptimeSeconds):     Supplies(),
			FactCapability(facts.KeyNetInterfaces):        Supplies(),
			FactCapability(facts.KeyNetNeighbors):         Supplies(),
			FactCapability(facts.KeyNetVlans):             Supplies(),
			FactCapability(facts.KeyNetRouteNextHopCount): Gap("M-11", Unscheduled, "`show ip route` is refused by the command guard; a summary form needs a decision"),
			FactCapability(facts.KeyMgmtProtocol):         Supplies(),
			FactCapability(facts.KeyMgmtPlaintext):        Supplies("telnet read per platform — IOS VTY `transport input`, NX-OS `show feature`, the ASA / IOS-XR `telnet` section; no fact when the device gives no positive evidence either way (P-08)"),
		},
		Endpoints: []Endpoint{
			ciscoExec("show version", "software version, model, serial and uptime"),
			ciscoExec("show inventory", "chassis model and serial"),
			ciscoExec("show interfaces", "interface state, MAC and bandwidth"),
			ciscoExec("show ip interface brief", "interface addresses"),
			ciscoExec("show vlan brief", "VLAN ids and names"),
			ciscoExec("show cdp neighbors detail", "CDP neighbours and edges"),
			ciscoExec("show lldp neighbors detail", "LLDP neighbours and edges"),
			ciscoExec("show ip arp", "ARP neighbours (IOS, IOS-XE, NX-OS)"),
			ciscoExec("show arp", "ARP neighbours (IOS-XR, ASA)"),
			ciscoExec("show interface ip brief", "interface addresses (ASA)"),
			ciscoExec("show crypto map", "crypto maps (IPsec transform sets, PFS group)"),
			ciscoExec("show crypto ipsec sa", "IPsec security associations"),
			ciscoExec("show crypto isakmp sa", "ISAKMP (IKEv1) security associations (IOS, IOS-XE)"),
			ciscoExec("show crypto ikev1 sa detail", "IKEv1 security associations with the negotiated cipher and hash (ASA 8.4 and later)"),
			ciscoExec("show crypto ikev2 sa", "IKEv2 security associations"),
			ciscoExec("show ssl", "SSL/TLS versions and ciphers (ASA)"),
			// Not an ASA exec command (`show running-config webvpn` is); listed
			// because the collector sends it.
			ciscoExec("show webvpn", "WebVPN service (ASA) — not a valid ASA exec command"),
			{
				Transport: TransportSSH, Method: "exec", Target: "show running-config | include ssl cipher",
				Purpose: "configured SSL cipher lists — the only running-config form the collector may run",
				// The one privilege in this list that is certain: IOS restricts
				// `show running-config` to level 15 unless a parser view or a
				// `privilege exec` line grants it lower.
				Privilege: "privilege level 15, or a parser view granting `show running-config`",
			},
			{
				Transport: TransportSSH, Method: "exec", Target: "show running-config | include ^line vty|transport input",
				Purpose:   "whether the VTY lines accept telnet (IOS, IOS-XE) — the VTY `transport input` lines and nothing else",
				Privilege: "privilege level 15, or a parser view granting `show running-config`",
			},
			ciscoExec("show feature | include telnet", "whether the telnet feature is enabled (NX-OS)"),
			ciscoExec("show running-config telnet", "the telnet access configuration (IOS-XR, ASA): addresses, timeout, server count"),
			ciscoExec("show privilege", "the account's privilege level (IOS, IOS-XE)"),
			ciscoExec("show curpriv", "the account's privilege level (ASA)"),
			// Interactive-session lines, written only when a below-15 account
			// is raised with an enable secret (or the device refuses exec
			// channels). The secret itself is not a request: it is written
			// only at the Password: prompt `enable` produces.
			ciscoSession("enable", "raise a below-15 account to privileged EXEC (IOS, IOS-XE, ASA)"),
			ciscoSession("terminal length 0", "turn the pager off (IOS, IOS-XE, NX-OS, IOS-XR)"),
			ciscoSession("terminal pager 0", "turn the pager off (ASA)"),
			ciscoSession("exit", "leave the interactive session"),
		},
	}
}

// ciscoSession is a line written to an interactive CLI session that is not a
// `show` command.
func ciscoSession(line, purpose string) Endpoint {
	return Endpoint{Transport: TransportSSH, Method: "session", Target: line, Purpose: purpose}
}

func ciscoExec(command, purpose string) Endpoint {
	return Endpoint{Transport: TransportSSH, Method: "exec", Target: command, Purpose: purpose}
}

func fortinetManifest() CollectorManifest {
	return CollectorManifest{
		Collector: fortinetCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:      Gap("K-01", "W4.1"),
			CapMgmtSSHHostKey:    NotApplicable(naNotSSHManaged),
			CapMgmtSSHAlgorithms: NotApplicable(naNotSSHManaged),
			CapVLANAddressing:    Supplies(),
			CapVLANDHCP:          Gap("K-02", "W4.2", "`system.dhcp/server` is not read"),
			CapIPv6:              Gap("C-09", "W3.8"),
			CapNeighborEdges:     Gap("K-03", "W4.3", "`monitor/network/lldp/neighbors` is not read"),
			CapNeighborPosture:   Gap("K-03", "W4.3"),
			CapEndpointPeers:     Gap("K-04", "W4.8", "device inventory and DHCP leases are not read"),
			CapAdmissionEvidence: Gap("P-16", "W4.7"),
			CapManagedSubjects:   Gap("K-05", "W4.9", "FortiAP and FortiSwitch"),
			CapLBDependencies:    NotApplicable(naNotLB),
			CapVPNCrypto:         Supplies("IPsec phase 1 only; phase 2 is K-06, W4.4"),
			CapVPNTunnelEdges:    Gap("K-09", "W4.4"),
			CapDeviceServedTLS: Gap("M-02", "W3.3", "broken outright (C-04): FortiOS returns `vpn.ssl/settings` results as an OBJECT and the collector decodes a list, "+
				"so every real device yields a collection warning and no asset; the fields it would read (`cipher`/`tls_version`/`server_cert`) are not FortiOS's either — it answers "+
				"`ssl-min-proto-ver`/`servercert`/`algorithm`, so nothing about the TLS is measured; "+
				"`admin-server-cert` and SSL inspection profiles are K-07, W4.5"),
			CapCertificateInventory: Gap("P-13", "W2.4", "the local certificate store goes only to DeviceInfo"),
			CapCollectionWarnings:   Supplies(),

			FactCapability(facts.KeyOSName):               Supplies(),
			FactCapability(facts.KeyOSVersion):            Supplies(),
			FactCapability(facts.KeyHWVendor):             Supplies(),
			FactCapability(facts.KeyHWModel):              Supplies(),
			FactCapability(facts.KeyHWSerial):             Supplies(),
			FactCapability(facts.KeyHWFirmwareVersion):    NotApplicable(naOSIsSoftware),
			FactCapability(facts.KeyNetUptimeSeconds):     Gap("M-01", "W4.6", "§A.3 marked FortiGate uptime as supplied; no FortiOS call reads it"),
			FactCapability(facts.KeyNetInterfaces):        Supplies(),
			FactCapability(facts.KeyNetNeighbors):         Gap("K-03", "W4.3", "no neighbour table is read (LLDP W4.3, ARP W4.8)"),
			FactCapability(facts.KeyNetVlans):             Supplies(),
			FactCapability(facts.KeyNetRouteNextHopCount): Supplies(),
			FactCapability(facts.KeyMgmtProtocol):         Supplies(),
			FactCapability(facts.KeyMgmtPlaintext):        Supplies(),
		},
		Endpoints: []Endpoint{
			fortinetGet("/api/v2/cmdb/system/status", "model, serial, FortiOS version"),
			fortinetGet("/api/v2/cmdb/system/interface", "configured interfaces, addresses and VLAN tags"),
			fortinetGet("/api/v2/monitor/system/interface", "link state and negotiated speed"),
			fortinetGet("/api/v2/monitor/router/ipv4", "distinct next hops, counted; nothing else is kept"),
			fortinetGet("/api/v2/cmdb/vpn.ssl/settings", "SSL-VPN settings"),
			fortinetGet("/api/v2/cmdb/vpn.ipsec/phase1-interface", "IPsec phase-1 tunnels"),
			fortinetGet("/api/v2/cmdb/certificate/local", "local certificate store (public certificates; the private key is projected away)"),
		},
	}
}

func fortinetGet(path, purpose string) Endpoint {
	return Endpoint{Transport: TransportHTTPS, Method: "GET", Target: path, Purpose: purpose}
}

// PAN-OS XML API privileges follow the request `type`: the admin role's XML
// API tab has one permission per type.
const (
	panPrivilegeOp     = "admin role, XML API: Operational Requests"
	panPrivilegeConfig = "admin role, XML API: Configuration"
)

func paloAltoManifest() CollectorManifest {
	return CollectorManifest{
		Collector: panCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:         Gap("K-01", "W4.1"),
			CapMgmtSSHHostKey:       NotApplicable(naNotSSHManaged),
			CapMgmtSSHAlgorithms:    NotApplicable(naNotSSHManaged),
			CapVLANAddressing:       Gap("K-02", "W4.2", "data-plane subinterfaces are not turned into net.vlans"),
			CapVLANDHCP:             Gap("K-02", "W4.2"),
			CapIPv6:                 Gap("C-09", "W3.8"),
			CapNeighborEdges:        Supplies(),
			CapNeighborPosture:      Supplies(),
			CapEndpointPeers:        Gap("K-04", "W4.8", "ARP is read as a fact only"),
			CapAdmissionEvidence:    Gap("P-16", "W4.7"),
			CapManagedSubjects:      Gap("K-05", "W4.9", "Panorama-managed firewalls"),
			CapLBDependencies:       NotApplicable(naNotLB),
			CapVPNCrypto:            Gap("K-06", "W4.4", "IKE gateways, IKE/IPsec crypto profiles and GlobalProtect are not read"),
			CapVPNTunnelEdges:       Gap("K-09", "W4.4"),
			CapDeviceServedTLS:      Gap("M-03", "W4.5", "decryption profiles and rules are recorded with a name and a CA only — nothing about the TLS is measured (K-07)"),
			CapCertificateInventory: Gap("P-13", "W2.4", "only a CA name is collected"),
			CapCollectionWarnings:   Supplies(),

			FactCapability(facts.KeyOSName):               Supplies(),
			FactCapability(facts.KeyOSVersion):            Supplies(),
			FactCapability(facts.KeyHWVendor):             Supplies(),
			FactCapability(facts.KeyHWModel):              Supplies(),
			FactCapability(facts.KeyHWSerial):             Supplies(),
			FactCapability(facts.KeyHWFirmwareVersion):    NotApplicable(naOSIsSoftware),
			FactCapability(facts.KeyNetUptimeSeconds):     Supplies(),
			FactCapability(facts.KeyNetInterfaces):        Supplies(),
			FactCapability(facts.KeyNetNeighbors):         Supplies(),
			FactCapability(facts.KeyNetVlans):             Gap("K-02", "W4.2"),
			FactCapability(facts.KeyNetRouteNextHopCount): Gap("M-11", Unscheduled, "no routing call is made"),
			FactCapability(facts.KeyMgmtProtocol):         Supplies(),
			FactCapability(facts.KeyMgmtPlaintext):        Supplies(),
		},
		Endpoints: []Endpoint{
			{Transport: TransportHTTPS, Method: "POST", Target: "/api/", Name: "keygen",
				Body:    "form{password={credential},type=keygen,user={credential}}",
				Purpose: "exchange the username and password for an API key"},
			panOp("<show><system><info></info></system></show>", "show system info",
				"hostname, model, serial, PAN-OS version, uptime, management address"),
			panOp("<show><interface>all</interface></show>", "show interface all", "interfaces, addresses, VLAN tags, link state"),
			panOp("<show><arp><entry name='all'/></arp></show>", "show arp all", "layer-3 neighbours"),
			panOp("<show><lldp><neighbors>all</neighbors></lldp></show>", "show lldp neighbors all", "layer-2 neighbours and edges"),
			panConfigGet(panSSLDecryptXPath, "SSL decryption profiles"),
			panConfigGet(panSecurityRulesXPath, "security rules carrying an SSL-decrypt action"),
		},
	}
}

func panOp(cmd, name, purpose string) Endpoint {
	return Endpoint{Transport: TransportHTTPS, Method: "GET", Target: "/api/?type=op&cmd=" + cmd,
		Name: name, Purpose: purpose, Privilege: panPrivilegeOp}
}

func panConfigGet(xpath, purpose string) Endpoint {
	return Endpoint{Transport: TransportHTTPS, Method: "GET", Target: "/api/?type=config&action=get&xpath=" + xpath,
		Purpose: purpose, Privilege: panPrivilegeConfig}
}

func f5Manifest() CollectorManifest {
	return CollectorManifest{
		Collector: f5Collector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:         Gap("K-01", "W4.1"),
			CapMgmtSSHHostKey:       NotApplicable(naNotSSHManaged),
			CapMgmtSSHAlgorithms:    NotApplicable(naNotSSHManaged),
			CapVLANAddressing:       Supplies("from the self IPs"),
			CapVLANDHCP:             NotApplicable(naF5NoDHCP),
			CapIPv6:                 Supplies("VIP destinations and IPv6-only VLANs; a dual-stack VLAN keeps only its first self IP (M-04, W3.8)"),
			CapNeighborEdges:        Gap("K-03", "W4.3"),
			CapNeighborPosture:      Gap("K-03", "W4.3"),
			CapEndpointPeers:        Gap("M-06", Unscheduled, "the ARP table is not read; W4.8 does not list BIG-IP"),
			CapAdmissionEvidence:    Gap("P-16", "W4.7"),
			CapManagedSubjects:      NotApplicable(naF5NoSubordinates),
			CapLBDependencies:       Supplies(),
			CapVPNCrypto:            NotApplicable(naF5LTMNoVPN),
			CapVPNTunnelEdges:       NotApplicable(naF5LTMNoVPN),
			CapDeviceServedTLS:      Supplies("VIP client-ssl/server-ssl; versions default to TLS 1.2 when the profile names none (P-04, W1.2)"),
			CapCertificateInventory: Supplies("certificates read from config carry no data_source (P-13, W2.4)"),
			CapCollectionWarnings:   Supplies(),

			FactCapability(facts.KeyOSName):               Supplies(),
			FactCapability(facts.KeyOSVersion):            Supplies(),
			FactCapability(facts.KeyHWVendor):             Supplies(),
			FactCapability(facts.KeyHWModel):              Supplies(),
			FactCapability(facts.KeyHWSerial):             Supplies(),
			FactCapability(facts.KeyHWFirmwareVersion):    NotApplicable(naOSIsSoftware),
			FactCapability(facts.KeyNetUptimeSeconds):     Gap("K-08", "W4.6"),
			FactCapability(facts.KeyNetInterfaces):        Supplies(),
			FactCapability(facts.KeyNetNeighbors):         Gap("K-03", "W4.3"),
			FactCapability(facts.KeyNetVlans):             Supplies(),
			FactCapability(facts.KeyNetRouteNextHopCount): Gap("M-11", Unscheduled, "`/mgmt/tm/net/route` is on the customer doc's never-read list; a count needs a decision"),
			FactCapability(facts.KeyMgmtProtocol):         Supplies(),
			FactCapability(facts.KeyMgmtPlaintext):        Supplies(),
		},
		Endpoints: []Endpoint{
			{Transport: TransportHTTPS, Method: "POST", Target: "/mgmt/shared/authn/login",
				Body:    "json{loginProviderName=tmos,password={credential},username={credential}}",
				Purpose: "iControl REST token (login provider hard-coded to tmos, C-06)"},
			f5Get("/mgmt/tm/sys/version", "software version"),
			f5Get("/mgmt/tm/sys/hardware", "chassis serial and platform"),
			f5Get("/mgmt/tm/ltm/virtual", "virtual servers"),
			f5Get("/mgmt/tm/net/interface", "interfaces"),
			f5Get("/mgmt/tm/net/vlan", "VLANs"),
			f5Get("/mgmt/tm/net/self", "self IPs: each VLAN's subnet and the device's address on it"),
			f5Get("/mgmt/tm/ltm/pool?expandSubcollections=true", "pool members, for the dependency edges"),
			f5Get("/mgmt/tm/ltm/profile/client-ssl", "client SSL profiles"),
			f5Get("/mgmt/tm/ltm/profile/server-ssl", "server SSL profiles"),
			f5Get("/mgmt/tm/sys/crypto/cert/{name}", "each profile certificate's public half"),
		},
	}
}

func f5Get(path, purpose string) Endpoint {
	return Endpoint{Transport: TransportHTTPS, Method: "GET", Target: path, Purpose: purpose}
}

func unifiManifest() CollectorManifest {
	return CollectorManifest{
		Collector: unifiCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:         Supplies(),
			CapMgmtSSHHostKey:       NotApplicable(naNotSSHManaged),
			CapMgmtSSHAlgorithms:    NotApplicable(naNotSSHManaged),
			CapVLANAddressing:       Supplies(),
			CapVLANDHCP:             Supplies(),
			CapIPv6:                 Gap("M-05", "W3.8", "networkconf IPv6 settings are not read"),
			CapNeighborEdges:        Supplies(),
			CapNeighborPosture:      Supplies(),
			CapEndpointPeers:        Supplies(),
			CapAdmissionEvidence:    Supplies("controller inventory and clients; its LLDP neighbours carry none (P-16, W4.7)"),
			CapManagedSubjects:      Supplies(),
			CapLBDependencies:       NotApplicable(naNotLB),
			CapVPNCrypto:            Supplies(),
			CapVPNTunnelEdges:       Gap("K-09", "W4.4", "the peer stays in metadata"),
			CapDeviceServedTLS:      Gap("M-03", "W4.5", "managed devices are recorded as TLS assets with nothing measured; no gateway-served TLS is read"),
			CapCertificateInventory: Supplies("the management plane's chain only"),
			CapCollectionWarnings:   Supplies(),

			FactCapability(facts.KeyOSName):               Gap("M-12", Unscheduled, "the controller's own UniFi OS / Network version is not emitted as a fact"),
			FactCapability(facts.KeyOSVersion):            Gap("M-12", Unscheduled, "the controller's own UniFi OS / Network version is not emitted as a fact"),
			FactCapability(facts.KeyHWVendor):             Supplies(),
			FactCapability(facts.KeyHWModel):              Supplies("for managed devices"),
			FactCapability(facts.KeyHWSerial):             Supplies("for managed devices"),
			FactCapability(facts.KeyHWFirmwareVersion):    Supplies("for managed devices"),
			FactCapability(facts.KeyNetUptimeSeconds):     Supplies("for managed devices"),
			FactCapability(facts.KeyNetInterfaces):        Supplies(),
			FactCapability(facts.KeyNetNeighbors):         Supplies(),
			FactCapability(facts.KeyNetVlans):             Supplies(),
			FactCapability(facts.KeyNetRouteNextHopCount): Gap("M-11", Unscheduled, "no routing call is made"),
			FactCapability(facts.KeyMgmtProtocol):         Supplies(),
			FactCapability(facts.KeyMgmtPlaintext):        Supplies(),
		},
		Endpoints: []Endpoint{
			{Transport: TransportHTTPS, Method: "POST", Target: "/api/auth/login", Body: unifiLoginJSON,
				Purpose: "UniFi OS login (UDM/UDR/UCG); selects the /proxy/network prefix"},
			{Transport: TransportHTTPS, Method: "POST", Target: "/api/login", Body: unifiLoginJSON,
				Purpose: "legacy Network controller login (JSON)"},
			{Transport: TransportHTTPS, Method: "POST", Target: "/api/login", Body: "form{password={credential},username={credential}}",
				Purpose: "older legacy controller login (form-encoded), tried when the JSON login is refused"},
			unifiGet("/proxy/network/api/self", "controller session details (UniFi OS)"),
			unifiGet("/proxy/network/api/s/{site}/rest/networkconf", "networks, VLANs and VPNs (UniFi OS)"),
			unifiGet("/proxy/network/api/s/{site}/list/setting", "controller name (UniFi OS)"),
			unifiGet("/proxy/network/api/s/{site}/stat/device", "managed devices and their topology (UniFi OS)"),
			unifiGet("/proxy/network/api/s/{site}/stat/sta", "connected clients (UniFi OS)"),
			unifiGet("/api/self", "controller session details (legacy controller)"),
			unifiGet("/api/s/{site}/rest/networkconf", "networks, VLANs and VPNs (legacy controller)"),
			unifiGet("/api/s/{site}/list/setting", "controller name (legacy controller)"),
			unifiGet("/api/s/{site}/stat/device", "managed devices and their topology (legacy controller)"),
			unifiGet("/api/s/{site}/stat/sta", "connected clients (legacy controller)"),
		},
	}
}

const unifiLoginJSON = "json{password={credential},username={credential}}"

func unifiGet(path, purpose string) Endpoint {
	return Endpoint{Transport: TransportHTTPS, Method: "GET", Target: path, Purpose: purpose}
}

// snmpPrivilege is the one privilege SNMP has: read access through a view that
// includes the object.
func snmpPrivilege(mib string) string {
	return "SNMPv2c read community whose view includes " + mib
}

func snmpManifest() CollectorManifest {
	return CollectorManifest{
		Collector: snmpCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:         NotApplicable(naSNMPNoTLS),
			CapMgmtSSHHostKey:       NotApplicable(naSNMPNoSSH),
			CapMgmtSSHAlgorithms:    NotApplicable(naSNMPNoSSH),
			CapVLANAddressing:       Gap("K-02", "W4.2", "IP-MIB ipAddrTable and Q-BRIDGE VLAN names are not walked"),
			CapVLANDHCP:             NotApplicable(naSNMPNoDHCPMIB),
			CapIPv6:                 Gap("C-09", "W3.8"),
			CapNeighborEdges:        Supplies("LLDP only; no CDP-MIB (K-03, W4.3)"),
			CapNeighborPosture:      Gap("K-03", "W4.3", "LLDP-MIB capabilities and system description are not walked"),
			CapEndpointPeers:        Gap("K-04", "W4.8", "ARP is read as a fact only; the bridge FDB is not walked"),
			CapAdmissionEvidence:    Gap("P-16", "W4.7"),
			CapManagedSubjects:      NotApplicable(naSNMPNoManaged),
			CapLBDependencies:       NotApplicable(naNotLB),
			CapVPNCrypto:            NotApplicable(naSNMPNoVPN),
			CapVPNTunnelEdges:       NotApplicable(naSNMPNoVPN),
			CapDeviceServedTLS:      NotApplicable(naSNMPNoTLSConfig),
			CapCertificateInventory: NotApplicable(naSNMPNoCerts),
			CapCollectionWarnings:   Supplies(),

			FactCapability(facts.KeyOSName):               Gap("M-12", Unscheduled, "sysDescr is read but no os.* fact is emitted from it"),
			FactCapability(facts.KeyOSVersion):            Gap("M-12", Unscheduled, "sysDescr is read but no os.* fact is emitted from it"),
			FactCapability(facts.KeyHWVendor):             Supplies(),
			FactCapability(facts.KeyHWModel):              Supplies(),
			FactCapability(facts.KeyHWSerial):             Supplies(),
			FactCapability(facts.KeyHWFirmwareVersion):    Supplies(),
			FactCapability(facts.KeyNetUptimeSeconds):     Supplies(),
			FactCapability(facts.KeyNetInterfaces):        Supplies(),
			FactCapability(facts.KeyNetNeighbors):         Supplies(),
			FactCapability(facts.KeyNetVlans):             Gap("K-02", "W4.2"),
			FactCapability(facts.KeyNetRouteNextHopCount): Gap("M-11", Unscheduled, "the route table is deliberately not walked until a bounded summary is designed (snmp_ops.go)"),
			FactCapability(facts.KeyMgmtProtocol):         Supplies(),
			FactCapability(facts.KeyMgmtPlaintext):        Supplies(),
		},
		Endpoints: []Endpoint{
			snmpGet(snmpOIDSysDescr, "SNMPv2-MIB::sysDescr.0", "system description"),
			snmpGet(snmpOIDSysObjectID, "SNMPv2-MIB::sysObjectID.0", "vendor and product line"),
			snmpGet(snmpOIDSysName, "SNMPv2-MIB::sysName.0", "system name"),
			snmpGet(snmpOIDSysContact, "SNMPv2-MIB::sysContact.0", "contact"),
			snmpGet(snmpOIDSysLocation, "SNMPv2-MIB::sysLocation.0", "location"),
			snmpGet(snmpOIDSysUpTime, "SNMPv2-MIB::sysUpTime.0", "uptime"),
			snmpWalkEndpoint(snmpOIDEntPhysicalClass, "chassis row"),
			snmpWalkEndpoint(snmpOIDEntPhysicalMfgName, "chassis vendor"),
			snmpWalkEndpoint(snmpOIDEntPhysicalModelName, "chassis model"),
			snmpWalkEndpoint(snmpOIDEntPhysicalSerialNum, "chassis serial"),
			snmpWalkEndpoint(snmpOIDEntPhysicalFirmwareRev, "chassis firmware"),
			snmpWalkEndpoint(snmpOIDIfDescr, "interfaces"),
			snmpWalkEndpoint(snmpOIDIfName, "interface names"),
			snmpWalkEndpoint(snmpOIDIfPhysAddress, "interface MACs"),
			snmpWalkEndpoint(snmpOIDIfAdminStatus, "administrative state"),
			snmpWalkEndpoint(snmpOIDIfOperStatus, "operational state"),
			snmpWalkEndpoint(snmpOIDIfHighSpeed, "speed"),
			snmpWalkEndpoint(snmpOIDIfSpeed, "speed (legacy counter)"),
			snmpWalkEndpoint(snmpOIDLLDPRemChassisID, "LLDP neighbours"),
			snmpWalkEndpoint(snmpOIDLLDPRemPortID, "LLDP neighbour ports"),
			snmpWalkEndpoint(snmpOIDLLDPRemPortDesc, "LLDP neighbour port descriptions"),
			snmpWalkEndpoint(snmpOIDLLDPRemSysName, "LLDP neighbour names"),
			snmpWalkEndpoint(snmpOIDLLDPLocPortID, "local port of each LLDP neighbour"),
			snmpWalkEndpoint(snmpOIDIPNetToMediaPhysAddress, "ARP cache MACs"),
			snmpWalkEndpoint(snmpOIDIPNetToMediaNetAddress, "ARP cache addresses"),
		},
	}
}

func snmpGet(oid, name, purpose string) Endpoint {
	return Endpoint{Transport: TransportSNMP, Method: "get", Target: oid, Name: name, Purpose: purpose,
		Privilege: snmpPrivilege(name)}
}

func snmpWalkEndpoint(column, purpose string) Endpoint {
	name := snmpColumnNames[column]
	return Endpoint{Transport: TransportSNMP, Method: "walk", Target: column, Name: name, Purpose: purpose,
		Privilege: snmpPrivilege(name)}
}

func httpManifest() CollectorManifest {
	na := NotApplicable(naGenericEndpoint)
	host := NotApplicable(naHTTPHostFacts)
	return CollectorManifest{
		Collector: httpCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:         Supplies(),
			CapMgmtSSHHostKey:       NotApplicable(naNotSSHManaged),
			CapMgmtSSHAlgorithms:    NotApplicable(naNotSSHManaged),
			CapVLANAddressing:       na,
			CapVLANDHCP:             na,
			CapIPv6:                 na,
			CapNeighborEdges:        na,
			CapNeighborPosture:      na,
			CapEndpointPeers:        na,
			CapAdmissionEvidence:    na,
			CapManagedSubjects:      na,
			CapLBDependencies:       na,
			CapVPNCrypto:            na,
			CapVPNTunnelEdges:       na,
			CapDeviceServedTLS:      NotApplicable(naHTTPServedIsMgmt),
			CapCertificateInventory: Supplies("the probed chain; REST certificates land in Certificate, not the canonical array"),
			CapCollectionWarnings:   Gap("M-07", "W2.4", "a failed TLS probe is silent; W0.1 did not cover this collector (decision Q9 replaces it)"),

			FactCapability(facts.KeyOSName):               host,
			FactCapability(facts.KeyOSVersion):            host,
			FactCapability(facts.KeyHWVendor):             host,
			FactCapability(facts.KeyHWModel):              host,
			FactCapability(facts.KeyHWSerial):             host,
			FactCapability(facts.KeyHWFirmwareVersion):    host,
			FactCapability(facts.KeyNetUptimeSeconds):     host,
			FactCapability(facts.KeyNetInterfaces):        na,
			FactCapability(facts.KeyNetNeighbors):         na,
			FactCapability(facts.KeyNetVlans):             na,
			FactCapability(facts.KeyNetRouteNextHopCount): na,
			FactCapability(facts.KeyMgmtProtocol):         Gap("M-13", Unscheduled, "the probed HTTPS management plane is not recorded as mgmt.protocol"),
			FactCapability(facts.KeyMgmtPlaintext):        Gap("M-13", Unscheduled, "the probed HTTPS management plane is not recorded as mgmt.plaintext"),
		},
		Endpoints: []Endpoint{
			{Transport: TransportHTTPS, Method: "GET", Target: "/api/v1/certificates",
				Purpose: "certificate list (the path is configurable per device: metadata cert_path)"},
		},
	}
}

func databaseManifest() CollectorManifest {
	na := NotApplicable(naSQLService)
	host := NotApplicable(naDBHostFacts)
	sslinfo := "any login role; ssl_is_used() and ssl_cipher() need the sslinfo extension in the target database"
	return CollectorManifest{
		Collector: databaseCollector,
		Declarations: map[Capability]Declaration{
			CapMgmtTLSChain:         NotApplicable(naDBNoMgmtPlane),
			CapMgmtSSHHostKey:       NotApplicable(naDBNoSSH),
			CapMgmtSSHAlgorithms:    NotApplicable(naDBNoSSH),
			CapVLANAddressing:       na,
			CapVLANDHCP:             na,
			CapIPv6:                 na,
			CapNeighborEdges:        na,
			CapNeighborPosture:      na,
			CapEndpointPeers:        na,
			CapAdmissionEvidence:    na,
			CapManagedSubjects:      na,
			CapLBDependencies:       na,
			CapVPNCrypto:            na,
			CapVPNTunnelEdges:       na,
			CapDeviceServedTLS:      Supplies("the session's own TLS version and cipher, when SSL is on"),
			CapCertificateInventory: Gap("M-13", Unscheduled, "the server certificate is never read"),
			CapCollectionWarnings:   Gap("M-07", "W2.4", "every failed query is skipped silently; W0.1 did not cover this collector"),

			FactCapability(facts.KeyOSName):               host,
			FactCapability(facts.KeyOSVersion):            host,
			FactCapability(facts.KeyHWVendor):             host,
			FactCapability(facts.KeyHWModel):              host,
			FactCapability(facts.KeyHWSerial):             host,
			FactCapability(facts.KeyHWFirmwareVersion):    host,
			FactCapability(facts.KeyNetUptimeSeconds):     host,
			FactCapability(facts.KeyNetInterfaces):        na,
			FactCapability(facts.KeyNetNeighbors):         na,
			FactCapability(facts.KeyNetVlans):             na,
			FactCapability(facts.KeyNetRouteNextHopCount): na,
			FactCapability(facts.KeyMgmtProtocol):         NotApplicable(naDBTransportOnAsset),
			FactCapability(facts.KeyMgmtPlaintext):        NotApplicable(naDBTransportOnAsset),
		},
		Endpoints: []Endpoint{
			dbQuery("SELECT version()", "PostgreSQL version", "any login role"),
			dbQuery("SELECT ssl_is_used()", "whether this session is TLS (PostgreSQL)", sslinfo),
			dbQuery("SELECT ssl_cipher(), version()", "this session's cipher (PostgreSQL)", sslinfo),
			dbQuery("SELECT name, setting FROM pg_settings WHERE name = $1",
				"ssl, ssl_min_protocol_version, ssl_max_protocol_version, ssl_ciphers, ssl_prefer_server_ciphers, password_encryption (PostgreSQL)",
				"any login role"),
			dbQuery("SELECT setting FROM pg_settings WHERE name = 'ssl'", "whether SSL is on (PostgreSQL)", "any login role"),
			dbQuery("SELECT VERSION()", "MySQL version", "any login account"),
			dbQuery("SHOW VARIABLES WHERE Variable_name LIKE '%ssl%' OR Variable_name LIKE '%tls%' OR Variable_name LIKE '%encrypt%'",
				"TLS and encryption variables, filtered to an allowlist before anything is kept (MySQL)", "any login account"),
			dbQuery("SELECT @@innodb_encrypt_tables", "at-rest table encryption (MariaDB; MySQL has no such variable and the query fails harmlessly)", "any login account"),
		},
	}
}

func dbQuery(sql, purpose, privilege string) Endpoint {
	return Endpoint{Transport: TransportSQL, Method: "query", Target: sql, Purpose: purpose, Privilege: privilege}
}
