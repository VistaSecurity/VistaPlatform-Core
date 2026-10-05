package discovery

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// PortSet is an immutable, sorted, de-duplicated set of port numbers in
// 1–65535. The zero value is the empty set. Values share their backing array,
// which is safe because nothing ever writes to it after construction.
type PortSet struct {
	ports []uint16
}

const (
	// maxPortSpecLen bounds the text ParsePortSpec will look at. A spec is
	// typed by a person or sent by the API; the longest useful one (every
	// curated band spelled out) is a few hundred bytes. Anything far larger is
	// a mistake or an attempt to make the parser do work.
	maxPortSpecLen = 4096
	// maxPortSpecTokens bounds the comma-separated tokens for the same reason.
	maxPortSpecTokens = 1024
)

// portBits is a 65 536-bit set used while building a PortSet, so unions and
// ranges cost the same however large they are.
type portBits [65536 / 64]uint64

func (b *portBits) set(p uint16)      { b[p/64] |= 1 << (p % 64) }
func (b *portBits) has(p uint16) bool { return b[p/64]&(1<<(p%64)) != 0 }
func (b *portBits) setRange(lo, hi int) {
	for p := lo; p <= hi; p++ {
		b.set(uint16(p))
	}
}
func (b *portBits) addSet(s PortSet) {
	for _, p := range s.ports {
		b.set(p)
	}
}
func (b *portBits) removeSet(s PortSet) {
	for _, p := range s.ports {
		b[p/64] &^= 1 << (p % 64)
	}
}
func (b *portBits) portSet() PortSet {
	var out []uint16
	for p := 1; p <= 65535; p++ {
		if b.has(uint16(p)) {
			out = append(out, uint16(p))
		}
	}
	return PortSet{ports: out}
}

// NewPortSet builds a PortSet from individual port numbers. Duplicates are
// folded; a number outside 1–65535 is an error naming it.
func NewPortSet(ports ...int) (PortSet, error) {
	var b portBits
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return PortSet{}, fmt.Errorf("port %d is out of range 1-65535", p)
		}
		b.set(uint16(p))
	}
	return b.portSet(), nil
}

// mustPorts builds a preset from literals known at compile time.
func mustPorts(spec string) PortSet {
	s, err := ParsePortSpec(spec)
	if err != nil {
		panic("discovery: bad built-in port spec: " + err.Error())
	}
	return s
}

// ParsePortSpec parses a comma-separated list of ports and inclusive ranges,
// e.g. "22,80,8000-8100". Whitespace around tokens is ignored; overlapping
// entries are folded. Every error names the offending token: an empty token
// ("22,,80"), a port of 0 or above 65535, a reversed range ("100-80"), or
// anything that is not digits ("http", "+22", "1-2-3"). A spec longer than
// 4096 bytes or with more than 1024 tokens is refused outright.
func ParsePortSpec(spec string) (PortSet, error) {
	if len(spec) > maxPortSpecLen {
		return PortSet{}, fmt.Errorf("port spec is %d bytes; the limit is %d", len(spec), maxPortSpecLen)
	}
	return parsePortSpec(spec, maxPortSpecTokens)
}

// parsePortSpec is ParsePortSpec without the length bound, and with the token
// bound as a parameter (0 = none). The server re-reads specs it wrote itself
// (a plan's per-target ports, PortSet.String) through it: those are not
// caller input, and a collapsed set can legitimately exceed the request bounds.
func parsePortSpec(spec string, maxTokens int) (PortSet, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return PortSet{}, errors.New("port spec is empty")
	}
	tokens := strings.Split(trimmed, ",")
	if maxTokens > 0 && len(tokens) > maxTokens {
		return PortSet{}, fmt.Errorf("port spec has %d entries; the limit is %d", len(tokens), maxTokens)
	}
	var b portBits
	for i, raw := range tokens {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			return PortSet{}, fmt.Errorf("port spec entry %d is empty", i+1)
		}
		lo, hi, err := parsePortToken(tok)
		if err != nil {
			return PortSet{}, fmt.Errorf("port spec entry %q: %w", tok, err)
		}
		b.setRange(lo, hi)
	}
	return b.portSet(), nil
}

func parsePortToken(tok string) (int, int, error) {
	if strings.Count(tok, "-") > 1 {
		return 0, 0, errors.New("a range has exactly one '-'")
	}
	loText, hiText, isRange := strings.Cut(tok, "-")
	lo, err := parsePortNumber(strings.TrimSpace(loText))
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return lo, lo, nil
	}
	hi, err := parsePortNumber(strings.TrimSpace(hiText))
	if err != nil {
		return 0, 0, err
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("range start %d is greater than its end %d", lo, hi)
	}
	return lo, hi, nil
}

func parsePortNumber(s string) (int, error) {
	if s == "" {
		return 0, errors.New("missing port number")
	}
	// strconv.Atoi alone would accept "+22" and "-0"; a port is digits only.
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q is not a port number", s)
		}
	}
	if len(s) > 5 {
		return 0, fmt.Errorf("port %s is out of range 1-65535", s)
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is out of range 1-65535", n)
	}
	return n, nil
}

// Len reports how many ports the set holds.
func (s PortSet) Len() int { return len(s.ports) }

// Contains reports whether port is in the set.
func (s PortSet) Contains(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	_, ok := slices.BinarySearch(s.ports, uint16(port))
	return ok
}

func (s PortSet) contains16(port uint16) bool {
	_, ok := slices.BinarySearch(s.ports, port)
	return ok
}

// Ports returns the ports in ascending order, as a fresh slice.
func (s PortSet) Ports() []int {
	out := make([]int, len(s.ports))
	for i, p := range s.ports {
		out[i] = int(p)
	}
	return out
}

// Union returns the ports in s or o.
func (s PortSet) Union(o PortSet) PortSet {
	var b portBits
	b.addSet(s)
	b.addSet(o)
	return b.portSet()
}

// Without returns the ports in s that are not in o.
func (s PortSet) Without(o PortSet) PortSet {
	var b portBits
	b.addSet(s)
	b.removeSet(o)
	return b.portSet()
}

// String renders the set in ParsePortSpec form with runs collapsed to ranges,
// e.g. "22,80,8000-8100". The empty set renders as "".
func (s PortSet) String() string {
	var sb strings.Builder
	for i := 0; i < len(s.ports); {
		j := i
		for j+1 < len(s.ports) && s.ports[j+1] == s.ports[j]+1 {
			j++
		}
		if sb.Len() > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(int(s.ports[i])))
		if j > i {
			sb.WriteByte('-')
			sb.WriteString(strconv.Itoa(int(s.ports[j])))
		}
		i = j + 1
	}
	return sb.String()
}

// quickInfraPorts widens the crypto-identification ports (cryptoPortProtocols)
// into the Quick depth: the handful of ports whose presence most often
// identifies what a host IS, or that carry crypto behind an upgrade, so a
// quick pass still finds the server and the appliance, not only the TLS
// listener.
//
//	21 FTP (explicit FTPS via AUTH TLS)          23 Telnet (cleartext management is itself a finding)
//	25 SMTP (STARTTLS)                           53 DNS
//	80 HTTP (appliance UIs; often the only port) 88 Kerberos (domain controllers)
//	110 POP3 (STLS)                              135 MS-RPC endpoint mapper (Windows hosts)
//	143 IMAP (STARTTLS)                          389 LDAP (StartTLS)
//	587 mail submission (STARTTLS)               853 DNS over TLS
//	1433 SQL Server (TLS inside TDS)             1521 Oracle Net
//	3306 MySQL/MariaDB (TLS upgrade)             3389 RDP (TLS/CredSSP)
//	5432 PostgreSQL (SSLRequest)                 5900 VNC
//	5985/5986 WinRM (HTTP / HTTPS)               6443 Kubernetes API server
//	8080 alternate HTTP / proxies
const quickInfraPorts = "21,23,25,53,80,88,110,135,143,389,587,853,1433,1521,3306,3389,5432,5900,5985,5986,6443,8080"

// standardCuratedPorts is what the Standard depth adds above 1–1024 and the
// Quick set. It is OUR list, written from the services this product
// inventories — it is deliberately not derived from any scanner's
// frequency-ranked port data (nmap's nmap-services licence forbids reuse).
// Rationale per group; a change to it is a product change, which is why
// TestStandardPorts_Pinned pins the exact result.
var standardCuratedPorts = strings.Join([]string{
	// Databases and caches: SQL Server browser, Oracle TCPS, MySQL X protocol,
	// PostgreSQL alternates, Redis (+TLS port), Cassandra (inter-node, TLS
	// inter-node, CQL, CQL TLS), CouchDB (+TLS), InfluxDB, Elasticsearch
	// (HTTP, transport), memcached, CockroachDB, MongoDB (mongod, shard,
	// config), Db2.
	"1434,2483,2484,33060,5433,6380,7000,7001,9042,9142,5984,6984,8086,9200,9300,11211,26257,27017-27019,50000",
	// Message brokers and coordination: MQTT, NATS (client, cluster,
	// monitor), AMQP (RabbitMQ) + management UI, STOMP (+TLS), ActiveMQ
	// OpenWire (+TLS), Kafka (plain, TLS), ZooKeeper (+TLS), Erlang epmd.
	"1883,4222,6222,8222,5672,15671,15672,61613,61614,61616,61617,9092,9093,2181,2281,4369",
	// Remote management, VPN and directory: OpenVPN over TCP, PPTP, L2TP
	// control, VNC displays, AD Global Catalog (+LDAPS), AD Web Services,
	// WBEM/CIM (HTTP, HTTPS — storage arrays, hypervisors), Webmin, Cockpit,
	// Proxmox VE, HPE iLO remote console, alternate HTTPS 4443/7443.
	"1194,1723,1701,5901-5903,3268,3269,9389,5988,5989,10000,9090,8006,17988,17990,4443,7443",
	// Kubernetes and cluster infrastructure: etcd (client, peer), kubelet
	// (+read-only), kube-proxy health, controller-manager and scheduler
	// secure ports, RKE2 supervisor, MicroK8s API, Docker API (plain, TLS),
	// container registry, HashiCorp Vault (API, cluster), Consul (server RPC,
	// LAN/WAN gossip, HTTP, HTTPS, gRPC), Nomad (HTTP, RPC, serf), libvirt
	// (+TLS), Grafana.
	"2379,2380,10250,10255,10256,10257,10259,9345,16443,2375,2376,5000,5001,8200,8201,8300-8302,8500-8502,4646-4648,16509,16514,3000",
	// Alternate HTTP/TLS bands where appliances and application servers put
	// their consoles and APIs (Tomcat/AJP, WebLogic, WebSphere, JBoss,
	// GlassFish admin, MinIO, Prometheus exporters, 9443-style admin TLS):
	// a band, not single ports, because vendors pick neighbours of the
	// well-known number.
	"8000-8100,8180,8181,8440-8450,8800,8843,8880,8888,9000-9100,9440-9450,4848,18080,18443",
	// Other crypto-bearing or identifying services: SIP (+TLS), XMPP (client,
	// legacy TLS, server), syslog over TLS, HTTP proxies, SOCKS, NFS, iSCSI,
	// Zabbix (agent, server), Nagios NRPE, WS-Management alternate listener.
	"5060,5061,5222,5223,5269,6514,3128,1080,2049,3260,10050,10051,5666,47001",
}, ",")

// otPortList is the set of TCP ports that belong to industrial control and
// building-automation protocols. A device listening on one of these may be a
// PLC, RTU or controller whose TCP stack tolerates only one to three sessions
// and can fault on unexpected traffic, so the engine treats these ports
// specially (OTPolicy) wherever they appear in a scan.
//
//	102    ISO-TSAP: Siemens S7comm and IEC 61850 MMS
//	502    Modbus/TCP
//	789    Red Lion Crimson v3
//	802    Modbus/TCP Security (Modbus over TLS)
//	1911   Tridium Niagara Fox (building automation)
//	1962   Phoenix Contact PCWorx
//	2404   IEC 60870-5-104 (telecontrol)
//	2455   CODESYS runtime (WAGO and other CODESYS PLCs)
//	4840   OPC UA binary
//	4843   OPC UA over TLS
//	4911   Tridium Niagara Fox over TLS
//	5094   HART-IP
//	9600   OMRON FINS
//	18245  GE SRTP
//	18246  GE SRTP (secondary)
//	20000  DNP3
//	20547  ProConOS (KW-Software runtime)
//	44818  EtherNet/IP (CIP explicit messaging)
//	47808  BACnet/IP (normally UDP; a TCP listener here is a BACnet device too)
const otPortList = "102,502,789,802,1911,1962,2404,2455,4840,4843,4911,5094,9600,18245,18246,20000,20547,44818,47808"

var (
	otPortsOnce = sync.OnceValue(func() PortSet { return mustPorts(otPortList) })

	quickPortsOnce = sync.OnceValue(func() PortSet {
		var b portBits
		for p := range cryptoPortProtocols {
			b.set(uint16(p))
		}
		b.addSet(mustPorts(quickInfraPorts))
		return b.portSet()
	})

	standardPortsOnce = sync.OnceValue(func() PortSet {
		var b portBits
		b.setRange(1, 1024)
		b.addSet(QuickPorts())
		b.addSet(mustPorts(standardCuratedPorts))
		return b.portSet()
	})

	thoroughPortsOnce = sync.OnceValue(func() PortSet {
		var b portBits
		b.setRange(1, 65535)
		return b.portSet()
	})
)

// QuickPorts is the Quick depth: the curated crypto-identification ports
// (DefaultCryptoPorts) plus a small set of infrastructure and management ports
// that identify what a host is (see quickInfraPorts). Around forty ports.
func QuickPorts() PortSet { return quickPortsOnce() }

// StandardPorts is the Standard depth: every port in 1–1024, the Quick set,
// and a curated list of common service ports above 1024 — databases, message
// brokers, remote management and VPN, Kubernetes and cluster services, and
// the alternate HTTP/TLS bands (8000–8100, 8440–8450, 9000–9100, 9440–9450)
// where consoles and APIs live. See standardCuratedPorts for the rationale.
func StandardPorts() PortSet { return standardPortsOnce() }

// ThoroughPorts is the Thorough depth: all of 1–65535.
func ThoroughPorts() PortSet { return thoroughPortsOnce() }

// OTPorts is the set of industrial-control / building-automation TCP ports
// the engine handles under its OTPolicy (see otPortList for each port).
// Several fall inside the Standard and Thorough ranges; the policy, not the
// preset, decides how they are touched.
func OTPorts() PortSet { return otPortsOnce() }
