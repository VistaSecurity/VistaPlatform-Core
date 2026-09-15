package producers

// The configuration rule table, pinned.
//
// The table IS the producer's catalogue, so what it says is the substance of
// every finding the producer writes. Three things are tested here and each of
// them has a known way of going wrong:
//
//  1. the table's own shape — every rule names a registered kind, has a
//     detail, a why, and at least one way to fire;
//  2. matching — token boundaries (ftp / sftp / tftp), transport narrowing
//     (514/tcp is rsh, 514/udp is syslog), and the TLS guard;
//  3. the port-alone suppression — a measured service name that does not match
//     the rule stops the port rule, because a port is a hint and a measurement
//     is an answer.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

func TestConfigurationRulesAreWellFormed(t *testing.T) {
	if len(configurationRules) == 0 {
		t.Fatal("the rule table is empty; the producer can raise nothing")
	}
	ids := map[string]bool{}
	for _, r := range configurationRules {
		if ids[r.ID] {
			t.Errorf("duplicate rule id %q — the id is the citation on every finding it raises", r.ID)
		}
		ids[r.ID] = true

		if _, ok := findings.Get(findings.ProducerConfiguration, r.Kind); !ok {
			t.Errorf("rule %q raises kind %q, which the configuration producer does not emit", r.ID, r.Kind)
		}
		if strings.TrimSpace(r.Detail) == "" {
			t.Errorf("rule %q has no detail; its title would read with an empty {detail}", r.ID)
		}
		if strings.TrimSpace(r.Why) == "" {
			t.Errorf("rule %q has no `why`; a finding that cannot say what the exposure is cannot be triaged", r.ID)
		}
		if len(r.Names) == 0 && len(r.Ports) == 0 {
			t.Errorf("rule %q can never fire: no names and no ports", r.ID)
		}
		if r.PortAlone && len(r.Ports) == 0 {
			t.Errorf("rule %q sets PortAlone with no ports", r.ID)
		}
		switch r.Transport {
		case "", "tcp", "udp":
		default:
			t.Errorf("rule %q has transport %q; asset_endpoints stores tcp, udp or none", r.ID, r.Transport)
		}
		for _, n := range r.Names {
			if n != normaliseServiceText(n) {
				t.Errorf("rule %q needle %q is not in normalised form (%q) and can therefore never match",
					r.ID, n, normaliseServiceText(n))
			}
		}
	}
}

// What each row of the table CLAIMS, written out independently of the table.
//
// This is the pin, and it is deliberately a second copy. A sweep that feeds
// each rule its own ports proves reachability and nothing else: change 27019 to
// 27099 and the fixture changes with the expectation, so the test stays green
// on a rule that now matches a port MongoDB does not use. The values have no
// second source anywhere — the table is the catalogue — so the only thing that
// can pin them is a literal restatement that a reviewer sees change beside the
// rule it describes.
//
// Ports are "p,p/transport" with the transport the rule claims, or "any" for a
// transport-blind rule; "-" means the rule declares no port rule at all.
// Needles are the exact normalised needles, in order.
var wantConfigurationRules = map[string]struct {
	kind    string
	ports   string
	names   string
	portsOK bool // PortAlone: may this row fire with nothing measured?
}{
	"mgmt-telnet":  {findings.KindPlaintextManagement, "23,2323/tcp", "telnet telnetd in telnetd", true},
	"mgmt-ftp":     {findings.KindPlaintextManagement, "21/tcp", "ftp ftpd vsftpd proftpd pure ftpd wu ftpd", true},
	"mgmt-snmp-v1": {findings.KindPlaintextManagement, "161/udp", "snmpv1 snmp v1", false},
	"mgmt-snmp-v2c": {findings.KindPlaintextManagement, "161/udp",
		"snmpv2c snmpv2 snmp v2c snmp v2", false},
	"expose-redis":            {findings.KindInsecureServiceExposed, "6379/tcp", "redis redis server", true},
	"expose-memcached":        {findings.KindInsecureServiceExposed, "11211/any", "memcached memcache", true},
	"expose-mongodb":          {findings.KindInsecureServiceExposed, "27017,27018,27019/tcp", "mongod mongodb", true},
	"expose-elasticsearch":    {findings.KindInsecureServiceExposed, "9200,9300/tcp", "elasticsearch elastic search", true},
	"expose-etcd":             {findings.KindInsecureServiceExposed, "2379/tcp", "etcd", true},
	"expose-couchdb":          {findings.KindInsecureServiceExposed, "5984/tcp", "couchdb", true},
	"expose-docker-api":       {findings.KindInsecureServiceExposed, "2375/tcp", "dockerd docker api docker daemon", true},
	"expose-kubelet-readonly": {findings.KindInsecureServiceExposed, "10255/tcp", "kubelet", true},
	"expose-rsh": {findings.KindInsecureServiceExposed, "512,513,514/tcp",
		"rsh rshd in rshd rlogin rlogind in rlogind rexec rexecd", true},
	"expose-tftp":    {findings.KindInsecureServiceExposed, "69/udp", "tftp tftpd in tftpd", true},
	"expose-nfs":     {findings.KindInsecureServiceExposed, "2049/any", "nfs nfsd rpc nfsd", true},
	"expose-rpcbind": {findings.KindInsecureServiceExposed, "111/any", "rpcbind portmap portmapper", true},
}

// TestConfigurationRulesMatchTheirPins is the restatement, checked both ways:
// no rule may drift from its pin, and no rule may exist without one.
//
// Mutation-proven: change any port, transport, needle or PortAlone in the table
// and this goes red naming the row.
func TestConfigurationRulesMatchTheirPins(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range configurationRules {
		want, ok := wantConfigurationRules[r.ID]
		if !ok {
			t.Errorf("rule %q has no pin in wantConfigurationRules. Every row is a judgement we make and "+
				"maintain; adding one without restating what it claims means the next port typo ships green", r.ID)
			continue
		}
		seen[r.ID] = true
		if r.Kind != want.kind {
			t.Errorf("rule %q raises %q, pinned as %q", r.ID, r.Kind, want.kind)
		}
		if got := portsPin(r); got != want.ports {
			t.Errorf("rule %q claims ports %s, pinned as %s", r.ID, got, want.ports)
		}
		if got := strings.Join(r.Names, " "); got != want.names {
			t.Errorf("rule %q needles are %q, pinned as %q", r.ID, got, want.names)
		}
		if r.PortAlone != want.portsOK {
			t.Errorf("rule %q PortAlone = %v, pinned as %v — whether a port may fire on its own is the "+
				"difference between a hint and an answer", r.ID, r.PortAlone, want.portsOK)
		}
	}
	for id := range wantConfigurationRules {
		if !seen[id] {
			t.Errorf("pin for %q names no rule in the table; either the rule was removed or its id changed", id)
		}
	}
}

// portsPin renders a rule's ports the way wantConfigurationRules spells them.
func portsPin(r serviceRule) string {
	if len(r.Ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(r.Ports))
	for _, p := range r.Ports {
		parts = append(parts, strconv.Itoa(p))
	}
	transport := r.Transport
	if transport == "" {
		transport = "any"
	}
	return strings.Join(parts, ",") + "/" + transport
}

// EVERY row of the table, fired both ways.
//
// The pin above says what each row CLAIMS; this says each claim actually
// fires, and fires as itself. TestMatchConfigurationRules below covers the
// interesting cases by hand and reaches six of the sixteen rules — that leaves
// ten that nothing executes at all, so a rule shadowed by an earlier one of the
// same kind, or a needle that can never match, would ship green.
//
// Two directions per row:
//
//   - by NAME: the rule's own needle, with a real identification method. That
//     also suppresses every port rule (`measured`), so the only thing that can
//     fire is a needle — and the needles are distinct per rule, so the row that
//     fires must be this one.
//   - by PORT: the rule's own port and transport with nothing measured. A rule
//     that does NOT set PortAlone must fire nothing at all here, which is the
//     half that keeps `snmp` off port 161 (161 cannot tell v2c from v3, and v3
//     is the fix).
func TestEveryConfigurationRuleFiresOnItsOwnSignals(t *testing.T) {
	for _, r := range configurationRules {
		t.Run(r.ID+"/name", func(t *testing.T) {
			if len(r.Names) == 0 {
				t.Skip("no needles")
			}
			for _, needle := range r.Names {
				ep := endpointFacts{
					ServiceName:          needle,
					Port:                 firstPort(r),
					Transport:            ruleTransport(r),
					IdentificationMethod: "banner",
				}
				got := matchConfigurationRules(ep)
				if len(got) != 1 || got[0].Rule.ID != r.ID {
					t.Fatalf("service name %q matched %s, want exactly %s", needle, ruleIDs(got), r.ID)
				}
				if got[0].Signal != signalServiceName {
					t.Errorf("service name %q fired as %q, want %q", needle, got[0].Signal, signalServiceName)
				}
			}
		})

		t.Run(r.ID+"/port", func(t *testing.T) {
			if len(r.Ports) == 0 {
				t.Skip("no ports")
			}
			for _, port := range r.Ports {
				ep := endpointFacts{Port: port, Transport: ruleTransport(r)}
				got := matchConfigurationRules(ep)
				if !r.PortAlone {
					if len(got) != 0 {
						t.Fatalf("port %d fired %s on a rule that does not set PortAlone — a port the rule cannot decide from must raise nothing",
							port, ruleIDs(got))
					}
					continue
				}
				if len(got) != 1 || got[0].Rule.ID != r.ID {
					t.Fatalf("port %d/%s matched %s, want exactly %s", port, ruleTransport(r), ruleIDs(got), r.ID)
				}
				if got[0].Signal != signalPort {
					t.Errorf("port %d fired as %q, want %q — a port-derived finding must record that it was the port",
						port, got[0].Signal, signalPort)
				}
			}
		})

		// And the transport the rule does NOT claim fires nothing on its ports.
		// 514/udp is syslog, 69/tcp is not the TFTP this rule describes.
		t.Run(r.ID+"/wrong transport", func(t *testing.T) {
			if r.Transport == "" || !r.PortAlone {
				t.Skip("transport-blind, or not a port rule")
			}
			other := "udp"
			if r.Transport == "udp" {
				other = "tcp"
			}
			for _, port := range r.Ports {
				if got := matchConfigurationRules(endpointFacts{Port: port, Transport: other}); len(got) != 0 {
					t.Errorf("port %d/%s matched %s; this rule claims %s only", port, other, ruleIDs(got), r.Transport)
				}
			}
		})
	}
}

// firstPort is a rule's first port, or a port no rule claims.
func firstPort(r serviceRule) int {
	if len(r.Ports) > 0 {
		return r.Ports[0]
	}
	return 65000
}

// ruleTransport is the transport a rule claims, defaulting to tcp for the
// transport-blind ones so the fixture has a concrete value to carry.
func ruleTransport(r serviceRule) string {
	if r.Transport != "" {
		return r.Transport
	}
	return "tcp"
}

// Every kind the registry declares for this producer is either produced by a
// rule or explicitly accounted for. `default_credentials_exposed` is the one
// that is not produced, and this test is where that decision is recorded in
// code rather than only in a comment — so somebody who later adds a
// default-credential probe finds the list and updates it.
func TestEveryConfigurationKindIsAccountedFor(t *testing.T) {
	notProduced := map[string]string{
		findings.KindDefaultCredentialsExposed: "nothing in the product records that a vendor default credential was ACCEPTED; see the doc comment on ConfigurationProducer",
	}

	byRule := map[string]bool{}
	for _, r := range configurationRules {
		byRule[r.Kind] = true
	}
	for _, k := range findings.All {
		if k.Producer != findings.ProducerConfiguration {
			continue
		}
		_, excused := notProduced[k.Key]
		switch {
		case byRule[k.Key] && excused:
			t.Errorf("kind %q is both produced by a rule and listed as not produced — one of the two is stale", k.Key)
		case !byRule[k.Key] && !excused:
			t.Errorf("kind %q is in the registry, has no rule, and is not listed as deliberately unproduced. "+
				"A kind nothing writes is invisible: either add a rule or record why there is none", k.Key)
		}
	}
	for key := range notProduced {
		if _, ok := findings.Get(findings.ProducerConfiguration, key); !ok {
			t.Errorf("%q is listed as not produced but is no longer a registered kind", key)
		}
	}
}

func TestMatchConfigurationRules(t *testing.T) {
	cases := []struct {
		name string
		ep   endpointFacts
		// wantRule is the rule id expected, or "" for no match.
		wantRule   string
		wantSignal string
		why        string
	}{
		{
			name:       "telnet by process name",
			ep:         endpointFacts{ServiceName: "in.telnetd", Port: 23, Transport: "tcp", IdentificationMethod: "host_socket_owner"},
			wantRule:   "mgmt-telnet",
			wantSignal: signalServiceName,
		},
		{
			name:       "telnet by port when nothing measured the service",
			ep:         endpointFacts{Port: 23, Transport: "tcp"},
			wantRule:   "mgmt-telnet",
			wantSignal: signalPort,
		},
		{
			name: "sftp is not ftp",
			ep:   endpointFacts{ServiceName: "sftp-server", Port: 22, Transport: "tcp", IdentificationMethod: "host_socket_owner"},
			why:  "`ftp` as a substring matches `sftp`, and sftp is the encrypted one — the needle match must be on whole tokens",
		},
		{
			name:       "tftp is not ftp",
			ep:         endpointFacts{ServiceName: "in.tftpd", Port: 69, Transport: "udp", IdentificationMethod: "host_socket_owner"},
			wantRule:   "expose-tftp",
			wantSignal: signalServiceName,
			why:        "the tftp rule must win, not the ftp one",
		},
		{
			name:       "rsh on 514/tcp",
			ep:         endpointFacts{Port: 514, Transport: "tcp"},
			wantRule:   "expose-rsh",
			wantSignal: signalPort,
		},
		{
			name: "syslog on 514/udp is not rsh",
			ep:   endpointFacts{Port: 514, Transport: "udp"},
			why:  "514/udp is syslog; a transport-blind port rule raises a remote-shell finding on every log collector in the estate",
		},
		{
			name:       "redis by port",
			ep:         endpointFacts{Port: 6379, Transport: "tcp"},
			wantRule:   "expose-redis",
			wantSignal: signalPort,
		},
		{
			name: "a measured service that is not redis stops the redis port rule",
			ep: endpointFacts{
				ServiceName: "haproxy", Port: 6379, Transport: "tcp",
				IdentificationMethod: "host_socket_owner",
			},
			why: "the host named the process; a port cannot overrule a measurement",
		},
		{
			name: "a port_heuristic name does not count as a measurement",
			ep: endpointFacts{
				ServiceName: "HTTPS (alternate)", Port: 6379, Transport: "tcp",
				IdentificationMethod: "port_heuristic",
			},
			wantRule:   "expose-redis",
			wantSignal: signalPort,
			why:        "that name WAS derived from the port; treating it as corroboration counts the same guess twice",
		},
		{
			name: "TLS on an Elasticsearch port is not the unauthenticated default",
			ep:   endpointFacts{Port: 9200, Transport: "tcp", Protocol: "TLS"},
			why:  "an Elasticsearch behind transport security is the configuration this finding asks for",
		},
		{
			name: "SNMP on 161 does not fire on the port alone",
			ep:   endpointFacts{Port: 161, Transport: "udp"},
			why:  "161 cannot tell v2c from v3, and v3 is the fix — firing on the port reports the remediated device as unremediated",
		},
		{
			name:       "SNMP v2c named in the service version",
			ep:         endpointFacts{ServiceName: "snmp", ServiceVersion: "SNMPv2c", Port: 161, Transport: "udp", IdentificationMethod: "banner"},
			wantRule:   "mgmt-snmp-v2c",
			wantSignal: signalServiceName,
		},
		{
			name: "an unremarkable web server matches nothing",
			ep:   endpointFacts{ServiceName: "nginx", Port: 80, Transport: "tcp", IdentificationMethod: "banner"},
			why:  "there is no HTTP rule: no endpoint signal distinguishes a management console from a web server",
		},
		{
			name: "port 0 (an at-rest endpoint) matches nothing",
			ep:   endpointFacts{Port: 0, Transport: "none"},
		},
		{
			name:       "docker on 2375 is the plaintext daemon",
			ep:         endpointFacts{Port: 2375, Transport: "tcp"},
			wantRule:   "expose-docker-api",
			wantSignal: signalPort,
		},
		{
			name: "docker on 2376 is the TLS daemon and has no rule",
			ep:   endpointFacts{Port: 2376, Transport: "tcp"},
			why:  "2376 is the TLS port; it is a different configuration and not this finding",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchConfigurationRules(tc.ep)
			if tc.wantRule == "" {
				if len(got) != 0 {
					t.Fatalf("matched %v, want nothing. %s", ruleIDs(got), tc.why)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("matched %v, want exactly %q. %s", ruleIDs(got), tc.wantRule, tc.why)
			}
			if got[0].Rule.ID != tc.wantRule {
				t.Errorf("matched %q, want %q. %s", got[0].Rule.ID, tc.wantRule, tc.why)
			}
			if got[0].Signal != tc.wantSignal {
				t.Errorf("signal %q, want %q — the finding records which signal fired and they are not equally strong",
					got[0].Signal, tc.wantSignal)
			}
		})
	}
}

// One endpoint may match both kinds; it may never match one kind twice, because
// `findings_open_subject_uniq` allows one open row per (producer, kind,
// subject) and a second match could not be stored.
func TestMatchConfigurationRulesReturnsAtMostOnePerKind(t *testing.T) {
	// A name that hits two rules of the same kind: `telnet` and `ftp` are both
	// plaintext_management.
	got := matchConfigurationRules(endpointFacts{
		ServiceName:          "telnet ftp gateway",
		Port:                 23,
		Transport:            "tcp",
		IdentificationMethod: "banner",
	})
	seen := map[string]int{}
	for _, m := range got {
		seen[m.Rule.Kind]++
	}
	for kind, n := range seen {
		if n > 1 {
			t.Errorf("%d matches for kind %q on one endpoint; only one could ever be stored", n, kind)
		}
	}
}

// The table's order is its precedence, and the result must not depend on map
// iteration. A run whose finding order changes between passes is a run whose
// tests pass intermittently.
func TestMatchConfigurationRulesIsDeterministic(t *testing.T) {
	ep := endpointFacts{ServiceName: "telnet", Port: 6379, Transport: "tcp", IdentificationMethod: "banner"}
	first := ruleIDs(matchConfigurationRules(ep))
	for i := 0; i < 50; i++ {
		if got := ruleIDs(matchConfigurationRules(ep)); got != first {
			t.Fatalf("iteration %d returned %s, first call returned %s", i, got, first)
		}
	}
}

func TestNormaliseServiceText(t *testing.T) {
	for in, want := range map[string]string{
		"Redis-Server 7.0":   "redis server 7 0",
		"  OpenSSH_8.9p1  ":  "openssh 8 9p1",
		"HTTPS (alternate)":  "https alternate",
		"":                   "",
		"in.telnetd":         "in telnetd",
		"SNMPv2c":            "snmpv2c",
		"UniFi Controller":   "unifi controller",
		"---":                "",
		"rpc.nfsd (v4)":      "rpc nfsd v4",
		"Cisco IOS-XE 17.09": "cisco ios xe 17 09",
	} {
		if got := normaliseServiceText(in); got != want {
			t.Errorf("normaliseServiceText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEndpointLabel(t *testing.T) {
	for _, tc := range []struct {
		addr, fqdn string
		port       int
		transport  string
		want       string
	}{
		{addr: "198.51.100.4", port: 23, transport: "tcp", want: "198.51.100.4:23"},
		{addr: "", fqdn: "sw1.example.net", port: 161, transport: "udp", want: "sw1.example.net:161/udp"},
		{addr: "198.51.100.4", port: 0, transport: "none", want: "198.51.100.4"},
		{addr: "", fqdn: "", port: 80, transport: "tcp", want: "endpoint:80"},
	} {
		if got := endpointLabel(tc.addr, tc.fqdn, tc.port, tc.transport); got != tc.want {
			t.Errorf("endpointLabel(%q,%q,%d,%q) = %q, want %q", tc.addr, tc.fqdn, tc.port, tc.transport, got, tc.want)
		}
	}
}

// parseJSONBool is the three-valued read of `mgmt.plaintext`. Absent and false
// are DIFFERENT answers — standards/fact-keys.yaml says so on that key in
// as many words — and a scanner that collapsed them would make every
// unassessed device look assessed-and-clean.
func TestParseJSONBool(t *testing.T) {
	if v := parseJSONBool(nil); v != nil {
		t.Errorf("a missing fact parsed as %v, want nil (NOT ASSESSED)", *v)
	}
	if v := parseJSONBool([]byte("false")); v == nil {
		t.Error("an explicit false parsed as nil; false is an ANSWER, not an absence")
	} else if *v {
		t.Error("false parsed as true")
	}
	if v := parseJSONBool([]byte("true")); v == nil || !*v {
		t.Error("true did not parse as true")
	}
	if v := parseJSONBool([]byte(`"true"`)); v != nil {
		t.Errorf(`the STRING "true" parsed as %v; the registry types this key as boolean and a string is not one`, *v)
	}
}

func ruleIDs(ms []ruleMatch) string {
	if len(ms) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Rule.ID+"/"+m.Signal)
	}
	return "[" + strings.Join(out, " ") + "]"
}
