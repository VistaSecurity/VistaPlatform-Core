package producers

import (
	"sort"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// The `configuration_rules` catalogue — the registry names it as the
// `configuration` producer's catalogue, and this is it.
//
// # Why a Go table and not a database catalogue
//
// `eol_catalogue` and `vulnerability_matches` are MIRRORS: rows imported from a
// feed that moves without us, which is why they are tables an operator can see
// staleness on. This is not that. Every row below is a JUDGEMENT we make and
// maintain — "an unauthenticated Redis on the wire is a problem" is not a fact
// anybody publishes on a schedule — so it belongs in reviewed, tested code with
// the producer that reads it, not in a seeded table where it would be editable
// by anybody with database access and invisible in a diff.
//
// # What a rule may fire on
//
// Two signals, and the difference is recorded on every finding
// (`evidence.matched_by`) because they are not equally strong:
//
//	service_name  something MEASURED what is listening — a host naming the
//	              process holding the socket, a parsed banner, an interrogation.
//	              This is the real signal.
//	port          nothing measured the service and the port is all there is.
//	              Only rules that set PortAlone may fire on it, and only where
//	              the port is registered to one service and used for little
//	              else. A port is a hint; the seed's own rule for service
//	              identification says a confidently wrong label is worse than a
//	              generic one, and that applies twice over to a finding.
//
// A port rule is SUPPRESSED the moment something did measure the service and it
// was not this one: if the host says the process on 6379 is `haproxy`, it is not
// Redis, and firing anyway would be the port overruling the measurement.
// `service_identification_method = port_heuristic` does not count as a
// measurement — that name was derived from the port in the first place, so
// treating it as independent corroboration would be the same guess counted
// twice.
//
// # Two things deliberately NOT in this table
//
//   - **VNC.** ADR-0005 D3's kind description and the workstream brief both say
//     "VNC without auth". Nothing in the product measures whether a VNC
//     listener requires a password, and an authenticated VNC server exposed on
//     a management segment is not this finding. A rule that fired on "a VNC
//     port answered" would be reporting something it did not measure, so there
//     is no rule until there is a probe. Same reasoning, same answer, for X11.
//   - **SMBv1.** `shared/discovery/probe_smb.go` offers dialects 2.0.2 through
//     3.1.1 in its NEGOTIATE and records what came back, so a v1-only server
//     does not answer it at all and no endpoint column ever holds "SMB1". The
//     absence of a dialect is not evidence of v1 — it is evidence of no answer.
//     NFS, rpcbind and TFTP carry the "legacy file sharing" case meanwhile.
//
// Both are recorded here rather than silently omitted: the next person to read
// the brief beside the table should find the argument, not the gap.

// serviceRule is one row of the configuration rule table.
type serviceRule struct {
	// ID is the stable rule identifier. It travels on every finding as
	// `evidence.rule_id`, which is what makes a disputed judgement lead back to
	// the exact row that made it — the same job `catalogue_id` does for the
	// end-of-life producer.
	ID string
	// Kind is the finding kind this rule raises. One table, two kinds: what a
	// device is MANAGED over and what it EXPOSES are judged from the same
	// endpoint row and separating the tables would mean walking it twice.
	Kind string
	// Detail is the `{detail}` the registry's title_template substitutes — the
	// protocol or service, named the way an operator would say it.
	Detail string
	// Service is the human name for the evidence block.
	Service string
	// Names are the needles matched against the endpoint's measured service
	// name and version, already normalised (lowercase, single-spaced). Matching
	// is by whole TOKEN RUN, never substring: `ftp` must not match `sftp`, and
	// `tftp` must not match `ftp`.
	Names []string
	// Ports are the ports this service is registered on.
	Ports []int
	// Transport narrows a port rule to "tcp" or "udp"; empty means either.
	// Load-bearing on 514, where tcp is rsh and udp is syslog.
	Transport string
	// PortAlone allows the rule to fire with no measured service name. See the
	// package comment: only where the port is registered to one service.
	PortAlone bool
	// Why is the one clause that says what the exposure is, for the evidence
	// block. Generic to the rule, never to an instance.
	Why string
}

// signal values recorded on a finding as `evidence.matched_by`.
const (
	signalServiceName = "service_name"
	signalPort        = "port"
	signalFact        = "fact"
)

// configurationRules is the table, in precedence order within each kind.
//
// Scores and severities are NOT here: the registry owns them
// (`default_severity` / `score` per kind) and the writer refuses anything else.
// What this table owns is WHICH condition is the kind, which is the part the
// registry cannot express.
var configurationRules = []serviceRule{
	// ---------------------------------------------------------- plaintext mgmt
	//
	// The management plane in the clear. HTTP management is NOT here and that
	// is deliberate: no endpoint signal distinguishes a management console from
	// any other web server on port 80, so it is detected from the
	// `mgmt.protocol` / `mgmt.plaintext` facts an interrogation writes, on the
	// ASSET subject. See plaintextFromFacts in configuration.go.
	{
		ID:        "mgmt-telnet",
		Kind:      findings.KindPlaintextManagement,
		Detail:    "telnet",
		Service:   "Telnet",
		Names:     []string{"telnet", "telnetd", "in telnetd"},
		Ports:     []int{23, 2323},
		Transport: "tcp",
		PortAlone: true,
		Why:       "Telnet carries the login and every command that follows in cleartext.",
	},
	{
		ID:        "mgmt-ftp",
		Kind:      findings.KindPlaintextManagement,
		Detail:    "ftp",
		Service:   "FTP",
		Names:     []string{"ftp", "ftpd", "vsftpd", "proftpd", "pure ftpd", "wu ftpd"},
		Ports:     []int{21},
		Transport: "tcp",
		PortAlone: true,
		Why:       "FTP sends the credential and the transferred file in cleartext.",
	},
	{
		ID:      "mgmt-snmp-v1",
		Kind:    findings.KindPlaintextManagement,
		Detail:  "snmpv1",
		Service: "SNMP v1",
		Names:   []string{"snmpv1", "snmp v1"},
		// No port rule. 161 is SNMP, but the port cannot tell v1/v2c from v3,
		// and v3 with authPriv is the fix this finding asks for — so firing on
		// the port would report the remediated device as unremediated.
		Ports:     []int{161},
		Transport: "udp",
		PortAlone: false,
		Why:       "SNMP v1 authenticates with a community string sent in the clear.",
	},
	{
		ID:        "mgmt-snmp-v2c",
		Kind:      findings.KindPlaintextManagement,
		Detail:    "snmpv2c",
		Service:   "SNMP v2c",
		Names:     []string{"snmpv2c", "snmpv2", "snmp v2c", "snmp v2"},
		Ports:     []int{161},
		Transport: "udp",
		PortAlone: false,
		Why:       "SNMP v2c authenticates with a community string sent in the clear.",
	},

	// ------------------------------------------------------- insecure exposure
	//
	// Datastores whose shipped default is no authentication at all. The TLS
	// guard in matchConfigurationRules is what keeps a properly wrapped one
	// (an Elasticsearch 8 with transport security, an mTLS etcd) out of this
	// list.
	{
		ID:        "expose-redis",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "Redis",
		Service:   "Redis",
		Names:     []string{"redis", "redis server"},
		Ports:     []int{6379},
		Transport: "tcp",
		PortAlone: true,
		Why:       "Redis ships with no authentication and no transport encryption; anything that can reach the port can read and write every key.",
	},
	{
		ID:      "expose-memcached",
		Kind:    findings.KindInsecureServiceExposed,
		Detail:  "memcached",
		Service: "memcached",
		Names:   []string{"memcached", "memcache"},
		Ports:   []int{11211},
		// Either transport: the UDP listener is also the reflection-amplifier.
		Transport: "",
		PortAlone: true,
		Why:       "memcached has no authentication, and its UDP listener is a reflection amplifier as well as a data leak.",
	},
	{
		ID:        "expose-mongodb",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "MongoDB",
		Service:   "MongoDB",
		Names:     []string{"mongod", "mongodb"},
		Ports:     []int{27017, 27018, 27019},
		Transport: "tcp",
		PortAlone: true,
		Why:       "A MongoDB instance started without --auth serves every database to anything that can reach it.",
	},
	{
		ID:        "expose-elasticsearch",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "Elasticsearch",
		Service:   "Elasticsearch",
		Names:     []string{"elasticsearch", "elastic search"},
		Ports:     []int{9200, 9300},
		Transport: "tcp",
		PortAlone: true,
		Why:       "An Elasticsearch node reachable over plain HTTP exposes every index, and its _cluster API, to anything on the segment.",
	},
	{
		ID:        "expose-etcd",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "etcd",
		Service:   "etcd",
		Names:     []string{"etcd"},
		Ports:     []int{2379},
		Transport: "tcp",
		PortAlone: true,
		Why:       "etcd's client port without client certificates hands over the cluster's entire configuration store, secrets included.",
	},
	{
		ID:        "expose-couchdb",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "CouchDB",
		Service:   "CouchDB",
		Names:     []string{"couchdb"},
		Ports:     []int{5984},
		Transport: "tcp",
		PortAlone: true,
		Why:       "CouchDB in admin-party mode grants administrative access to every caller.",
	},

	// Debug and control interfaces that are, by construction, remote code
	// execution for whoever reaches them.
	{
		ID:      "expose-docker-api",
		Kind:    findings.KindInsecureServiceExposed,
		Detail:  "the Docker daemon API",
		Service: "Docker daemon API",
		Names:   []string{"dockerd", "docker api", "docker daemon"},
		// 2375 only. 2376 is the TLS port and is a different configuration.
		Ports:     []int{2375},
		Transport: "tcp",
		PortAlone: true,
		Why:       "The unauthenticated Docker API is root on the host: any caller can start a privileged container mounting the filesystem.",
	},
	{
		ID:        "expose-kubelet-readonly",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "the kubelet read-only port",
		Service:   "kubelet read-only port",
		Names:     []string{"kubelet"},
		Ports:     []int{10255},
		Transport: "tcp",
		PortAlone: true,
		Why:       "The kubelet read-only port serves pod specs and node state with no authentication at all.",
	},

	// Legacy remote shells. Plaintext AND host-trust authenticated, which is
	// why they are an exposure rather than only a confidentiality problem.
	{
		ID:      "expose-rsh",
		Kind:    findings.KindInsecureServiceExposed,
		Detail:  "rsh/rlogin",
		Service: "rsh / rlogin / rexec",
		Names:   []string{"rsh", "rshd", "in rshd", "rlogin", "rlogind", "in rlogind", "rexec", "rexecd"},
		// TCP only, and 514 is the reason: 514/tcp is the rsh `cmd` service,
		// 514/udp is syslog. A transport-blind rule here would raise a
		// remote-shell finding on every syslog collector in the estate.
		Ports:     []int{512, 513, 514},
		Transport: "tcp",
		PortAlone: true,
		Why:       "rsh, rlogin and rexec authenticate on host trust and carry the session in cleartext.",
	},

	// Legacy file sharing.
	{
		ID:        "expose-tftp",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "TFTP",
		Service:   "TFTP",
		Names:     []string{"tftp", "tftpd", "in tftpd"},
		Ports:     []int{69},
		Transport: "udp",
		PortAlone: true,
		Why:       "TFTP has no authentication of any kind, and is routinely left serving device configuration and firmware.",
	},
	{
		ID:        "expose-nfs",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "NFS",
		Service:   "NFS",
		Names:     []string{"nfs", "nfsd", "rpc nfsd"},
		Ports:     []int{2049},
		Transport: "",
		PortAlone: true,
		Why:       "NFS without Kerberos authorises by client-asserted uid, so any host that can mount the export is any user on it.",
	},
	{
		ID:        "expose-rpcbind",
		Kind:      findings.KindInsecureServiceExposed,
		Detail:    "rpcbind",
		Service:   "rpcbind / portmapper",
		Names:     []string{"rpcbind", "portmap", "portmapper"},
		Ports:     []int{111},
		Transport: "",
		PortAlone: true,
		Why:       "rpcbind enumerates every RPC service on the host to any caller, and its UDP listener is a reflection amplifier.",
	},
}

// endpointFacts is what a rule is matched against: one endpoint, reduced to the
// signals a rule may read.
//
// Deliberately not the whole row. A rule must not be able to reach a credential,
// a banner or anything else the endpoint happens to carry — the table above is
// reviewed on the assumption that these five fields are all it can see.
type endpointFacts struct {
	// ServiceName and ServiceVersion as measured, verbatim.
	ServiceName    string
	ServiceVersion string
	// IdentificationMethod is how the name was arrived at. `port_heuristic`
	// means the name WAS the port, which is why it does not count as a
	// measurement for the port-rule suppression.
	IdentificationMethod string
	Port                 int
	Transport            string
	// Protocol is the measured crypto protocol (`asset_endpoints.protocol`),
	// empty when none was observed.
	Protocol string
}

// ruleMatch is one rule firing on one endpoint.
type ruleMatch struct {
	Rule serviceRule
	// Signal is signalServiceName or signalPort.
	Signal string
	// Matched is the needle or the port that fired, as a string. It goes on the
	// finding so a person can see WHY the rule fired, not merely that it did.
	Matched string
}

// matchConfigurationRules returns at most one match per kind for one endpoint.
//
// Order within a kind is the table's order, and the first match wins — which is
// also the only shape the findings table allows: `findings_open_subject_uniq`
// permits one open row per (producer, kind, subject), so a second match on the
// same endpoint could not be stored anyway. Returning it and letting the writer
// collapse it would make the survivor depend on iteration order.
func matchConfigurationRules(ep endpointFacts) []ruleMatch {
	// An endpoint whose measured protocol is TLS or SSH is not what any rule
	// here describes. The plaintext kinds are about the ABSENCE of transport
	// confidentiality, and the exposure kinds are about a datastore or debug
	// port shipped with no authentication — an Elasticsearch behind TLS, an
	// etcd behind client certificates and a telnet-over-TLS listener are all
	// configurations somebody made deliberately, and reporting them as the
	// default would be the rule overruling the measurement.
	switch strings.ToUpper(strings.TrimSpace(ep.Protocol)) {
	case "TLS", "SSH":
		return nil
	}

	haystack := normaliseServiceText(ep.ServiceName + " " + ep.ServiceVersion)
	// "Was the service measured?" — a name derived from the port is the port
	// again, not a second opinion about it.
	measured := haystack != "" && ep.IdentificationMethod != "port_heuristic"

	byKind := map[string]ruleMatch{}
	for _, r := range configurationRules {
		if _, taken := byKind[r.Kind]; taken {
			continue
		}
		if needle, ok := matchesName(r, haystack); ok {
			byKind[r.Kind] = ruleMatch{Rule: r, Signal: signalServiceName, Matched: needle}
			continue
		}
		if !r.PortAlone || measured {
			continue
		}
		if matchesPort(r, ep.Port, ep.Transport) {
			byKind[r.Kind] = ruleMatch{Rule: r, Signal: signalPort, Matched: portText(ep.Port, ep.Transport)}
		}
	}

	out := make([]ruleMatch, 0, len(byKind))
	for _, m := range byKind {
		out = append(out, m)
	}
	// Deterministic: a map iteration order decides which finding is written
	// first, and a run whose output order changes between passes is a run whose
	// tests pass intermittently.
	sort.Slice(out, func(i, j int) bool { return out[i].Rule.ID < out[j].Rule.ID })
	return out
}

// matchesName reports whether any of the rule's needles appears in the
// normalised service text as a whole token run.
//
// Token run, not substring, and the difference is the whole correctness of the
// table: `strings.Contains("sftp", "ftp")` is true and `sftp` is the encrypted
// one. Padding both sides with a space turns containment into a word-boundary
// test without a regexp per needle per endpoint.
func matchesName(r serviceRule, haystack string) (string, bool) {
	if haystack == "" {
		return "", false
	}
	padded := " " + haystack + " "
	for _, n := range r.Names {
		if strings.Contains(padded, " "+n+" ") {
			return n, true
		}
	}
	return "", false
}

// matchesPort reports whether the endpoint's port and transport are one the
// rule claims.
func matchesPort(r serviceRule, port int, transport string) bool {
	if port <= 0 {
		return false
	}
	if r.Transport != "" && !strings.EqualFold(r.Transport, transport) {
		return false
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// normaliseServiceText lowercases and reduces everything that is not a letter
// or a digit to a single space, so "Redis-Server 7.0" and "redis_server" both
// become "redis server 7 0".
func normaliseServiceText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := true
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevSpace = false
		default:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

// portText renders the port signal for the evidence block.
func portText(port int, transport string) string {
	t := strings.ToLower(strings.TrimSpace(transport))
	if t == "" {
		t = "tcp"
	}
	return t + "/" + strconv.Itoa(port)
}

// configurationKinds is every kind this producer emits, derived from the
// registry rather than listed — so a kind added to the `configuration` producer
// without a sweep here is impossible.
var configurationKinds = func() []string {
	var out []string
	for _, k := range findings.All {
		if k.Producer == findings.ProducerConfiguration {
			out = append(out, k.Key)
		}
	}
	return out
}()
