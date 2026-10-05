package agentconfig

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Port lists — the one rule for the sensor's "additional TLS ports" setting
// ( WP5), shared by the platform's validation, the sensor that applies
// the value, and (through testdata/port_lists.json) the console's own check.
//
// A port list travels as a STRING in canonical form ("9443,10443"), not as a
// JSON array. Value's wire form is a bool, a whole number or a string, and a
// sensor or agent older than this setting decodes the WHOLE heartbeat answer
// through that type: handing one an array would fail the decode and cost it
// every setting, not just this one. A string reaches it intact, finds no
// handler and is reported back as unsupported — the honest outcome the
// applier was built for.

// MaxPortListEntries bounds a port list. Each entry is a term in the sensor's
// capture filter, so an unbounded list is an unbounded filter.
const MaxPortListEntries = 64

// ParsePortList reads a port list typed by a person or sent by a client.
//
// Entries are separated by commas or whitespace; empty entries are skipped, so
// "" is the empty list. The result is sorted with duplicates removed. Every
// unusable entry produces its own problem naming it — a person who pasted six
// ports with two typos is told about both at once — and any problem means the
// list as a whole is refused: half-applying a list is a setting nobody asked
// for.
//
// The problem strings are operator-facing and pinned, word for word, by
// testdata/port_lists.json, which the console's own check reads too.
func ParsePortList(s string) ([]int, []string) {
	fields := strings.FieldsFunc(s, isPortListSeparator)
	seen := make(map[int]struct{}, len(fields))
	ports := make([]int, 0, len(fields))
	var problems []string
	for _, f := range fields {
		p, problem := parsePort(f)
		if problem != "" {
			problems = append(problems, problem)
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	sort.Ints(ports)
	if len(ports) > MaxPortListEntries {
		problems = append(problems, fmt.Sprintf("%d ports listed; at most %d are allowed", len(ports), MaxPortListEntries))
	}
	return ports, problems
}

func isPortListSeparator(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

func parsePort(f string) (int, string) {
	if !allDigits(f) {
		if lo, hi, ok := strings.Cut(f, "-"); ok && allDigits(lo) && allDigits(hi) {
			// Said separately because it is the likeliest mistake: the
			// sensor watches ports, not ranges, and "not a port number" would
			// leave a person wondering what is wrong with 9000.
			return 0, fmt.Sprintf("%q is a range; list each port on its own", f)
		}
		return 0, fmt.Sprintf("%q is not a port number", f)
	}
	p, err := strconv.Atoi(f)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Sprintf("%s is outside the port range 1-65535", f)
	}
	return p, ""
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

// FormatPortList writes ports in canonical form: sorted, without duplicates,
// comma-separated, with anything outside 1-65535 left out. The empty list is "".
//
// Canonical so that one set of ports is one string, and therefore one
// revision: "10443,9443" and "9443, 10443" must not read as two different
// configurations and leave a converged sensor showing as pending.
func FormatPortList(ports []int) string {
	seen := make(map[int]struct{}, len(ports))
	keep := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		keep = append(keep, p)
	}
	sort.Ints(keep)
	out := make([]string, len(keep))
	for i, p := range keep {
		out[i] = strconv.Itoa(p)
	}
	return strings.Join(out, ",")
}

// SensorBuiltInTCPPorts is every TCP port the sensor already gives a meaning,
// with the name the console shows ("already monitored as HTTPS").
//
// It mirrors the sensor's port classifier (getProtocolFromPort, with STARTTLS
// on) and a sensor test holds the two equal over all 65 535 ports, so a port
// added to the classifier and not here fails the build. Listing one of these
// as an additional TLS port is harmless — the sensor never lets an extra
// override a built-in meaning — but a person adding 443 deserves to be told it
// was never missing.
//
// STARTTLS ports are the built-in set only; a sensor's own file can add more,
// which the platform cannot see.
var SensorBuiltInTCPPorts = map[int]string{
	443:   "HTTPS",
	8443:  "HTTPS (alternate port)",
	993:   "IMAPS",
	995:   "POP3S",
	465:   "SMTPS",
	587:   "SMTP submission",
	636:   "LDAPS",
	5671:  "AMQPS",
	853:   "DNS over TLS",
	3389:  "RDP",
	802:   "Modbus/TLS",
	22:    "SSH",
	445:   "SMB",
	88:    "Kerberos",
	502:   "Modbus",
	102:   "MMS / ICCP",
	20000: "DNP3",
	4840:  "OPC UA",
	44818: "EtherNet/IP",
	5094:  "HART-IP",
	500:   "IKE",
	4500:  "IKE (NAT traversal)",
	25:    "SMTP (STARTTLS)",
	143:   "IMAP (STARTTLS)",
	110:   "POP3 (STARTTLS)",
	5432:  "PostgreSQL (STARTTLS)",
	3306:  "MySQL (STARTTLS)",
	21:    "FTP (STARTTLS)",
	5222:  "XMPP (STARTTLS)",
	389:   "LDAP (STARTTLS)",
}
