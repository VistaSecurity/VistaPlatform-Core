package hostobs

import (
	"errors"
	"strings"
)

// errTruncated means the message ENDED in the middle of something, as opposed
// to contradicting itself. It never leaves this file: [parseDNSMessage]
// translates it into a salvage.
//
// The distinction is the one frame.go's error doc insists on. A truncated
// message's bytes DO parse as the protocol — we were handed a prefix of a
// well-formed message — so reporting it as [ErrMalformed] says the segment has
// a broken speaker on it when what actually happened is that we cut the packet
// off ourselves: the sensor caps captured payloads at 2 KB, and a printer's
// mDNS announcement with a dozen service types goes past that routinely. Every
// one of those was counted as a malformed frame, and the records that DID parse
// before the cut were thrown away with it.
//
// Structural faults stay [ErrMalformed]: a forward or self-referential
// compression pointer, a reserved label type, a name over the DNS length limit.
// Those are contradictions in the bytes we DO hold, and no amount of extra
// bytes would resolve them.
var errTruncated = errors.New("hostobs: message ends mid-record")

// DNS wire format (RFC 1035 §4), shared by [DecodeDNS] and [DecodeMDNS].
//
// Header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
// then qdcount questions, then ancount+nscount+arcount resource records.

const (
	dnsHeaderLen = 12

	dnsTypeA    = 1
	dnsTypePTR  = 12
	dnsTypeTXT  = 16
	dnsTypeAAAA = 28
	dnsTypeSRV  = 33

	// dnsMaxRecords bounds how many resource records are walked in one
	// message. A single mDNS announcement from a printer runs to a dozen; a
	// message claiming sixty-five thousand is not one we need to finish
	// reading.
	dnsMaxRecords = 48

	// dnsMaxJumps bounds compression-pointer following. RFC 1035 permits a
	// pointer chain; a malicious message points a label at itself. Every jump
	// must also move strictly backwards, which alone makes a loop impossible —
	// the counter is the belt to that braces.
	dnsMaxJumps = 16
)

type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	RData []byte
	// rdataOff is the offset of RData within the whole message, needed to
	// decompress names inside SRV/PTR record data.
	rdataOff int
}

type dnsMessage struct {
	Flags   uint16
	Records []dnsRR
}

// isResponse reports the QR bit.
func (m *dnsMessage) isResponse() bool { return m.Flags&0x8000 != 0 }

// parseDNSMessage reads the header and every resource record, skipping the
// question section without recording it.
//
// The question section is skipped rather than returned on purpose: a DNS
// question is a record of what somebody looked up. See the package doc.
//
// # Truncation is salvaged; contradiction is not
//
// A message that simply ENDS — mid-name, mid-record header, mid-rdata — yields
// the records that parsed before the cut, and no error. LLDP and CDP have
// always behaved this way (a TLV they cannot read ends the walk and what was
// read is kept); this reader refused the whole message, which meant the sensor's
// own 2 KB payload cap turned every large mDNS announcement into
// [ErrMalformed]. The printer was on the segment, the frame was well-formed, and
// we recorded a parse fault and nothing else.
//
// A message that CONTRADICTS ITSELF is still refused whole: a forward or
// self-referential compression pointer, a reserved label type, a name over the
// length limit. Those are wrong in the bytes we hold, and a reader that salvaged
// past them would be guessing which half to believe.
//
// A truncated message from which nothing at all could be read comes back with
// zero records. Its caller then returns [ErrNotApplicable] — "we could read no
// host observation out of this" — which is the honest answer and, importantly,
// is not the malformed counter.
func parseDNSMessage(b []byte) (*dnsMessage, error) {
	if len(b) < dnsHeaderLen {
		// Not even a header. There is no flags word to trust and no record
		// boundary to find, so there is nothing to salvage from.
		return nil, ErrMalformed
	}
	flags, _ := be16(b, 2)
	qd, _ := be16(b, 4)
	an, _ := be16(b, 6)
	ns, _ := be16(b, 8)
	ar, _ := be16(b, 10)

	msg := &dnsMessage{Flags: flags}

	off := dnsHeaderLen
	for i := 0; i < int(qd); i++ {
		var err error
		_, off, err = readDNSName(b, off)
		if errors.Is(err, errTruncated) {
			// The question section runs off the end, so the answers it precedes
			// are not in this buffer at all. Nothing to salvage — but the flags
			// are real, so the caller can still tell a response from a query.
			return msg, nil
		}
		if err != nil {
			return nil, err
		}
		// qtype(2) + qclass(2)
		if off+4 > len(b) {
			return msg, nil
		}
		off += 4
	}

	total := int(an) + int(ns) + int(ar)
	if total > dnsMaxRecords {
		total = dnsMaxRecords
	}

	msg.Records = make([]dnsRR, 0, total)
	for i := 0; i < total && off < len(b); i++ {
		name, next, err := readDNSName(b, off)
		if errors.Is(err, errTruncated) {
			return msg, nil
		}
		if err != nil {
			return nil, err
		}
		off = next
		// type(2) class(2) ttl(4) rdlength(2)
		if off+10 > len(b) {
			return msg, nil
		}
		rtype, _ := be16(b, off)
		rclass, _ := be16(b, off+2)
		rdlen, _ := be16(b, off+8)
		off += 10
		if off+int(rdlen) > len(b) {
			return msg, nil
		}
		msg.Records = append(msg.Records, dnsRR{
			Name: name,
			Type: rtype,
			// mDNS overloads the top class bit as cache-flush (responses) or
			// unicast-response (questions); mask it off so a class comparison
			// does not have to know which message it is in.
			Class:    rclass & 0x7fff,
			RData:    b[off : off+int(rdlen)],
			rdataOff: off,
		})
		off += int(rdlen)
	}
	return msg, nil
}

// readDNSName decodes a possibly-compressed name, returning the dotted form
// and the offset just past the name IN THE ORIGINAL STREAM (which is the
// offset past the pointer, not past the target, when compression was used).
func readDNSName(b []byte, off int) (string, int, error) {
	var labels []string
	jumps := 0
	next := -1
	total := 0

	for {
		if off < 0 {
			return "", 0, ErrMalformed
		}
		if off >= len(b) {
			return "", 0, errTruncated
		}
		l := int(b[off])
		switch {
		case l == 0:
			off++
			if next < 0 {
				next = off
			}
			return strings.Join(labels, "."), next, nil

		case l&0xc0 == 0xc0:
			// Compression pointer: 14-bit offset in the low bits.
			if off+2 > len(b) {
				return "", 0, errTruncated
			}
			target := (l&0x3f)<<8 | int(b[off+1])
			if next < 0 {
				next = off + 2
			}
			jumps++
			// Strictly backwards. A pointer to itself or forwards is the
			// classic decompression loop; refusing them ends it structurally.
			if jumps > dnsMaxJumps || target >= off {
				return "", 0, ErrMalformed
			}
			off = target

		case l&0xc0 != 0:
			// Reserved label type (0x40 extended, 0x80 unassigned).
			return "", 0, ErrMalformed

		default:
			if off+1+l > len(b) {
				return "", 0, errTruncated
			}
			total += l + 1
			if total > MaxNameLen+2 {
				return "", 0, ErrMalformed
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

// dnsSRVTarget reads the target name out of SRV record data.
// SRV rdata: priority(2) weight(2) port(2) target(name).
func dnsSRVTarget(msg []byte, rr dnsRR) (string, uint16, bool) {
	if len(rr.RData) < 7 {
		return "", 0, false
	}
	port, _ := be16(rr.RData, 4)
	name, _, err := readDNSName(msg, rr.rdataOff+6)
	if err != nil {
		return "", 0, false
	}
	return name, port, true
}

// dnsPTRTarget reads the target name out of PTR record data.
func dnsPTRTarget(msg []byte, rr dnsRR) (string, bool) {
	if len(rr.RData) == 0 {
		return "", false
	}
	name, _, err := readDNSName(msg, rr.rdataOff)
	if err != nil {
		return "", false
	}
	return name, true
}

// dnsServiceType extracts the DNS-SD service type from a name like
// "Office Printer._ipp._tcp.local" or "_ipp._tcp.local", returning "_ipp._tcp".
//
// Returns "" when the name is not a service name. The test is structural — two
// adjacent labels, the second being _tcp or _udp — rather than a list of known
// service types, because the useful signal is precisely the service we have
// not seen before.
func dnsServiceType(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	for i := 0; i+1 < len(labels); i++ {
		proto := labels[i+1]
		if proto != "_tcp" && proto != "_udp" {
			continue
		}
		svc := labels[i]
		if len(svc) < 2 || !strings.HasPrefix(svc, "_") {
			continue
		}
		st := svc + "." + proto
		if len(st) > MaxIdentifierLen {
			return ""
		}
		return st
	}
	return ""
}

// dnsIsServiceName reports whether any label begins with an underscore, which
// marks the name as DNS-SD structure rather than a host name.
func dnsIsServiceName(name string) bool {
	for _, l := range strings.Split(name, ".") {
		if strings.HasPrefix(l, "_") {
			return true
		}
	}
	return false
}
