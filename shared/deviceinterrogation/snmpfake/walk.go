package snmpfake

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// A recorded walk is text, one varbind per line, so a fixture is reviewable
// and a planted secret is visible in it:
//
//	# community: <the community string the agent requires>
//	<oid> s "<quoted text>"
//	<oid> x <hex bytes>            (MACs, PortList bitmaps)
//	<oid> i <int>   g <gauge>   t <timeticks>
//	<oid> a <ipv4>  o <oid value>

// Recording is a walk and the community the agent answers to.
type Recording struct {
	Community string
	MIB       []Value
}

// Marshal renders a recording in the text form above.
func (r Recording) Marshal() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# community: %s\n", r.Community)
	for _, v := range r.MIB {
		switch v.tag {
		case tagOctetString:
			if printable(v.raw) {
				fmt.Fprintf(&b, "%s s %s\n", v.OID, strconv.Quote(string(v.raw)))
			} else {
				fmt.Fprintf(&b, "%s x %s\n", v.OID, hex.EncodeToString(v.raw))
			}
		case tagInteger:
			fmt.Fprintf(&b, "%s i %d\n", v.OID, decodeSigned(v.raw))
		case tagGauge32:
			fmt.Fprintf(&b, "%s g %d\n", v.OID, decodeUnsigned(v.raw))
		case tagTimeTicks:
			fmt.Fprintf(&b, "%s t %d\n", v.OID, decodeUnsigned(v.raw))
		case tagIPAddress:
			fmt.Fprintf(&b, "%s a %d.%d.%d.%d\n", v.OID, v.raw[0], v.raw[1], v.raw[2], v.raw[3])
		case tagOID:
			fmt.Fprintf(&b, "%s o %s\n", v.OID, decodeOID(v.raw))
		}
	}
	return b.Bytes()
}

// Unmarshal parses the text form.
func Unmarshal(data []byte) (Recording, error) {
	var rec Recording
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.HasPrefix(line, "# community: ") {
			rec.Community = strings.TrimPrefix(line, "# community: ")
			continue
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " ", 3)
		if len(f) != 3 {
			return rec, fmt.Errorf("snmpfake: line %d: want '<oid> <type> <value>'", n)
		}
		oid, kind, val := f[0], f[1], f[2]
		switch kind {
		case "s":
			s, err := strconv.Unquote(val)
			if err != nil {
				return rec, fmt.Errorf("snmpfake: line %d: %w", n, err)
			}
			rec.MIB = append(rec.MIB, Str(oid, s))
		case "x":
			raw, err := hex.DecodeString(val)
			if err != nil {
				return rec, fmt.Errorf("snmpfake: line %d: %w", n, err)
			}
			rec.MIB = append(rec.MIB, Bytes(oid, raw))
		case "i", "g", "t":
			num, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return rec, fmt.Errorf("snmpfake: line %d: %w", n, err)
			}
			switch kind {
			case "i":
				rec.MIB = append(rec.MIB, Int(oid, num))
			case "g":
				rec.MIB = append(rec.MIB, Gauge(oid, num))
			default:
				rec.MIB = append(rec.MIB, Ticks(oid, num))
			}
		case "a":
			rec.MIB = append(rec.MIB, IP(oid, val))
		case "o":
			rec.MIB = append(rec.MIB, OIDValue(oid, val))
		default:
			return rec, fmt.Errorf("snmpfake: line %d: unknown type %q", n, kind)
		}
	}
	return rec, sc.Err()
}

func printable(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func decodeSigned(b []byte) int64 {
	var n int64
	if len(b) > 0 && b[0]&0x80 != 0 {
		n = -1
	}
	for _, c := range b {
		n = n<<8 | int64(c)
	}
	return n
}

func decodeUnsigned(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		n = n<<8 | uint64(c)
	}
	return n
}
