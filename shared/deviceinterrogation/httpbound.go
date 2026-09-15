package deviceinterrogation

import (
	"encoding/json"
	"fmt"
	"io"
)

// Bounded reads of a device's HTTP response body.
//
// A collector that decodes whatever a remote device chooses to send has handed
// the device control of its own memory. The Cisco collector already reads its
// command output through a bounded writer for exactly this reason
// (ciscoMaxCommandBytes); this is the same bound for the REST clients, which
// were streaming straight into a json.Decoder with nothing between the device
// and the heap. `ltm/pool?expandSubcollections=true` on a large BIG-IP and a
// FortiGate's `monitor/router/ipv4` are the two biggest responses either
// collector asks for, and neither has a ceiling the device does not choose.
//
// The difference from the Cisco bound is deliberate: a truncated CLI table is
// still a table, and Cisco keeps the rows it read and SAYS the rest are
// missing. A truncated JSON document is not a JSON document — it decodes to a
// syntax error or, worse, to a prefix that happens to parse. So here
// overshooting the bound is an ERROR, never a partial success.

// maxAPIResponseBytes bounds one REST response body.
//
// 8 MiB is far above any response these collectors legitimately receive (the
// largest observed is a pool collection in the low hundreds of kilobytes) and
// far below what would hurt a service running sixteen interrogations at once.
const maxAPIResponseBytes = 8 << 20

// readBoundedBody reads at most maxAPIResponseBytes from r, and fails rather
// than returning a prefix when there is more.
//
// The limit is set one byte high on purpose: io.LimitReader cannot distinguish
// "exactly at the bound" from "cut short at the bound", and a bound that
// silently truncates is the silent-success failure this codebase keeps paying
// for.
func readBoundedBody(r io.Reader, what string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxAPIResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", what, err)
	}
	if len(body) > maxAPIResponseBytes {
		return nil, fmt.Errorf("%s exceeded the %d-byte response bound; refusing to decode a partial document", what, maxAPIResponseBytes)
	}
	return body, nil
}

// decodeBoundedJSON reads a bounded body and unmarshals it into out.
func decodeBoundedJSON(r io.Reader, what string, out any) error {
	body, err := readBoundedBody(r, what)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("failed to decode %s: %w", what, err)
	}
	return nil
}
