package services

// Value conversion between the API shape and SQL arguments, and the mapping of
// driver errors onto the IPAM engine's errors.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(x) == ""
	}
	return false
}

// sqlParam converts an API-shape value into a driver argument for a column.
func sqlParam(c ipamCol, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	bad := func() error { return ipamInvalid("%s has the wrong type", c.Name) }
	switch c.Type {
	case colBool:
		b, ok := v.(bool)
		if !ok {
			return nil, bad()
		}
		return b, nil
	case colInt, colBigint:
		switch n := v.(type) {
		case json.Number:
			i, err := n.Int64()
			if err != nil {
				return nil, bad()
			}
			return i, nil
		case int:
			return int64(n), nil
		case int64:
			return n, nil
		case float64:
			if n != float64(int64(n)) {
				return nil, bad()
			}
			return int64(n), nil
		}
		return nil, bad()
	case colNumeric:
		switch n := v.(type) {
		case string:
			return n, nil
		case json.Number:
			return n.String(), nil
		case float64:
			// A sync write decoded without UseNumber (a NetBox decimal such as
			// a device type's u_height): exact for the numeric(p,s) columns.
			return strconv.FormatFloat(n, 'f', -1, 64), nil
		}
		return nil, bad()
	case colJSONValue:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, bad()
		}
		return string(b), nil
	case colJSON:
		if _, ok := v.(map[string]any); !ok {
			return nil, ipamInvalid("%s must be an object", c.Name)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, bad()
		}
		return string(b), nil
	case colTextArray:
		arr, ok := v.([]any)
		if !ok {
			if ss, ok := v.([]string); ok {
				return pq.Array(ss), nil
			}
			return nil, bad()
		}
		ss := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return nil, bad()
			}
			ss = append(ss, s)
		}
		return pq.Array(ss), nil
	case colBigintArray:
		arr, ok := v.([]any)
		if !ok {
			return nil, bad()
		}
		ns := make([]int64, 0, len(arr))
		for _, e := range arr {
			if e == nil {
				return nil, bad()
			}
			n, err := sqlParam(ipamCol{Name: c.Name, Type: colBigint}, e)
			if err != nil {
				return nil, err
			}
			ns = append(ns, n.(int64))
		}
		return pq.Array(ns), nil
	case colUUIDArray:
		arr, ok := v.([]any)
		if !ok {
			return nil, bad()
		}
		seen := map[string]bool{}
		ids := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return nil, bad()
			}
			id, err := uuid.Parse(strings.TrimSpace(s))
			if err != nil {
				return nil, ipamInvalid("%s: %q is not a UUID", c.Name, s)
			}
			if !seen[id.String()] {
				seen[id.String()] = true
				ids = append(ids, id.String())
			}
		}
		return pq.Array(ids), nil
	case colVidRanges:
		pairs, err := vidRanges(v)
		if err != nil {
			return nil, ipamInvalid("%s: %v", c.Name, err)
		}
		parts := make([]string, 0, len(pairs))
		for _, p := range pairs {
			parts = append(parts, fmt.Sprintf(`"[%d,%d)"`, p[0], p[1]+1))
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	case colUUID:
		s, ok := v.(string)
		if !ok {
			return nil, bad()
		}
		if s == "" {
			return nil, nil
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, ipamInvalid("%s must be a UUID", c.Name)
		}
		return id, nil
	default:
		s, ok := v.(string)
		if !ok {
			return nil, bad()
		}
		return s, nil
	}
}

// vidRanges parses [[lo, hi], …] (inclusive, NetBox's shape) and checks each
// pair lies in 1–4094.
func vidRanges(v any) ([][2]int, error) {
	arr, ok := v.([]any)
	if !ok {
		if p, ok := v.([][2]int); ok {
			return p, nil
		}
		return nil, errors.New("must be a list of [low, high] pairs")
	}
	out := make([][2]int, 0, len(arr))
	for _, e := range arr {
		pair, ok := e.([]any)
		if !ok || len(pair) != 2 {
			return nil, errors.New("must be a list of [low, high] pairs")
		}
		var lh [2]int
		for i, x := range pair {
			n, err := strconv.Atoi(fmt.Sprint(x))
			if err != nil {
				return nil, errors.New("bounds must be integers")
			}
			lh[i] = n
		}
		if lh[0] < 1 || lh[1] > 4094 || lh[0] > lh[1] {
			return nil, fmt.Errorf("[%d, %d] is not within 1-4094", lh[0], lh[1])
		}
		out = append(out, lh)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one range is required")
	}
	return out, nil
}

var rangeLiteral = regexp.MustCompile(`^\[(\d+),(\d+)\)$`)

// presentVidRanges turns ["[1,4095)"] into [[1, 4094]].
func presentVidRanges(row map[string]any) {
	arr, ok := row["vid_ranges"].([]any)
	if !ok {
		return
	}
	out := make([][2]int, 0, len(arr))
	for _, e := range arr {
		m := rangeLiteral.FindStringSubmatch(fmt.Sprint(e))
		if m == nil {
			continue
		}
		lo, _ := strconv.Atoi(m[1])
		hi, _ := strconv.Atoi(m[2])
		out = append(out, [2]int{lo, hi - 1})
	}
	row["vid_ranges"] = out
}

// mapIPAMError turns driver errors into the engine's errors.
func mapIPAMError(err error, deleting bool) error {
	if err == nil {
		return nil
	}
	var pe *pq.Error
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: an object with the same identity already exists (%s)", ErrIPAMConflict, pe.Constraint)
		case "23514":
			return fmt.Errorf("%w: a value is outside the allowed set (%s)", ErrIPAMInvalid, pe.Constraint)
		case "23503":
			if deleting {
				return fmt.Errorf("%w: other objects still reference it (%s)", ErrIPAMInUse, pe.Constraint)
			}
			return fmt.Errorf("%w: a referenced object does not exist (%s)", ErrIPAMInvalid, pe.Constraint)
		case "23502":
			return fmt.Errorf("%w: %s is required", ErrIPAMInvalid, pe.Column)
		case "22P02", "22003", "22007", "22008", "22023":
			return fmt.Errorf("%w: %s", ErrIPAMInvalid, pe.Message)
		}
	}
	return err
}

// visible reports whether id is a row of table the tenant can read (its own,
// or a platform row of a catalogue). A foreign key to a catalogue checks only
// existence, not tenancy, so references are checked here under RLS.
func visible(ctx context.Context, tx *sql.Tx, table string, id any) error {
	if id == nil || id == "" {
		return nil
	}
	var ok bool
	q := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM public.%s WHERE id = $1::uuid)`, pq.QuoteIdentifier(table))
	if err := tx.QueryRowContext(ctx, q, fmt.Sprint(id)).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("no such %s %v", strings.TrimSuffix(table, "s"), id)
	}
	return nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func filterValue(t ipamColType, v string) (any, error) {
	switch t {
	case colUUID:
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, errors.New("must be a UUID")
		}
		return id, nil
	case colBool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errors.New("must be true or false")
		}
		return b, nil
	case colInt, colBigint:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, errors.New("must be an integer")
		}
		return n, nil
	default:
		return v, nil
	}
}

func decodeRow(sp *ipamSpec, raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var row map[string]any
	if err := dec.Decode(&row); err != nil {
		return nil, err
	}
	presentRow(sp, row)
	return row, nil
}

func present(sp *ipamSpec, raw []byte) (json.RawMessage, error) {
	if sp.Present == nil && !hasMAC(sp) {
		return raw, nil
	}
	row, err := decodeRow(sp, raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(row)
}

func hasMAC(sp *ipamSpec) bool {
	_, ok := sp.col("mac_address")
	return ok
}

func presentRow(sp *ipamSpec, row map[string]any) {
	if v, ok := row["mac_address"].(string); ok {
		row["mac_address"] = eui48(v)
	}
	if sp.Present != nil {
		sp.Present(row)
	}
}

// eui48 turns a macaddr8 holding an EUI-48 (ff:fe in the middle, as Postgres
// stores a six-byte input) back into the six-byte form NetBox uses.
func eui48(v string) string {
	parts := strings.Split(v, ":")
	if len(parts) == 8 && strings.EqualFold(parts[3], "ff") && strings.EqualFold(parts[4], "fe") {
		return strings.Join(append(append([]string{}, parts[:3]...), parts[5:]...), ":")
	}
	return v
}

// decodeBody parses a request body into a patch: only writable columns.
func decodeBody(sp *ipamSpec, body []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	var patch map[string]any
	if err := dec.Decode(&patch); err != nil {
		return nil, ipamInvalid("body must be a JSON object")
	}
	if patch == nil {
		return nil, ipamInvalid("body must be a JSON object")
	}
	for k := range patch {
		c, ok := sp.col(k)
		if !ok || c.Computed {
			return nil, ipamInvalid("unknown or read-only field %q", k)
		}
	}
	return patch, nil
}
