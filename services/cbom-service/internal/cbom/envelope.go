package cbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// The signed envelope.
//
// A signature over sha256(canonical bytes) alone leaves everything else about
// an artifact unsigned: which scope it claims to describe, which version of
// that scope, the compliance attestation layers, who generated it. A writer
// to the table could change any of them and /verify would still pass. The
// signature therefore covers a small canonical JSON document that binds the
// content hash to all of those:
//
//	{"hash":"…","scope_id":"…","scope_version":N,"layers_hash":"…","kind":"…","generated_by":"…"}
//
// The key order is fixed (it is the order of the struct fields below, not a
// map's), there is no insignificant whitespace, and the document is stored
// verbatim on the row (`signed_envelope`) so /verify checks the signature over
// the exact bytes that were signed and then compares each field against the
// row's own columns. A field that no longer matches is named in the response.

// Envelope is the document the artifact signature covers. Field order is part
// of the format: do not reorder, and do not add a field without a new
// signature version.
type Envelope struct {
	Hash         string `json:"hash"`
	ScopeID      string `json:"scope_id"`
	ScopeVersion int    `json:"scope_version"`
	LayersHash   string `json:"layers_hash"`
	Kind         string `json:"kind"`
	GeneratedBy  string `json:"generated_by"`
}

// EnvelopeFieldNames lists the envelope's fields in canonical order. The
// verify response reports mismatches by these names.
var EnvelopeFieldNames = []string{"hash", "scope_id", "scope_version", "layers_hash", "kind", "generated_by"}

// NewEnvelope assembles the envelope from an artifact's own fields. hash is
// the SHA-256 of the canonical bytes; layers is hashed in canonical form.
func NewEnvelope(hash string, scopeID uuid.UUID, scopeVersion int, layers []Layer, kind ArtifactKind, generatedBy uuid.UUID) (Envelope, error) {
	lh, err := CanonicalLayersHash(layers)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Hash:         hash,
		ScopeID:      scopeID.String(),
		ScopeVersion: scopeVersion,
		LayersHash:   lh,
		Kind:         string(kind),
		GeneratedBy:  generatedBy.String(),
	}, nil
}

// Bytes is the exact byte string that is signed.
func (e Envelope) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, fmt.Errorf("cbom: encode envelope: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Mismatches names the fields of e (the envelope recorded at signing time)
// that differ from want (the envelope recomputed from the row now).
func (e Envelope) Mismatches(want Envelope) []string {
	var out []string
	if e.Hash != want.Hash {
		out = append(out, "hash")
	}
	if e.ScopeID != want.ScopeID {
		out = append(out, "scope_id")
	}
	if e.ScopeVersion != want.ScopeVersion {
		out = append(out, "scope_version")
	}
	if e.LayersHash != want.LayersHash {
		out = append(out, "layers_hash")
	}
	if e.Kind != want.Kind {
		out = append(out, "kind")
	}
	if e.GeneratedBy != want.GeneratedBy {
		out = append(out, "generated_by")
	}
	return out
}

// ParseEnvelope reads a stored envelope. Unknown fields are an error: an
// envelope with extra members is not one this code produced.
func ParseEnvelope(raw []byte) (Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, fmt.Errorf("cbom: parse signed envelope: %w", err)
	}
	return e, nil
}

// CanonicalLayersHash is sha256 over the canonical JSON of the layers: object
// keys sorted, no whitespace, numbers in one plain decimal form.
//
// The layers go through a JSONB column, which reorders keys and renormalises
// numbers, so the hash must be taken over a form that survives that round
// trip. The input is first normalised through []Layer JSON (the shape a row is
// read back into), then canonicalised, so the value hashed at signing and the
// value hashed from the row at verify are the same.
func CanonicalLayersHash(layers []Layer) (string, error) {
	if layers == nil {
		layers = []Layer{}
	}
	raw, err := json.Marshal(layers)
	if err != nil {
		return "", fmt.Errorf("cbom: marshal layers: %w", err)
	}
	var norm []Layer
	if err := json.Unmarshal(raw, &norm); err != nil {
		return "", fmt.Errorf("cbom: normalise layers: %w", err)
	}
	raw, err = json.Marshal(norm)
	if err != nil {
		return "", fmt.Errorf("cbom: marshal layers: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("cbom: decode layers: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return "", err
	}
	return sha256Hex(buf.Bytes()), nil
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return fmt.Errorf("cbom: canonical number %q: %w", s, err)
			}
			s = strconv.FormatFloat(f, 'f', -1, 64)
		}
		buf.WriteString(s)
	case string:
		var sb bytes.Buffer
		enc := json.NewEncoder(&sb)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(t); err != nil {
			return err
		}
		buf.Write(bytes.TrimRight(sb.Bytes(), "\n"))
	case []interface{}:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("cbom: canonical: unsupported type %T", v)
	}
	return nil
}
