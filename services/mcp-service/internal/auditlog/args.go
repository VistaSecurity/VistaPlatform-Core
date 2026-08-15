package auditlog

import (
	"encoding/json"
)

// allowedArgs is the explicit projection of tool arguments that may be
// recorded. It is an ALLOWLIST, not a denylist: anything not named here is
// dropped, so a field added to a tool input struct later cannot start leaking
// into the audit trail because nobody remembered to exclude it.
//
// This mirrors the "Collect posture, never key material" rule the device
// collectors follow. Nothing in the current MCP tool inputs carries a secret —
// they are filters and UUIDs — but the MCP surface is exactly where a future
// "run this query" argument would land, and a denylist would have shipped it.
var allowedArgs = map[string]bool{
	// pagination / ordering
	"page":       true,
	"page_size":  true,
	"limit":      true,
	"sort_by":    true,
	"sort_order": true,

	// asset filters
	"asset_type":                 true,
	"environment":                true,
	"risk_level":                 true,
	"business_unit":              true,
	"asset_status":               true,
	"has_certificates":           true,
	"cert_expiring_within_days":  true,
	"uses_deprecated_algorithms": true,

	// certificate filters
	"expiring_days": true,
	"algorithm":     true,
	"key_size_min":  true,
	"self_signed":   true,

	// algorithm-catalogue filters
	"category":           true,
	"strength":           true,
	"deprecation_status": true,
	"pqc":                true,

	// compliance filters
	"severity": true,

	// identifiers — which object was read is the point of the record
	"asset_id":     true,
	"framework_id": true,
	"control_id":   true,
	"scope_id":     true,
	"artifact_id":  true,
	"base_id":      true,
	"head_id":      true,
}

// previewArgs are free-text arguments recorded only as a truncated preview,
// under a "<name>_preview" key so nobody mistakes the stored value for the
// exact query. Same treatment shared/middleware/audit gives ?search=.
var previewArgs = map[string]bool{
	"search": true,
	"issuer": true,
}

// previewLen bounds a recorded free-text preview.
const previewLen = 64

// projectArgs turns a tool's typed input struct into the subset of arguments
// that may be recorded. Input structs use omitempty, so absent filters simply
// do not appear.
func projectArgs(in any) map[string]any {
	if in == nil {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}

	out := map[string]any{}
	for k, v := range raw {
		switch {
		case previewArgs[k]:
			s, ok := v.(string)
			if !ok || s == "" {
				continue
			}
			out[k+"_preview"] = truncate(s, previewLen)
		case allowedArgs[k]:
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// CountRecords reports how many records a tool response carried, and whether
// the response had a countable collection at all.
//
// The distinction matters: a summary tool returns an object, not a list, and
// reporting "0 records" for it would be a lie of the same shape as a risk score
// of 0 meaning "not assessed". Callers pair this with a byte size, which is
// always meaningful.
func CountRecords(v any) (int, bool) {
	switch t := v.(type) {
	case []any:
		return len(t), true
	case map[string]any:
		// Prefer the conventional envelope keys, so a response carrying both a
		// list and, say, an empty "errors" array counts the right one.
		for _, k := range []string{"data", "items", "results", "assets", "certificates", "frameworks", "artifacts", "scopes", "findings", "algorithms", "controls", "crypto_configurations", "configurations", "changes"} {
			if arr, ok := t[k].([]any); ok {
				return len(arr), true
			}
		}
		// Exactly one array in the object is unambiguous; two or more is not,
		// and guessing would be worse than declining to count.
		found, n := 0, 0
		for _, val := range t {
			if arr, ok := val.([]any); ok {
				found++
				n = len(arr)
			}
		}
		if found == 1 {
			return n, true
		}
	}
	return 0, false
}
