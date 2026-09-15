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
	// MUTATION-TESTED: adding "question" here fails TestAskQuestionIsNeverRecorded.
	//
	// pagination / ordering
	"page":       true,
	"page_size":  true,
	"limit":      true,
	"sort_by":    true,
	"sort_order": true,

	// asset facets — a closed vocabulary of facet LEVEL names (class, risk,
	// environment, …). These are code, not tenant data: an unknown one is
	// refused by the platform rather than reaching SQL.
	"facets": true,

	// compliance filters
	"environment": true,

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
// exact query. Same treatment shared/middleware/audit gives ?search=. The value
// is that argument's own cap in bytes.
//
// `query` is here rather than in allowedArgs, and it is the case the allowlist
// comment anticipated: the query language IS the "run this query" argument, and
// a query is free text a caller composed — it can carry an owner's email or a
// serial number it learned two calls ago. Which query an agent ran is the most
// useful line in this record, so it gets a longer cap than a search box rather
// than being dropped; it is still bounded, and still a preview, because the
// stored string is evidence of a request, not a copy of the tenant's data.
var previewArgs = map[string]int{
	"search": 64,
	"issuer": 64,
	"text":   64,
	"query":  256,
}

// `question` — `vistaplatform_ask`'s only argument — is deliberately in NEITHER
// map, so the allowlist drops it.
//
// It is the one argument on this surface that is a PROMPT, and ADR-0008 D4.7 is
// that prompts are not stored unless the tenant opts in. That opt-in lives in
// `tenant_admin_settings.config->'ai'.record_questions` and is enforced inside
// `ai.WithAudit`, one layer down, where the question actually crosses the
// provider boundary. Recording it here as well would write the text to a second
// rail that never asked — an opt-in honoured in one place and bypassed in
// another is not an opt-in.
//
// What the record still says is everything it says for every other tool: who
// called, which tool, whether it was denied, how long it took and how much of
// the tenant's inventory came back. "Which assets did this select" is answerable
// from the grounding record the seam writes, where the canonical query — the
// platform's own derived artefact, not a word the user typed — is recorded
// unconditionally.
//
// `TestAskQuestionIsNeverRecorded` pins this, in both polarities.

// AskQuestionArg is the argument name that must never be recorded. Exported so
// the guard names it once rather than spelling it in a test and in a comment.
const AskQuestionArg = "question"

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
		switch cap, isPreview := previewArgs[k]; {
		case isPreview:
			s, ok := v.(string)
			if !ok || s == "" {
				continue
			}
			out[k+"_preview"] = truncate(s, cap)
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
