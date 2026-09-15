package producer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The findings evidence rail's SIZE backstop, beside its redaction backstop.
//
// The seed: a `new_issuer` finding on a host presenting hundreds of
// certificates writes them all into `findings.evidence`, which every findings
// list read returns and the drawer renders.
//
// Both polarities matter, and the over-strict one is the dangerous half here:
// a cap that trimmed an ordinary producer's evidence would silently delete
// judgement. TestMarshalEvidence_LeavesEveryProducersOwnEvidenceAlone is that
// polarity and it carries a deliberately LARGE but under-cap fixture.
//
// To mutation-test: raise maxEvidenceListItems past the fixture length (or drop
// the capEvidence call from marshalEvidence) and TestEvidenceCap_* go red;
// lower it below a real producer's list and the leaves-alone test goes red.

// decode is the marshalled evidence as a map, which is what a reader sees.
func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("evidence is not decodable JSON: %v\n%s", err, raw)
	}
	return out
}

func TestEvidenceCap_LongListIsTruncatedWithAnExplicitMarker(t *testing.T) {
	const total = maxEvidenceListItems + 37
	certs := make([]any, 0, total)
	for i := 0; i < total; i++ {
		certs = append(certs, map[string]any{
			"certificate_id":     fmt.Sprintf("cert-%03d", i),
			"fingerprint_sha256": fmt.Sprintf("%064x", i),
		})
	}

	raw, err := marshalEvidence(map[string]any{
		"observation_key": "issuer:CN=Some CA",
		"observed":        map[string]any{"certificates": certs},
	})
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	got := decode(t, raw)

	observed, ok := got["observed"].(map[string]any)
	if !ok {
		t.Fatalf("observed is gone: %s", raw)
	}
	list, ok := observed["certificates"].([]any)
	if !ok {
		t.Fatalf("the certificate list is gone: %s", raw)
	}
	if len(list) != maxEvidenceListItems {
		t.Errorf("kept %d entries, want %d", len(list), maxEvidenceListItems)
	}
	// The head is kept verbatim — a truncated list is still evidence.
	if first, _ := list[0].(map[string]any); first == nil || first["certificate_id"] != "cert-000" {
		t.Errorf("the first entry was not kept verbatim: %v", list[0])
	}

	// The marker lands BESIDE the list, in the same object, so a reader walking
	// `observed` cannot miss it.
	marker, ok := observed["certificates"+truncationMarkerSuffix].(map[string]any)
	if !ok {
		t.Fatalf("no truncation marker beside the list: %s", raw)
	}
	if marker["truncated"] != true {
		t.Errorf("marker does not say truncated: %v", marker)
	}
	if marker["omitted"] != float64(37) {
		t.Errorf("marker omitted = %v, want 37", marker["omitted"])
	}
	if marker["total"] != float64(total) {
		t.Errorf("marker total = %v, want %d", marker["total"], total)
	}

	// Identity survives: the key a re-run matches on is not something the cap
	// may touch.
	if got["observation_key"] != "issuer:CN=Some CA" {
		t.Errorf("the observation key did not survive: %v", got["observation_key"])
	}
}

// A list of SCALARS also gets a sentinel inside the list, because the drawer
// renders a scalar list by joining it — and a joined head reads as the whole.
func TestEvidenceCap_ScalarListCarriesAVisibleSentinel(t *testing.T) {
	ports := make([]any, 0, maxEvidenceListItems+5)
	for i := 0; i < maxEvidenceListItems+5; i++ {
		ports = append(ports, fmt.Sprintf("%d", 1000+i))
	}
	raw, err := marshalEvidence(map[string]any{"observed": map[string]any{"opened": ports}})
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	list := decode(t, raw)["observed"].(map[string]any)["opened"].([]any)
	if len(list) != maxEvidenceListItems+1 {
		t.Fatalf("scalar list has %d entries, want %d kept plus one sentinel",
			len(list), maxEvidenceListItems)
	}
	last, _ := list[len(list)-1].(string)
	if !strings.Contains(last, "5 more omitted") {
		t.Errorf("the last element is not the sentinel: %q", last)
	}
}

// Under the cap, nothing is added and nothing is moved. This is the polarity a
// cap gets wrong by being eager.
func TestEvidenceCap_UnderTheCapIsUntouched(t *testing.T) {
	list := make([]any, 0, maxEvidenceListItems)
	for i := 0; i < maxEvidenceListItems; i++ {
		list = append(list, fmt.Sprintf("item-%d", i))
	}
	in := map[string]any{"observation_key": "k", "observed": map[string]any{"ports": list}}

	want, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	got, err := marshalEvidence(in)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	var a, b any
	if err := json.Unmarshal(want, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &b); err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(a)
	gotJSON, _ := json.Marshal(b)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("a list exactly at the cap was changed.\n want %s\n  got %s", wantJSON, gotJSON)
	}
	if strings.Contains(string(gotJSON), truncationMarkerSuffix) {
		t.Errorf("a marker was written for a list that was not truncated: %s", gotJSON)
	}
}

// The byte cap: one enormous VALUE that no list cap can see.
func TestEvidenceCap_OversizeDocumentDropsLargestKeysAndSaysSo(t *testing.T) {
	in := map[string]any{
		"observation_key": "identity-must-survive",
		"asset_id":        "11111111-1111-4111-8111-111111111111",
		"small":           "kept",
		"huge":            strings.Repeat("x", maxEvidenceBytes+100),
		"medium":          strings.Repeat("y", 4096),
	}
	raw, err := marshalEvidence(in)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	if len(raw) > maxEvidenceBytes {
		t.Errorf("evidence is %d bytes, over the %d cap", len(raw), maxEvidenceBytes)
	}
	got := decode(t, raw)

	if _, still := got["huge"]; still {
		t.Errorf("the largest key survived the byte cap: %d bytes", len(raw))
	}
	for _, k := range []string{"observation_key", "asset_id", "small", "medium"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%q was dropped; only the largest keys should go, and never an identity key", k)
		}
	}
	marker, ok := got[documentMarkerKey].(map[string]any)
	if !ok {
		t.Fatalf("no document truncation marker: %s", raw)
	}
	if marker["truncated"] != true {
		t.Errorf("document marker does not say truncated: %v", marker)
	}
	keys, _ := marker["omitted_keys"].([]any)
	if len(keys) != 1 || keys[0] != "huge" {
		t.Errorf("omitted_keys = %v, want [huge]", keys)
	}
}

// An oversize document made ENTIRELY of identity keys is written rather than
// refused: losing the finding is worse than a large row, and there is nothing
// left the cap is allowed to take.
func TestEvidenceCap_RefusesToDropIdentityEvenWhenStillOversize(t *testing.T) {
	in := map[string]any{"observation_key": strings.Repeat("k", maxEvidenceBytes+100)}
	raw, err := marshalEvidence(in)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	got := decode(t, raw)
	if s, _ := got["observation_key"].(string); len(s) != maxEvidenceBytes+100 {
		t.Errorf("the identity key was trimmed; it is what a re-run matches on")
	}
}

// Idempotence. The upsert merges `evidence || EXCLUDED.evidence`, so a
// converged re-run must write byte-identical evidence — including its markers.
func TestEvidenceCap_IsIdempotent(t *testing.T) {
	list := make([]any, 0, maxEvidenceListItems*2)
	for i := 0; i < maxEvidenceListItems*2; i++ {
		list = append(list, fmt.Sprintf("item-%d", i))
	}
	in := map[string]any{"observed": map[string]any{"ports": list}, "big": strings.Repeat("z", maxEvidenceBytes)}

	first, err := marshalEvidence(in)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	second, err := marshalEvidence(in)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("two passes over the same evidence wrote different bytes:\n %s\n %s", first, second)
	}
	// And the producer's own map is not mutated by the pass — a producer that
	// reuses one map across subjects must not find it already truncated.
	if got := len(in["observed"].(map[string]any)["ports"].([]any)); got != maxEvidenceListItems*2 {
		t.Errorf("the caller's map was mutated: list is now %d long", got)
	}
}
