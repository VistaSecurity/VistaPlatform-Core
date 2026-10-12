package cbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEnvelope_BytesAreCanonicalAndFixedOrder(t *testing.T) {
	scope := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	by := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	env, err := NewEnvelope("abc", scope, 3, nil, KindSBOM, by)
	if err != nil {
		t.Fatal(err)
	}
	got, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	emptyLayers := sha256Hex([]byte("[]"))
	want := `{"hash":"abc","scope_id":"11111111-1111-1111-1111-111111111111","scope_version":3,` +
		`"layers_hash":"` + emptyLayers + `","kind":"sbom","generated_by":"22222222-2222-2222-2222-222222222222"}`
	if string(got) != want {
		t.Fatalf("envelope bytes\n got: %s\nwant: %s", got, want)
	}
}

func TestEnvelope_ParseRoundTripAndRejectsExtraMembers(t *testing.T) {
	env, _ := NewEnvelope("h", uuid.New(), 1, nil, KindCBOM, uuid.New())
	raw, _ := env.Bytes()
	back, err := ParseEnvelope(raw)
	if err != nil || back != env {
		t.Fatalf("round trip: %v / %+v vs %+v", err, back, env)
	}
	extra := strings.Replace(string(raw), `"kind"`, `"extra":1,"kind"`, 1)
	if _, err := ParseEnvelope([]byte(extra)); err == nil {
		t.Fatal("an envelope with an unknown member must not parse")
	}
}

func TestEnvelope_MismatchesNamesEveryField(t *testing.T) {
	base, _ := NewEnvelope("h", uuid.New(), 1, nil, KindCBOM, uuid.New())
	if got := base.Mismatches(base); len(got) != 0 {
		t.Fatalf("identical envelopes mismatch: %v", got)
	}
	mut := map[string]func(e *Envelope){
		"hash":          func(e *Envelope) { e.Hash = "x" },
		"scope_id":      func(e *Envelope) { e.ScopeID = uuid.NewString() },
		"scope_version": func(e *Envelope) { e.ScopeVersion = 9 },
		"layers_hash":   func(e *Envelope) { e.LayersHash = "x" },
		"kind":          func(e *Envelope) { e.Kind = "hbom" },
		"generated_by":  func(e *Envelope) { e.GeneratedBy = uuid.NewString() },
	}
	if len(mut) != len(EnvelopeFieldNames) {
		t.Fatalf("test covers %d fields, envelope has %d", len(mut), len(EnvelopeFieldNames))
	}
	for name, f := range mut {
		other := base
		f(&other)
		got := base.Mismatches(other)
		if len(got) != 1 || got[0] != name {
			t.Errorf("changing %s reported %v", name, got)
		}
	}
}

// The layers hash has to survive the JSONB round trip: Postgres reorders keys
// and renormalises numbers, and a hash that moved on read-back would fail
// every attested artifact on its first verify.
func TestCanonicalLayersHash_SurvivesJSONBRoundTrip(t *testing.T) {
	layers := []Layer{{
		Type: "compliance_attestation", Version: "v1",
		Data: map[string]interface{}{
			"zeta": 1, "alpha": 0.5, "tiny": 1e-7, "big": 1e21,
			"nested":    map[string]interface{}{"b": []int{3, 2, 1}, "a": "<&>"},
			"truncated": false,
		},
	}}
	h1, err := CanonicalLayersHash(layers)
	if err != nil {
		t.Fatal(err)
	}

	// What the column hands back: same content, different key order, numbers
	// as Postgres prints them.
	jsonb := `[{"data":{"alpha":0.5,"big":1000000000000000000000,"nested":{"a":"<&>","b":[3,2,1]},` +
		`"tiny":0.0000001,"truncated":false,"zeta":1},"type":"compliance_attestation","version":"v1"}]`
	var back []Layer
	if err := json.Unmarshal([]byte(jsonb), &back); err != nil {
		t.Fatal(err)
	}
	h2, err := CanonicalLayersHash(back)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("layers hash moved across the JSONB round trip: %s vs %s", h1, h2)
	}

	back[0].Data["zeta"] = 2
	h3, _ := CanonicalLayersHash(back)
	if h3 == h1 {
		t.Fatal("changing a layer value did not change the layers hash")
	}
	if a, b := mustHash(t, nil), mustHash(t, []Layer{}); a != b {
		t.Fatal("nil and empty layers must hash alike (the column stores [])")
	}
}

func mustHash(t *testing.T, l []Layer) string {
	t.Helper()
	h, err := CanonicalLayersHash(l)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
