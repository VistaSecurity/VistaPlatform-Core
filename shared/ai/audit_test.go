package ai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type recordingSink struct {
	mu      sync.Mutex
	records []AuditRecord
}

func (s *recordingSink) Record(_ context.Context, rec AuditRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
}

func (s *recordingSink) all() []AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditRecord(nil), s.records...)
}

func TestWithAudit_EmitsOneRecordPerCall(t *testing.T) {
	sink := &recordingSink{}
	mock := &MockProvider{
		ProviderName: "mock-provider",
		Responses: []Response{{
			Text: "summary", ModelID: "mock-model-1", InputTokens: 120, OutputTokens: 34,
		}},
	}
	p := Boundary(mock, sink)

	req := Request{
		Seam:     SeamNarrator,
		System:   "summarise",
		Messages: []Message{{Role: "user", Content: "cipher_suite: TLS_AES_256_GCM_SHA384"}},
		Invoker:  "user:0f3a",
	}
	if _, err := p.Complete(context.Background(), req); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want exactly 1", len(records))
	}
	rec := records[0]

	// Every field ADR-0008 D4.7 names.
	if rec.Seam != SeamNarrator {
		t.Errorf("Seam = %q, want %q", rec.Seam, SeamNarrator)
	}
	if rec.Provider != "mock-provider" {
		t.Errorf("Provider = %q, want the provider's own name", rec.Provider)
	}
	if rec.ModelID != "mock-model-1" {
		t.Errorf("ModelID = %q", rec.ModelID)
	}
	if rec.InputTokens != 120 || rec.OutputTokens != 34 {
		t.Errorf("tokens = %d/%d, want 120/34", rec.InputTokens, rec.OutputTokens)
	}
	if rec.Invoker != "user:0f3a" {
		t.Errorf("Invoker = %q", rec.Invoker)
	}
	if rec.At.IsZero() {
		t.Error("At is zero")
	}
	if len(rec.PromptSHA256) != 64 {
		t.Errorf("PromptSHA256 = %q, want a 64-char hex digest", rec.PromptSHA256)
	}
	if rec.Err != "" {
		t.Errorf("Err = %q on a successful call", rec.Err)
	}
}

// "Prompts themselves are not stored unless the tenant opts in" (D4.7). The
// record carries a digest; nothing in it may carry the text.
func TestWithAudit_RecordCarriesNoPromptText(t *testing.T) {
	const marker = "a-very-distinctive-string-from-the-prompt"

	sink := &recordingSink{}
	p := Boundary(&MockProvider{}, sink)

	_, _ = p.Complete(context.Background(), Request{
		Seam:     SeamQuery,
		Invoker:  "user:0f3a",
		System:   marker,
		Messages: []Message{{Role: "user", Content: marker}},
		Context:  []map[string]any{{"hostname": marker}},
	})

	for _, rec := range sink.all() {
		if strings.Contains(rec.PromptSHA256+rec.ModelID+rec.Invoker+rec.Err+string(rec.Seam)+rec.Provider, marker) {
			t.Errorf("the audit record carries prompt text: %+v", rec)
		}
	}
}

// A failed call is still a call that was attempted. An audit trail that records
// only successes cannot answer "what did this deployment try to send".
func TestWithAudit_RecordsFailedCallsToo(t *testing.T) {
	sink := &recordingSink{}
	p := Boundary(NoneProvider{}, sink)

	_, err := p.Complete(context.Background(), Request{
		Seam: SeamQuery, Invoker: "rule:cert-expiry", Model: "requested-model",
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}

	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1 — a failed call must still be audited", len(records))
	}
	if records[0].Err == "" {
		t.Error("the record of a failed call has an empty Err")
	}
	if records[0].ModelID != "requested-model" {
		t.Errorf("ModelID = %q; a call that failed before choosing a model records the requested one",
			records[0].ModelID)
	}
}

// TestWithAudit_SetsNoAttributes. The boundary knows a prompt crossed it and
// almost nothing about what it was for, so Attributes is a seam's field and
// stays one — with exactly one exception, [AuditAttrPrompt], written only when
// the tenant has opted in to question recording (D4.7). That exception is
// pinned in tenant_gate_test.go, in both polarities; this test holds the
// default, which is every call in every deployment that has not opted in.
//
// If this decorator ever started filling the map generally — from the request,
// say — a seam's own record and the boundary's would carry different things
// under one name, and "what did this call do" would have two answers.
func TestWithAudit_SetsNoAttributes(t *testing.T) {
	sink := &recordingSink{}
	p := Boundary(&MockProvider{Responses: []Response{{Text: "x", ModelID: "m"}}}, sink)

	if _, err := p.Complete(context.Background(), Request{
		Seam: SeamQuery, Invoker: "user-1", System: "sys", Messages: []Message{{Role: "user", Content: "q"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Attributes != nil {
		t.Errorf("WithAudit set Attributes = %v; that field belongs to the seam", records[0].Attributes)
	}
}

// The recorded digest must be the digest of the request that actually reached
// the provider. Not "a digest of the prompt" — of THAT request, the scrubbed
// one, byte for byte.
func TestBoundary_HashesExactlyWhatTheProviderReceived(t *testing.T) {
	sink := &recordingSink{}
	mock := &MockProvider{}
	p := Boundary(mock, sink)

	_, err := p.Complete(context.Background(), Request{
		Seam:     SeamNarrator,
		Invoker:  "user:0f3a",
		System:   "admin_password: hunter2",
		Messages: []Message{{Role: "user", Content: "cipher_suite: TLS_AES_256_GCM_SHA384"}},
		Context:  []map[string]any{{"hostname": "edge01", "api_key": "EXAMPLE-key"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	sent, ok := mock.LastRequest()
	if !ok {
		t.Fatal("nothing reached the provider")
	}
	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if got, want := records[0].PromptSHA256, PromptHash(sent); got != want {
		t.Errorf("audit recorded %q but the provider received a prompt hashing to %q;\n"+
			"the audit decorator is hashing something other than what it forwarded", got, want)
	}
}

// The consequence that makes the ordering worth enforcing: once the secret is
// gone, two prompts that differed only in the secret are the same prompt, and
// the digest says so. Hashing pre-redaction, they would differ — so "is this
// the same question as last time" would answer no whenever a password rotated.
func TestBoundary_SecretValuesDoNotChangeTheDigest(t *testing.T) {
	hashFor := func(secret string) string {
		sink := &recordingSink{}
		p := Boundary(&MockProvider{}, sink)
		if _, err := p.Complete(context.Background(), Request{
			Seam:    SeamQuery,
			Invoker: "user:0f3a",
			System:  "the host is edge01",
			Messages: []Message{{
				Role:    "user",
				Content: `{"admin_password": "` + secret + `", "key_size": 2048}`,
			}},
			Context: []map[string]any{{"hostname": "edge01", "api_key": secret}},
		}); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		records := sink.all()
		if len(records) != 1 {
			t.Fatalf("got %d records, want 1", len(records))
		}
		return records[0].PromptSHA256
	}

	first := hashFor("hunter2-the-service-account")
	second := hashFor("a-completely-different-Pa55w0rd")

	if first != second {
		t.Errorf("the same prompt with a different secret hashed differently (%q vs %q);\n"+
			"the digest is being taken before redaction", first, second)
	}
	if first == "" {
		t.Error("no digest was recorded at all")
	}
}

// The wrong order used to misreport silently. Now it cannot be wired at all:
// audit is handed the raw request, sees it has not been through Redact, and
// refuses — recording the attempt so the mistake is visible rather than only
// returned to a caller who may log it at debug.
func TestWithAudit_WrongOrderRefusesAndRecordsTheAttempt(t *testing.T) {
	sink := &recordingSink{}
	mock := &MockProvider{}
	p := WithAudit(WithRedaction(mock), sink) // deliberately inside out

	_, err := p.Complete(context.Background(), Request{
		Seam:    SeamNarrator,
		Invoker: "user:0f3a",
		System:  "admin_password: hunter2",
	})
	if !errors.Is(err, ErrNotSanitized) {
		t.Fatalf("err = %v, want ErrNotSanitized", err)
	}
	if got := len(mock.Requests()); got != 0 {
		t.Errorf("%d requests reached the provider through a refused call", got)
	}

	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1 — a refused attempt is still an attempt", len(records))
	}
	if !records[0].Refused {
		t.Error("the record of a refused call is not marked Refused")
	}
	if records[0].Err == "" {
		t.Error("the record of a refused call does not say why")
	}
	// A request refused for not being sanitized is the one case with no digest:
	// hashing it would put a digest of raw prompt text in the trail.
	if records[0].PromptSHA256 != "" {
		t.Errorf("PromptSHA256 = %q on an unsanitized request; that digest is of text "+
			"that never crossed the boundary", records[0].PromptSHA256)
	}
}

// D4.7 wants to know which user or rule invoked the call. An empty invoker, or
// a seam that is not one of the eight, makes the record unable to answer that —
// and looks like an answer, which is worse.
func TestWithAudit_RefusesUnattributedCalls(t *testing.T) {
	cases := map[string]Request{
		"no invoker":       {Seam: SeamNarrator},
		"blank invoker":    {Seam: SeamNarrator, Invoker: "   "},
		"no seam":          {Invoker: "user:0f3a"},
		"unknown seam":     {Seam: Seam("summariser"), Invoker: "user:0f3a"},
		"seam typo'd case": {Seam: Seam("Narrator"), Invoker: "user:0f3a"},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			sink := &recordingSink{}
			mock := &MockProvider{}
			p := Boundary(mock, sink)

			_, err := p.Complete(context.Background(), req)
			if !errors.Is(err, ErrUnattributed) {
				t.Fatalf("err = %v, want ErrUnattributed", err)
			}
			if got := len(mock.Requests()); got != 0 {
				t.Errorf("%d requests reached the provider unattributed", got)
			}

			records := sink.all()
			if len(records) != 1 {
				t.Fatalf("got %d records, want 1", len(records))
			}
			if !records[0].Refused {
				t.Error("the refusal was not recorded as one")
			}
			// This request DID pass the redactor, so the trail can still say
			// which prompt was refused.
			if records[0].PromptSHA256 == "" {
				t.Error("a sanitized-but-unattributed refusal recorded no prompt hash")
			}
		})
	}
}

func TestWithAudit_AcceptsEveryKnownSeam(t *testing.T) {
	// The inverse polarity of the refusal above: a check that rejects the eight
	// real seams would take every AI feature down, silently, at the boundary.
	for _, seam := range AllSeams() {
		t.Run(string(seam), func(t *testing.T) {
			sink := &recordingSink{}
			p := Boundary(&MockProvider{}, sink)
			if _, err := p.Complete(context.Background(), Request{Seam: seam, Invoker: "rule:x"}); err != nil {
				t.Fatalf("seam %q was refused: %v", seam, err)
			}
			if rec := sink.all(); len(rec) != 1 || rec[0].Refused {
				t.Errorf("seam %q recorded %+v", seam, rec)
			}
		})
	}
}

// A nil provider is a wiring mistake, and the honest response to one is to
// degrade to no-AI — not to panic at whichever call site first asks for a
// completion, long after the mistake.
func TestNilProviderDegradesInsteadOfPanicking(t *testing.T) {
	req := Request{Seam: SeamQuery, Invoker: "user:0f3a"}

	if p := WithRedaction(nil); p.Available() {
		t.Error("WithRedaction(nil) reported itself available")
	} else if _, err := p.Complete(context.Background(), req); !errors.Is(err, ErrUnavailable) {
		t.Errorf("WithRedaction(nil).Complete err = %v, want ErrUnavailable", err)
	}

	sink := &recordingSink{}
	p := Boundary(nil, sink)
	if p.Available() {
		t.Error("Boundary(nil, sink) reported itself available")
	}
	if _, err := p.Complete(context.Background(), req); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Boundary(nil, sink).Complete err = %v, want ErrUnavailable", err)
	}
	if got := len(sink.all()); got != 1 {
		t.Errorf("got %d audit records from a nil-provider call, want 1", got)
	}
}

func TestWithAudit_NilSinkIsAPassthrough(t *testing.T) {
	mock := &MockProvider{ProviderName: "mock-y"}
	if got := WithAudit(mock, nil); got != Provider(mock) {
		t.Errorf("WithAudit with a nil sink returned %T, want the provider unchanged", got)
	}
}

func TestSinkFunc_Adapts(t *testing.T) {
	var got AuditRecord
	sink := SinkFunc(func(_ context.Context, rec AuditRecord) { got = rec })

	p := Boundary(&MockProvider{}, sink)
	_, _ = p.Complete(context.Background(), Request{Seam: SeamAuthor, Invoker: "user:0f3a"})

	if got.Seam != SeamAuthor {
		t.Errorf("SinkFunc did not receive the record: %+v", got)
	}
}

func TestPromptHash_IsStableAndSensitive(t *testing.T) {
	base := Request{
		Seam:     SeamNarrator,
		Model:    "m1",
		System:   "sys",
		Messages: []Message{{Role: "user", Content: "hello"}},
		Context: []map[string]any{{
			"b": 2, "a": 1, "nested": map[string]any{"z": "zz", "y": "yy"},
		}},
	}

	first := PromptHash(base)

	// Stable: the same prompt hashes the same however many times you ask, and
	// whatever order Go happens to walk the maps in this run. Repeat enough
	// times that a map-order dependency would show up.
	for i := 0; i < 50; i++ {
		if got := PromptHash(base); got != first {
			t.Fatalf("PromptHash is not stable across calls: %q != %q (iteration %d)", got, first, i)
		}
	}

	// Sensitive: any change to any part of the prompt changes the digest.
	mutations := map[string]func(r *Request){
		"seam":            func(r *Request) { r.Seam = SeamQuery },
		"model":           func(r *Request) { r.Model = "m2" },
		"system":          func(r *Request) { r.System = "sys2" },
		"message content": func(r *Request) { r.Messages[0].Content = "hello!" },
		"message role":    func(r *Request) { r.Messages[0].Role = "assistant" },
		"extra message":   func(r *Request) { r.Messages = append(r.Messages, Message{Role: "user", Content: ""}) },
		"context value":   func(r *Request) { r.Context[0]["a"] = 99 },
		"context key":     func(r *Request) { r.Context[0]["c"] = 3 },
		"nested value":    func(r *Request) { r.Context[0]["nested"].(map[string]any)["z"] = "changed" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := cloneRequest(base)
			mutate(&mutated)
			if PromptHash(mutated) == first {
				t.Errorf("changing the %s did not change the prompt hash", name)
			}
		})
	}
}

// goldenHashFixture exercises every branch of the hasher: a nested map, a
// []map[string]any (what a Go caller builds), a []any of mixed scalars and maps
// (what encoding/json produces), and the scalar types that take the %T:%v tag.
func goldenHashFixture() Request {
	return Request{
		Seam:     SeamNarrator,
		Model:    "golden-model",
		System:   "summarise the posture",
		Messages: []Message{{Role: "user", Content: "what changed?"}},
		Context: []map[string]any{{
			"hostname":  "edge01",
			"key_size":  2048,
			"weak":      false,
			"ratio":     0.5,
			"nested":    map[string]any{"protocol_version": "TLSv1.2", "cipher": "TLS_AES_256_GCM_SHA384"},
			"certs":     []map[string]any{{"serial": "01"}, {"serial": "02"}},
			"mixed":     []any{"a", 2, map[string]any{"b": "c"}, []any{"deep"}},
			"empty_map": map[string]any{},
		}},
		MaxTokens: 1024,
		Invoker:   "user:0f3a",
	}
}

// The digest is a stored value: an operator comparing this week's audit rows
// against last quarter's is comparing hex strings across releases. So the
// SCHEME — the length prefixes, the "m"/"s"/"t"/"v" type tags, the sorted map
// keys — is part of the contract, not an implementation detail, and a
// refactor that changes it silently makes every historical row incomparable
// while every other test stays green.
//
// This constant is that contract. If it fails, the question is not "update the
// golden" but "did we mean to invalidate every digest ever recorded".
func TestPromptHash_GoldenDigest(t *testing.T) {
	const golden = "379bff3099b70e56d56d185858c81a60e0e43924d1043eda016c2047e249080f"

	got := PromptHash(goldenHashFixture())
	if got != golden {
		t.Errorf("PromptHash of the golden fixture = %q, want %q\n"+
			"The hashing scheme changed. Every prompt hash recorded by every deployment "+
			"before this change is now incomparable with the ones after it; if that is "+
			"intended, say so in the commit and update the constant.", got, golden)
	}
}

// Determinism over the same fixture: Go randomises map iteration per process,
// and a digest that changed on every call would turn the audit trail's most
// useful column into noise.
func TestPromptHash_GoldenFixtureIsDeterministic(t *testing.T) {
	first := PromptHash(goldenHashFixture())
	for i := 0; i < 200; i++ {
		// A fresh fixture each time: same content, different map internals.
		if got := PromptHash(goldenHashFixture()); got != first {
			t.Fatalf("iteration %d hashed %q, first call hashed %q", i, got, first)
		}
	}
}

// Length prefixes exist so that moving a boundary between adjacent strings
// changes the digest. Without them these two prompts collide.
func TestPromptHash_FieldBoundariesMatter(t *testing.T) {
	a := Request{System: "ab", Messages: []Message{{Role: "user", Content: "c"}}}
	b := Request{System: "a", Messages: []Message{{Role: "user", Content: "bc"}}}

	if PromptHash(a) == PromptHash(b) {
		t.Error("two different prompts hash alike; the length prefixes are not doing their job")
	}
}

// The digest must be of what crossed the boundary, which is why audit wraps
// redaction and not the other way round.
func TestPromptHash_ChangesOnceRedacted(t *testing.T) {
	req := Request{Seam: SeamNarrator, System: "admin_password: hunter2"}

	if PromptHash(req) == PromptHash(Redact(req)) {
		t.Error("the redacted prompt hashes like the raw one; redaction changed nothing")
	}
}

// (The test's own deep-copy helper was replaced by cloneRequest, the one the
// mock provider uses: two copiers would be two opinions about what "a copy of a
// request" means, and the mutation table below is only meaningful if the copy
// is genuinely independent.)
