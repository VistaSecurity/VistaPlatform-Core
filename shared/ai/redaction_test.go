package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// ADR-0008 D4.5. The mutation test for this one is spelled out at the bottom of
// the file: bypass the decorator, confirm these fail, restore.
func TestWithRedaction_RedactsSecretsInMessagesAndLeavesPosture(t *testing.T) {
	const (
		password = "hunter2-the-service-account"
		token    = "EXAMPLE-api-token-9f8e7d6c5b4a"
		psk      = "76cb7a67a0650c263bd78635193fc1b2"
		pem      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3\n-----END RSA PRIVATE KEY-----"
	)

	mock := &MockProvider{Responses: []Response{{Text: "ok", ModelID: "mock-1"}}}
	p := WithRedaction(mock)

	_, err := p.Complete(context.Background(), Request{
		Seam:   SeamNarrator,
		System: "You summarise crypto posture. admin_password: " + password,
		Messages: []Message{{
			Role: "user",
			Content: `Summarise this host.
{"api_token": "` + token + `", "cipher_suite": "TLS_AES_256_GCM_SHA384", "key_size": 2048}
pre_shared_key = ` + psk + `
protocol_version: TLSv1.2
` + pem,
		}},
		Context: []map[string]any{{
			"hostname":       "edge01",
			"admin_password": password,
			"key_algorithm":  "RSA",
			"nested": map[string]any{
				"webhook_url": "https://hooks.example.com/services/T/B/" + token,
			},
		}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	sent, ok := mock.LastRequest()
	if !ok {
		t.Fatal("the mock provider received no request")
	}
	if !sent.IsSanitized() {
		t.Error("WithRedaction did not mark the request sanitized")
	}

	// Everything the provider saw, flattened, so a secret cannot hide in a
	// field the assertions below forgot to name.
	seen := flatten(sent)

	for name, secret := range map[string]string{
		"account password":     password,
		"API token":            token,
		"pre-shared key":       psk,
		"PEM private key body": "MIIEowIBAAKCAQEA0Z3VS5JJcds3",
	} {
		if strings.Contains(seen, secret) {
			t.Errorf("%s crossed the provider boundary:\n%s", name, seen)
		}
	}

	// The inverse polarity: a boundary that eats the posture has destroyed the
	// question along with the answer.
	for _, posture := range []string{
		"TLS_AES_256_GCM_SHA384", "key_size", "2048", "TLSv1.2", "RSA", "edge01",
	} {
		if !strings.Contains(seen, posture) {
			t.Errorf("posture %q was redacted out of the prompt; the boundary is over-strict:\n%s", posture, seen)
		}
	}
}

func TestRedact_DoesNotMutateItsInput(t *testing.T) {
	in := Request{
		System:   "password: hunter2",
		Messages: []Message{{Role: "user", Content: "api_key: abc123"}},
		Context:  []map[string]any{{"admin_password": "hunter2"}},
	}
	_ = Redact(in)

	if !strings.Contains(in.System, "hunter2") {
		t.Error("Redact mutated the caller's System prompt")
	}
	if !strings.Contains(in.Messages[0].Content, "abc123") {
		t.Error("Redact mutated the caller's message")
	}
	if in.Context[0]["admin_password"] != "hunter2" {
		t.Error("Redact mutated the caller's context map")
	}
}

func TestRedactText_KeyValueForms(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		mustLose string
		mustKeep string
		// wantJSON asserts the output still parses. The quote-preserving branch
		// exists precisely so a redacted JSON blob stays JSON, and nothing
		// pinned that: the row below would pass just as well if the marker were
		// written unquoted and the payload became unparseable.
		wantJSON bool
	}{
		{name: "colon", in: "password: hunter2", mustLose: "hunter2", mustKeep: "password"},
		{name: "equals", in: "api_key=abc123", mustLose: "abc123", mustKeep: "api_key"},
		{
			name: "json quoted", in: `{"client_secret": "shh"}`,
			mustLose: "shh", mustKeep: "client_secret", wantJSON: true,
		},
		{
			name: "json compact, next field survives", in: `{"auth":"Basic xyz","key_size":2048}`,
			mustLose: "Basic xyz", mustKeep: "2048", wantJSON: true,
		},
		{
			// The unquoted-value terminator: the value runs to the next comma,
			// not to the end of the object. Nothing exercised this — widening
			// the terminator to "anything but a newline" passed the whole suite
			// while quietly eating every later field on the line.
			name: "unquoted value stops at the comma", in: `{"auth": abc, "key_size": 2048}`,
			mustLose: "abc", mustKeep: "2048",
		},
		{
			name: "unquoted value stops at the brace", in: `{"auth": abc}`,
			mustLose: "abc", mustKeep: "}",
		},
		{name: "posture with a colon is untouched", in: "cipher_suite: TLS_AES_128_GCM_SHA256", mustKeep: "TLS_AES_128_GCM_SHA256"},
		{name: "key_size is not key material", in: "key_size: 2048", mustKeep: "2048"},
		{name: "public_key is publishable", in: "public_key: MIIBIjANBgkq", mustKeep: "MIIBIjANBgkq"},
		{name: "webhook url is the secret", in: "webhook_url: https://hooks.example.com/T/B/XXXX", mustLose: "hooks.example.com", mustKeep: "webhook_url"},
		{name: "dashed spelling", in: "private-key: abcdef", mustLose: "abcdef", mustKeep: "private-key"},
		{
			name: "single quotes keep their quoting", in: `{'password': 'hunter2'}`,
			mustLose: "hunter2", mustKeep: "'" + "[redacted]" + "'",
		},
		{
			name: "an escaped quote does not end the value early",
			in:   `{"password": "hun\"ter2", "key_size": 2048}`,
			// If the escape were mishandled the value would end at the inner
			// quote and `ter2` would survive.
			mustLose: "ter2", mustKeep: "2048", wantJSON: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactText(tc.in)
			if tc.mustLose != "" && strings.Contains(got, tc.mustLose) {
				t.Errorf("redactText(%q) = %q; %q should not have survived", tc.in, got, tc.mustLose)
			}
			if tc.mustKeep != "" && !strings.Contains(got, tc.mustKeep) {
				t.Errorf("redactText(%q) = %q; %q should have survived", tc.in, got, tc.mustKeep)
			}
			if tc.wantJSON && !json.Valid([]byte(got)) {
				t.Errorf("redactText(%q) = %q, which is no longer valid JSON", tc.in, got)
			}
		})
	}
}

// The hole this rule used to have, in both of the shapes that produced it.
//
// The old pattern matched a name AND its value together, with the unquoted
// value running to the next comma, brace or newline. So the FIRST pair on a
// space-separated line claimed everything after it — including later pairs —
// and because the regex engine resumed past the end of that match, the secret
// pair inside was never evaluated at all. It crossed the boundary in clear,
// with every test in this file green.
func TestRedactText_ANonSecretPairCannotSwallowALaterSecretOne(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		mustLose []string
		mustKeep []string
	}{
		{
			name:     "space-separated line, secret last",
			in:       "cipher_suite: TLS_AES_256_GCM_SHA384 key_size: 2048 admin_password: hunter2",
			mustLose: []string{"hunter2"},
			mustKeep: []string{"TLS_AES_256_GCM_SHA384", "2048", "cipher_suite", "admin_password"},
		},
		{
			name:     "nested unquoted object",
			in:       `{"config": {"password": "hunter2"}, "key_size": 2048}`,
			mustLose: []string{"hunter2"},
			mustKeep: []string{"2048", "config"},
		},
		{
			name:     "two secrets on one line, both go",
			in:       "api_key: aaa111 note: fine x_mesh_psk: bbb222 key_size: 2048",
			mustLose: []string{"aaa111", "bbb222"},
			mustKeep: []string{"2048"},
		},
		{
			name:     "a secret pair after a sentence containing a colon",
			in:       "Summarise this host: it is an edge router. admin_password: hunter2",
			mustLose: []string{"hunter2"},
			mustKeep: []string{"edge router"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactText(tc.in)
			for _, secret := range tc.mustLose {
				if strings.Contains(got, secret) {
					t.Errorf("%q crossed the boundary:\n in: %q\nout: %q", secret, tc.in, got)
				}
			}
			for _, keep := range tc.mustKeep {
				if !strings.Contains(got, keep) {
					t.Errorf("%q was eaten; the rule is over-strict:\n in: %q\nout: %q", keep, tc.in, got)
				}
			}
		})
	}
}

// Context is the path the docs tell callers to PREFER, and it was the one path
// the prose rule never ran over: a row rendered to a string before it was put
// in the map is prose inside a structured field, and name-based redaction
// cannot see into it. A PEM key pasted into the same place had the same
// immunity.
func TestRedact_ContextStringLeavesAreValueScrubbedToo(t *testing.T) {
	const (
		password   = "hunter2-the-service-account"
		privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAA\n-----END OPENSSH PRIVATE KEY-----"
	)

	out := Redact(Request{
		Seam:    SeamNarrator,
		Invoker: "user:0f3a",
		Context: []map[string]any{{
			// Innocent field names, secrets in the values.
			"summary":  "host edge01, admin_password: " + password + ", key_size: 2048",
			"banner":   "SSH-2.0-OpenSSH_9.6\n" + privateKey,
			"evidence": []any{map[string]any{"line": "api_key = " + password}},
			"lines":    []string{"protocol_version: TLSv1.2", "client_secret: " + password},
		}},
	})

	seen := flatten(out)
	if strings.Contains(seen, password) {
		t.Errorf("a secret in a Context string crossed the boundary:\n%s", seen)
	}
	if strings.Contains(seen, "b3BlbnNzaC1rZXktdjEAAA") {
		t.Errorf("a PEM private key in a Context string crossed the boundary:\n%s", seen)
	}

	// And the posture in the same strings survives.
	for _, keep := range []string{"edge01", "2048", "SSH-2.0-OpenSSH_9.6", "TLSv1.2"} {
		if !strings.Contains(seen, keep) {
			t.Errorf("posture %q was scrubbed out of the context; the rule is over-strict:\n%s", keep, seen)
		}
	}
}

// A pasted key has no field name to catch it by, so this rule is by shape. It
// is the one value-based rule at the boundary and it lives here, not in
// shared/redact, because it is a property of free prose.
func TestRedactText_PEMPrivateKeyBlocks(t *testing.T) {
	for _, kind := range []string{"RSA", "EC", "OPENSSH", "ENCRYPTED", ""} {
		header := strings.TrimSpace(kind + " PRIVATE KEY")
		block := "-----BEGIN " + header + "-----\nc2VjcmV0Ynl0ZXM=\n-----END " + header + "-----"

		got := redactText("here you go:\n" + block + "\nthanks")
		if strings.Contains(got, "c2VjcmV0Ynl0ZXM=") {
			t.Errorf("%s private key survived: %q", kind, got)
		}
		if !strings.Contains(got, "thanks") {
			t.Errorf("%s block redaction swallowed the text after it: %q", kind, got)
		}
	}
}

func TestRedactText_TwoPEMBlocksRedactedSeparately(t *testing.T) {
	// Non-greedy matching: a greedy pattern would redact everything between the
	// first BEGIN and the last END, taking the posture in the middle with it.
	in := "-----BEGIN EC PRIVATE KEY-----\naaa\n-----END EC PRIVATE KEY-----\n" +
		"cipher_suite: TLS_AES_256_GCM_SHA384\n" +
		"-----BEGIN EC PRIVATE KEY-----\nbbb\n-----END EC PRIVATE KEY-----"

	got := redactText(in)
	if strings.Contains(got, "aaa") || strings.Contains(got, "bbb") {
		t.Errorf("a key body survived: %q", got)
	}
	if !strings.Contains(got, "TLS_AES_256_GCM_SHA384") {
		t.Errorf("greedy match swallowed the posture between two keys: %q", got)
	}
}

func TestWithRedaction_PreservesNameAndAvailability(t *testing.T) {
	mock := &MockProvider{ProviderName: "mock-x", Unavailable: true}
	p := WithRedaction(mock)

	if p.Name() != "mock-x" {
		t.Errorf("Name() = %q, want the inner provider's", p.Name())
	}
	if p.Available() {
		t.Error("Available() should pass through the inner provider's answer")
	}
}

// The sanitized flag is unexported and [Redact] is the only thing that sets it.
// These three assertions are what a `t.Skip`ped "mutation note" used to stand in
// for; a skipped test proves nothing, and the property is cheap to state.
//
// (The hand-run mutation for the redactor itself is still worth repeating: make
// redactingProvider.Complete forward req unchanged and confirm
// TestWithRedaction_RedactsSecretsInMessagesAndLeavesPosture fails on every
// secret; then make redactText redact regardless of IsSecretName and confirm
// the posture assertions fail. Both directions verified when this landed.)
func TestSanitizedFlag_OnlyRedactSetsIt(t *testing.T) {
	raw := Request{
		Seam:     SeamNarrator,
		Invoker:  "user:0f3a",
		System:   "admin_password: hunter2",
		Messages: []Message{{Role: "user", Content: "what is it?"}},
	}

	// A request a caller assembled itself is not sanitized, however complete it
	// looks. There is no exported field to set, so this is the only shape an
	// unredacted request can have.
	if raw.IsSanitized() {
		t.Error("a hand-built Request reported itself sanitized")
	}
	if (Request{}).IsSanitized() {
		t.Error("the zero Request reported itself sanitized")
	}

	// And a provider refuses it.
	mock := &MockProvider{}
	if _, err := mock.Complete(context.Background(), raw); !errors.Is(err, ErrNotSanitized) {
		t.Errorf("err = %v, want ErrNotSanitized", err)
	}

	// Redact is the one way through.
	if !Redact(raw).IsSanitized() {
		t.Error("Redact did not mark its output sanitized")
	}
	if _, err := mock.Complete(context.Background(), Redact(raw)); err != nil {
		t.Errorf("a redacted request was refused: %v", err)
	}
}

// The mock's record of what it received must not change under the caller's
// feet. A shallow copy shares the Context maps and the Messages array, so a
// caller reusing its buffers would rewrite history — in the one place built to
// record it.
func TestMockProvider_RecordsADeepCopy(t *testing.T) {
	mock := &MockProvider{}
	ctx := map[string]any{"hostname": "edge01", "nested": map[string]any{"port": 443}}
	msgs := []Message{{Role: "user", Content: "original"}}

	req := Redact(Request{Seam: SeamQuery, Messages: msgs, Context: []map[string]any{ctx}})
	if _, err := mock.Complete(context.Background(), req); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Mutate everything the caller still holds a reference to, including the
	// copy Redact handed back.
	req.Messages[0].Content = "tampered"
	req.Context[0]["hostname"] = "tampered"
	req.Context[0]["nested"].(map[string]any)["port"] = 0

	got, ok := mock.LastRequest()
	if !ok {
		t.Fatal("no request recorded")
	}
	if got.Messages[0].Content != "original" {
		t.Errorf("recorded message changed after the fact: %q", got.Messages[0].Content)
	}
	if got.Context[0]["hostname"] != "edge01" {
		t.Errorf("recorded context changed after the fact: %v", got.Context[0]["hostname"])
	}
	if got.Context[0]["nested"].(map[string]any)["port"] != 443 {
		t.Errorf("recorded nested context changed after the fact: %v", got.Context[0]["nested"])
	}

	// Mutating what Requests() hands out must not reach the mock either.
	all := mock.Requests()
	all[0].Context[0]["hostname"] = "tampered-again"
	if again, _ := mock.LastRequest(); again.Context[0]["hostname"] != "edge01" {
		t.Errorf("Requests() handed out a reference to the recorded request: %v", again.Context[0])
	}
}

// flatten renders everything a provider received into one string for
// contains-checks, so a secret cannot hide in a field an assertion forgot.
func flatten(req Request) string {
	var b strings.Builder
	b.WriteString(req.System)
	b.WriteString("\n")
	for _, m := range req.Messages {
		b.WriteString(m.Content)
		b.WriteString("\n")
	}
	for _, c := range req.Context {
		writeMap(&b, c)
	}
	return b.String()
}

func writeMap(b *strings.Builder, m map[string]any) {
	for k, v := range m {
		b.WriteString(k)
		b.WriteString("=")
		if nested, ok := v.(map[string]any); ok {
			writeMap(b, nested)
			continue
		}
		if items, ok := v.([]any); ok {
			for _, item := range items {
				if nested, ok := item.(map[string]any); ok {
					writeMap(b, nested)
					continue
				}
				b.WriteString(strings.TrimSpace(stringify(item)))
			}
			continue
		}
		b.WriteString(stringify(v))
		b.WriteString("\n")
	}
}

func stringify(v any) string { return fmt.Sprintf("%v", v) }

// Redaction is idempotent: scrubbing already-scrubbed text changes nothing.
//
// This is not a tidiness property, it is a correctness one, and it was broken.
// The marker `[redacted]` ends in `]`, which valueTerminators lists, so the
// second pass read the value as `[redacted` — one byte short — replaced it with
// a fresh marker and left the old closing bracket behind: `[redacted]]`, then
// `]]`, growing by a byte on every pass.
//
// Two things depend on the fix. ai.WithAudit hashes the request it forwards, so
// a prompt that had been through the boundary twice would hash differently from
// the same prompt seen once — and "is this the same question as last time" is
// the question D4.7's digest exists to answer. And ai.Redact is exported
// precisely so a caller can scrub early and then index into the result; the
// author seam cites pasted standards by byte offset, and a rewrite that shifts
// on every pass would have every offset it recorded name different text than it
// read.
func TestRedactText_IsIdempotent(t *testing.T) {
	cases := map[string]string{
		"unquoted":             "admin_password: hunter2",
		"quoted":               `{"password": "hunter2", "key_size": 2048}`,
		"single quoted":        "token = 'abc123'",
		"equals form":          "api_key=abcdef",
		"among posture":        "cipher_suite: TLS_AES_256_GCM_SHA384 admin_password: hunter2 key_size: 2048",
		"nothing to redact":    "cipher_suite: TLS_AES_256_GCM_SHA384 key_size: 2048",
		"value already marker": "admin_password: " + redact.Marker,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			once := redactText(input)
			twice := redactText(once)
			if twice != once {
				t.Fatalf("second pass changed the text:\n once %q\ntwice %q", once, twice)
			}
			// A third, because a bug that grows by a byte per pass could in
			// principle have had a two-cycle instead.
			if thrice := redactText(twice); thrice != once {
				t.Fatalf("third pass changed the text:\n  once %q\nthrice %q", once, thrice)
			}
		})
	}
}

// The inverse polarity. A rule that achieved idempotence by not redacting at
// all would pass the test above, so pin that the first pass still removes the
// secret and still leaves the posture fields alone.
func TestRedactText_IdempotenceDoesNotWeakenTheFirstPass(t *testing.T) {
	const line = "cipher_suite: TLS_AES_256_GCM_SHA384 admin_password: hunter2 key_size: 2048"
	got := redactText(redactText(line))

	if strings.Contains(got, "hunter2") {
		t.Fatalf("the secret survived: %q", got)
	}
	if !strings.Contains(got, "TLS_AES_256_GCM_SHA384") || !strings.Contains(got, "2048") {
		t.Fatalf("posture fields were eaten: %q", got)
	}
	if strings.Count(got, redact.Marker) != 1 {
		t.Fatalf("marker count = %d, want exactly one: %q", strings.Count(got, redact.Marker), got)
	}
}

// A quoted marker must be consumed WITH its quotes, or the closing one is left
// behind as a stray byte in the same way the bracket was.
func TestRedactText_QuotedMarkerIsRecognisedWholesale(t *testing.T) {
	once := redactText(`{"password": "hunter2"}`)
	if want := `{"password": "` + redact.Marker + `"}`; once != want {
		t.Fatalf("first pass = %q, want %q", once, want)
	}
	if twice := redactText(once); twice != once {
		t.Fatalf("second pass = %q, want it unchanged", twice)
	}
}
