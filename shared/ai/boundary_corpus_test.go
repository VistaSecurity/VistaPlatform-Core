package ai

// Gate 4's per-seam secret-class fixture, stated once at the boundary every
// seam actually goes through.
//
// # Why one corpus and not five
//
// The gate asks for a fixture per generative seam carrying every class of
// secret, asserted against the provider's received request. Five copies of the
// same corpus in five packages is five things to keep in step, and the fourth
// one to drift would be the one nobody notices — this repository's own lesson
// about hand-maintained parallel lists.
//
// What makes one corpus sufficient here is that the composition is now
// structural: TestBoundaryIsTheOnlySupportedComposition holds that [Boundary]
// is the ONLY way a non-test file outside this package may wrap a provider, and
// every one of the five seams wires it. So "what crosses for seam X" is
// `Boundary`'s answer for seam X's request, and this file asks exactly that,
// once per seam, over the full corpus.
//
// It does not replace the per-seam tests and is not meant to. Those pin
// something this cannot: that each seam's own PROJECTION puts a value somewhere
// the redactor can judge it. The remediator's
// TestPropose_EvidenceKeepsItsFieldNamesSoTheRedactorCanJudgeThem is the shape —
// flatten an evidence map into `{"key":…,"value":…}` rows and every secret
// arrives under the innocent name `value`, with a boundary that is working
// perfectly. Projection is per seam; redaction is per boundary; this file is
// the second.
//
// # What is NOT in the corpus, deliberately
//
// Email addresses. They are PII, not secret material, and this redactor is
// name-based over secrets: `owner` and `email` are not secret names and must not
// become them. A tenant's asset rows legitimately carry an owner — the query
// seam's own system prompt says so — and scrubbing it would break the answers
// while protecting nothing the caller did not already have. The seam that must
// send no identifiers at all is the remediator, and that is a PROJECTION rule
// enforced in its own package (TestPropose_NoIdentifiersCrossTheBoundary), not
// a redaction rule. Saying which layer owns which rule is the point; a corpus
// that quietly included emails would assert a guarantee no layer makes.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// secretClass is one class of material that must never reach a provider, with a
// sentinel value distinctive enough to grep the serialised request for.
type secretClass struct {
	name  string
	field string
	value string
}

func boundaryCorpus() []secretClass {
	return []secretClass{
		{"credential", "admin_password", "s3rvice-acct-Pa55w0rd"},
		{"pre-shared key", "pre_shared_key", "76cb7a67a0650c263bd78635193fc1b2"},
		{"API token", "api_token", "EXAMPLE-api-token-9f8e7d6c5b4a"},
		{"API key", "apiKey", "EXAMPLE-api-key-1a2b3c4d5e6f"},
		{"bearer header", "authorization", "Bearer EXAMPLE-jwt-aaaa.bbbb.cccc"},
		{"SNMP community string", "snmp_community", "EXAMPLE-ro-community-str"},
		{"bare SNMP community", "community", "EXAMPLE-bare-community-str"},
		{"webhook URL", "webhook_url", "https://hooks.example.com/services/T000/B000/EXAMPLEXXXXXXXXXXXX"},
		{"OAuth client secret", "client_secret", "EXAMPLE-client-secret-zzzz"},
		{"PEM private key", "private_key",
			"-----BEGIN OPENSSH PRIVATE KEY-----\nEXAMPLEb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----"},
	}
}

// posture is what the model is being ASKED about. An over-strict boundary that
// eats it has destroyed the question along with the answer, and would do it
// silently — the same bug pointed the other way.
var boundaryPosture = map[string]string{
	"cipher_suite":     "TLS_AES_256_GCM_SHA384",
	"protocol_version": "TLSv1.2",
	"key_algorithm":    "RSA",
	"public_key":       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	"authmethod":       "publickey",
	"host_key_type":    "ssh-ed25519",
	"owner":            "platform-team@example.com",
}

// corpusRequest builds the request for one seam, putting the corpus into every
// shape a prompt has: the structured Context (nested, and inside a slice), a
// string LEAF of the Context (a row somebody rendered to prose before putting
// it in a structured field — pass 1 cannot see into that), the system prompt,
// and a user message.
func corpusRequest(seam Seam, corpus []secretClass) Request {
	nested := map[string]any{}
	inSlice := map[string]any{}
	var prose, leaf strings.Builder
	for i, c := range corpus {
		if i%2 == 0 {
			nested[c.field] = c.value
		} else {
			inSlice[c.field] = c.value
		}
		prose.WriteString(c.field + ": " + c.value + "\n")
		leaf.WriteString(c.field + "=" + c.value + "\n")
	}

	ctxRow := map[string]any{
		"asset":  "web01",
		"config": nested,
		"items":  []any{inSlice},
		// The prose-inside-a-structured-field case.
		"rendered_row": leaf.String(),
	}
	for k, v := range boundaryPosture {
		ctxRow[k] = v
	}

	return Request{
		Seam:    seam,
		Invoker: "user:11111111-1111-1111-1111-111111111111",
		System:  "You summarise inventory rows.\n" + prose.String(),
		Messages: []Message{
			{Role: "user", Content: "why is this flagged?\n" + prose.String()},
		},
		Context: []map[string]any{ctxRow},
	}
}

// Every GENERATIVE seam, every secret class, every prompt shape: nothing
// reaches the provider, and the posture does.
func TestBoundary_NoSecretClassReachesTheProviderForAnySeam(t *testing.T) {
	corpus := boundaryCorpus()

	for _, seam := range AllSeams() {
		t.Run(string(seam), func(t *testing.T) {
			mock := &MockProvider{Responses: []Response{{ModelID: "m", Text: "ok"}}}
			var records []AuditRecord
			p := Boundary(mock, SinkFunc(func(_ context.Context, r AuditRecord) { records = append(records, r) }))

			if _, err := p.Complete(context.Background(), corpusRequest(seam, corpus)); err != nil {
				t.Fatalf("Complete: %v", err)
			}

			got, ok := mock.LastRequest()
			if !ok {
				t.Fatal("the provider was never called; this subtest proves nothing")
			}
			if !got.IsSanitized() {
				t.Fatal("the request reached the provider without passing through Redact")
			}
			blob := serialiseRequest(t, got)

			for _, c := range corpus {
				if strings.Contains(blob, c.value) {
					t.Errorf("%s (%s) crossed the provider boundary for seam %s:\n%s", c.name, c.field, seam, blob)
				}
			}
			// Non-vacuity: if the marker is nowhere, the corpus never reached
			// the request in the first place and the loop above compared
			// nothing against nothing.
			if !strings.Contains(blob, "[redacted]") {
				t.Fatalf("no redaction marker anywhere in the request; the corpus never got in:\n%s", blob)
			}
			// The inverse polarity, per posture field rather than in aggregate,
			// so a regression names the field that moved. The nested `config`
			// and the sliced `items` are secret-only by construction, so these
			// are read off the top-level row.
			for field, want := range boundaryPosture {
				if !strings.Contains(blob, want) {
					t.Errorf("posture field %q (%s) was destroyed at the boundary for seam %s", field, want, seam)
				}
			}

			// D4.7: one record per call, carrying a digest of what actually
			// crossed, and never the prompt itself unless the tenant opted in.
			if len(records) != 1 {
				t.Fatalf("audit records = %d, want exactly one per call", len(records))
			}
			if records[0].PromptSHA256 != PromptHash(got) {
				t.Error("the audit record's digest is not of the request the provider received")
			}
			if _, recorded := records[0].Attributes[AuditAttrPrompt]; recorded {
				t.Error("the prompt was recorded with no tenant opt-in (D4.7)")
			}
		})
	}
}

// The forward mutation, run in-process rather than left as a comment: with the
// redaction decorator removed, every class in the corpus reaches the provider.
// A guard that cannot fail is worse than no guard, and this one says so with a
// number rather than with an instruction to go and edit a file.
func TestBoundary_WithoutRedactionEverySecretClassLeaks(t *testing.T) {
	corpus := boundaryCorpus()
	mock := &MockProvider{Responses: []Response{{ModelID: "m", Text: "ok"}}}

	// Redact by hand so the request satisfies the provider's own sanitized
	// check, then send the UNREDACTED one — which is precisely what a caller
	// that skipped WithRedaction would do if nothing stopped them.
	req := corpusRequest(SeamNarrator, corpus)
	unredacted := req
	blessed := Redact(req)
	unredacted.sanitized = blessed.sanitized

	if _, err := mock.Complete(context.Background(), unredacted); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, _ := mock.LastRequest()
	blob := serialiseRequest(t, got)

	var leaked int
	for _, c := range corpus {
		if strings.Contains(blob, c.value) {
			leaked++
			continue
		}
		t.Errorf("%s (%s) did NOT leak without the redactor — so the forward test proves nothing about it",
			c.name, c.field)
	}
	if leaked != len(corpus) {
		t.Fatalf("only %d of %d classes leaked with redaction removed", leaked, len(corpus))
	}
}

// serialiseRequest flattens a request to one searchable string: the prose, the
// system prompt and the whole JSON of the context. Searching the serialisation
// rather than enumerated keys is what catches a value that survived at a nesting
// depth the assertions did not think of.
func serialiseRequest(t *testing.T, r Request) string {
	t.Helper()
	ctx, err := json.Marshal(r.Context)
	if err != nil {
		t.Fatalf("marshal context: %v", err)
	}
	var b strings.Builder
	b.WriteString(r.System)
	for _, m := range r.Messages {
		b.WriteString("\n" + m.Content)
	}
	b.WriteString("\n" + string(ctx))
	return b.String()
}
