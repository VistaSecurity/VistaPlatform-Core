package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// The boundary's tenant gate (the second lock) and D4.7's opt-in, both
// implemented once in WithAudit so a seam added tomorrow inherits them.
//
// recordingSink and MockProvider are the package's existing test doubles
// (audit_test.go, provider.go). Using them rather than new ones is deliberate:
// MockProvider refuses an unsanitized request exactly as a real provider does,
// so a test that reached it without going through Boundary would fail rather
// than quietly prove nothing.

func aRequest() Request {
	return Request{
		Seam:     SeamNarrator,
		Invoker:  "user-1",
		System:   "you summarise",
		Messages: []Message{{Role: "user", Content: "summarise the diff"}},
	}
}

func anAnsweringMock() *MockProvider {
	return &MockProvider{
		ProviderName: "mock-provider",
		Responses:    []Response{{Text: "hello", ModelID: "m-1"}},
	}
}

// Forward polarity: the tenant turned the assistant off, so nothing is sent and
// the attempt is recorded as refused.
func TestWithAudit_RefusesADisabledTenant(t *testing.T) {
	mock := anAnsweringMock()
	sink := &recordingSink{}
	p := Boundary(mock, sink)

	ctx := WithTenantControls(context.Background(), TenantControls{AssistantDisabled: true})
	_, err := p.Complete(ctx, aRequest())

	if !errors.Is(err, ErrTenantDisabled) {
		t.Fatalf("err = %v, want ErrTenantDisabled", err)
	}
	// Every existing degradation path tests for ErrUnavailable; the kill switch
	// has to arrive as one of those, or each of them needs a new branch.
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("ErrTenantDisabled must wrap ErrUnavailable so existing fallbacks handle it")
	}
	if n := len(mock.Requests()); n != 0 {
		t.Fatalf("provider saw %d requests; the kill switch must forward nothing", n)
	}
	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("audit records = %d, want 1 — a refused attempt is still an attempt", len(recs))
	}
	if !recs[0].Refused {
		t.Fatal("the record must be marked Refused")
	}
	if recs[0].PromptSHA256 == "" {
		t.Fatal("a request that HAD been through the redactor still records its digest")
	}
}

// Inverse polarity, and the one that makes the forward test mean something:
// with the switch off, the same call goes through.
func TestWithAudit_AllowsAnEnabledTenant(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() context.Context
	}{
		{"explicitly enabled", func() context.Context {
			return WithTenantControls(context.Background(), TenantControls{AssistantDisabled: false})
		}},
		{"unstamped — absence of a stamp is not a refusal", context.Background},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := anAnsweringMock()
			sink := &recordingSink{}
			p := Boundary(mock, sink)

			resp, err := p.Complete(tc.ctx(), aRequest())
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if resp.Text != "hello" {
				t.Fatalf("text = %q", resp.Text)
			}
			if n := len(mock.Requests()); n != 1 {
				t.Fatalf("provider saw %d requests, want 1", n)
			}
			recs := sink.all()
			if len(recs) != 1 || recs[0].Refused {
				t.Fatalf("records = %+v, want one non-refused", recs)
			}
		})
	}
}

// ── D4.7's opt-in, at the boundary ─────────────────────────────────────────

func TestWithAudit_PromptRecordedOnlyOnOptIn(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		sink := &recordingSink{}
		p := Boundary(anAnsweringMock(), sink)
		if _, err := p.Complete(context.Background(), aRequest()); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		rec := sink.all()[0]
		if _, ok := rec.Attributes[AuditAttrPrompt]; ok {
			t.Fatal("D4.7: the prompt must not be stored absent the tenant's opt-in")
		}
		if rec.Attributes != nil {
			t.Fatal("no attributes at all, not an empty map — the two read differently")
		}
		if rec.PromptSHA256 == "" {
			t.Fatal("the HASH is recorded either way; that is the point of it")
		}
	})

	t.Run("on when the tenant opted in", func(t *testing.T) {
		sink := &recordingSink{}
		p := Boundary(anAnsweringMock(), sink)
		ctx := WithTenantControls(context.Background(), TenantControls{RecordQuestions: true})
		if _, err := p.Complete(ctx, aRequest()); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		got := sink.all()[0].Attributes[AuditAttrPrompt]
		if !strings.Contains(got, "summarise the diff") {
			t.Fatalf("prompt attribute = %q, want the user turn", got)
		}
		if strings.Contains(got, "you summarise") {
			t.Fatal("the SYSTEM prompt is ours and constant; a copy on every call buries the part that varies")
		}
	})
}

// The recorded prompt is the REDACTED one. Audit sits inside redaction, so this
// is structural rather than a convention — but it is the whole reason the
// opt-in is safe to offer, so it is pinned.
func TestWithAudit_RecordedPromptIsRedacted(t *testing.T) {
	sink := &recordingSink{}
	p := Boundary(anAnsweringMock(), sink)
	ctx := WithTenantControls(context.Background(), TenantControls{RecordQuestions: true})

	req := aRequest()
	req.Messages = []Message{{Role: "user", Content: "the api_key: sk-live-supersecret is failing"}}
	if _, err := p.Complete(ctx, req); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	got := sink.all()[0].Attributes[AuditAttrPrompt]
	if strings.Contains(got, "sk-live-supersecret") {
		t.Fatalf("the audit trail recorded an unredacted secret: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("nothing was redacted at all: %q", got)
	}
}

func TestWithAudit_RecordedPromptIsBounded(t *testing.T) {
	sink := &recordingSink{}
	p := Boundary(anAnsweringMock(), sink)
	ctx := WithTenantControls(context.Background(), TenantControls{RecordQuestions: true})

	req := aRequest()
	// Multi-byte runes so the cut has a boundary to get wrong.
	req.Messages = []Message{{Role: "user", Content: strings.Repeat("é", MaxAuditedPromptBytes)}}
	if _, err := p.Complete(ctx, req); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	got := sink.all()[0].Attributes[AuditAttrPrompt]
	if len(got) > MaxAuditedPromptBytes+len(auditedPromptTruncatedMarker) {
		t.Fatalf("recorded prompt is %d bytes, past the cap", len(got))
	}
	if !strings.HasSuffix(got, auditedPromptTruncatedMarker) {
		t.Fatal("a cut prompt must say it was cut — a fragment reads exactly like the whole thing")
	}
	body := strings.TrimSuffix(got, auditedPromptTruncatedMarker)
	if !utf8.ValidString(body) {
		t.Fatal("the cut landed mid-rune")
	}
}

// A request refused for NOT having been redacted carries neither a digest nor a
// prompt, opt-in or no opt-in: there is no text that passed the redactor to
// record.
func TestWithAudit_UnsanitizedRefusalRecordsNoPrompt(t *testing.T) {
	sink := &recordingSink{}
	p := WithAudit(anAnsweringMock(), sink) // deliberately NOT Boundary
	ctx := WithTenantControls(context.Background(), TenantControls{RecordQuestions: true})

	if _, err := p.Complete(ctx, aRequest()); !errors.Is(err, ErrNotSanitized) {
		t.Fatalf("err = %v, want ErrNotSanitized", err)
	}
	rec := sink.all()[0]
	if rec.PromptSHA256 != "" {
		t.Fatal("no digest of text that never passed the redactor")
	}
	if rec.Attributes != nil {
		t.Fatalf("no prompt either: %+v", rec.Attributes)
	}
}
