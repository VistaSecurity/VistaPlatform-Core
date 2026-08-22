package email

import (
	"html/template"
	"strings"
	"testing"
)

// captureHTML renders one sender's mail and returns the HTML part, without
// touching the network. SendEmail dials SMTP, so the templates are exercised
// directly -- these tests are about what the template produces, not delivery.
func renderOrFail(t *testing.T, tmpl *template.Template, data any) string {
	t.Helper()
	got, err := renderHTML(tmpl, data)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return got
}

// A name carrying markup must not reach the recipient as markup.
//
// This is the half of go/email-injection that the boundary fix did not close:
// the org name, inviter name and white-label brand are attacker-influenced and
// were interpolated into the HTML part with fmt.Sprintf, which escapes nothing.
func TestTemplates_MarkupInNamesIsEscaped(t *testing.T) {
	const payload = `Acme<script>alert(1)</script><img src=x onerror=alert(2)>`

	cases := []struct {
		name string
		got  string
	}{
		{"tenant invite org", renderOrFail(t, tenantInviteHTML, struct{ Brand, Org, Link string }{"Vista", payload, "https://example.com/a"})},
		{"platform invite inviter", renderOrFail(t, platformInviteHTML, struct{ Platform, Inviter, Link, SSONames string }{"Vista", payload, "https://example.com/a", ""})},
		{"platform invite brand", renderOrFail(t, platformPasswordResetHTML, struct{ Platform, Link string }{payload, "https://example.com/a"})},
		{"alert type", renderOrFail(t, alertHTML, struct {
			Brand, AlertType, Message string
			Details                   []detailRow
		}{"Vista", payload, "msg", nil})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.got, "<script>") {
				t.Errorf("raw <script> survived into the HTML part:\n%s", excerpt(tc.got, "script"))
			}
			// Check for the raw tag delimiter, not the attribute text: an
			// escaped payload still CONTAINS "onerror=alert(2)" as inert
			// characters, so asserting on that substring fails against a
			// correctly-escaped output and proves nothing.
			if strings.Contains(tc.got, "<img") {
				t.Errorf("raw <img> tag survived into the HTML part:\n%s", excerpt(tc.got, "<img"))
			}
			if !strings.Contains(tc.got, "&lt;script&gt;") {
				t.Errorf("payload was not entity-escaped as expected:\n%s", excerpt(tc.got, "Acme"))
			}
		})
	}
}

// The case that makes html/template the right tool rather than a hand-rolled
// escaper: a link lands in href="...", which is a URL context. Entity-escaping
// does nothing to "javascript:" -- it contains no HTML metacharacters at all --
// so an escape-at-the-call-site fix would have shipped this vulnerability while
// looking correct.
func TestTemplates_JavascriptURLIsNeutralised(t *testing.T) {
	const bad = "javascript:alert(document.cookie)"

	for _, tc := range []struct {
		name string
		got  string
	}{
		{"password reset", renderOrFail(t, passwordResetHTML, struct{ Brand, Link string }{"Vista", bad})},
		{"email verification", renderOrFail(t, emailVerificationHTML, struct{ Brand, Link string }{"Vista", bad})},
		{"tenant invite", renderOrFail(t, tenantInviteHTML, struct{ Brand, Org, Link string }{"Vista", "Acme", bad})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.got, `href="javascript:`) {
				t.Fatalf("javascript: URL reached an href:\n%s", excerpt(tc.got, "javascript"))
			}
			// html/template replaces a filtered URL with this sentinel.
			if !strings.Contains(tc.got, "#ZgotmplZ") {
				t.Fatalf("expected the URL filter to fire, got:\n%s", excerpt(tc.got, "href="))
			}
		})
	}
}

// An alert's details map is arbitrary: keys and values both come from whatever
// raised the alert, including user-authored threshold names.
func TestTemplates_AlertDetailsAreEscaped(t *testing.T) {
	got := renderOrFail(t, alertHTML, struct {
		Brand, AlertType, Message string
		Details                   []detailRow
	}{"Vista", "Expiry", "msg", []detailRow{
		{Key: "<b>key</b>", Value: "<i>value</i>"},
	}})

	if strings.Contains(got, "<b>key</b>") || strings.Contains(got, "<i>value</i>") {
		t.Fatalf("alert details reached the HTML part unescaped:\n%s", excerpt(got, "key"))
	}
	if !strings.Contains(got, "&lt;b&gt;key&lt;/b&gt;") {
		t.Fatalf("alert detail key was not escaped:\n%s", excerpt(got, "key"))
	}
}

// The SSO block used to be assembled as a pre-built HTML fragment and pasted in
// raw. The template owns it now, so provider names are escaped like any other
// text -- and the block still disappears entirely when there are no providers.
func TestTemplates_SSOBlockIsConditionalAndEscaped(t *testing.T) {
	with := renderOrFail(t, platformInviteHTML, struct{ Platform, Inviter, Link, SSONames string }{
		"Vista", "Bob", "https://example.com/a", "<script>x</script>Google"})
	if strings.Contains(with, "<script>x</script>") {
		t.Fatalf("SSO provider name reached the HTML part unescaped:\n%s", excerpt(with, "Continue with"))
	}
	if !strings.Contains(with, "Prefer single sign-on?") {
		t.Fatal("SSO block missing when providers were supplied")
	}

	without := renderOrFail(t, platformInviteHTML, struct{ Platform, Inviter, Link, SSONames string }{
		"Vista", "Bob", "https://example.com/a", ""})
	if strings.Contains(without, "Prefer single sign-on?") {
		t.Fatal("SSO block rendered with no providers")
	}
}

// A legitimate https link must survive untouched -- a filter that mangles the
// real link would break every invitation while passing the tests above.
func TestTemplates_LegitimateURLSurvives(t *testing.T) {
	const good = "https://vista.example.com/accept?token=abc123&x=1"
	got := renderOrFail(t, tenantInviteHTML, struct{ Brand, Org, Link string }{"Vista", "Acme", good})

	if strings.Contains(got, "#ZgotmplZ") {
		t.Fatalf("the URL filter rejected a legitimate https link:\n%s", excerpt(got, "href="))
	}
	// The ampersand is entity-encoded in HTML; the link is still intact.
	if !strings.Contains(got, "token=abc123&amp;x=1") {
		t.Fatalf("legitimate link was altered:\n%s", excerpt(got, "token="))
	}
}

func excerpt(s, needle string) string {
	i := strings.Index(s, needle)
	if i < 0 {
		return s[:min(len(s), 300)]
	}
	start := max(0, i-120)
	return s[start:min(len(s), i+180)]
}
