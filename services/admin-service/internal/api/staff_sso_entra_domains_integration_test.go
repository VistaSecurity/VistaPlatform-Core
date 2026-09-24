package api

// Staff SSO through Microsoft Entra with an allowed-email-domain list, driven
// through the REAL admin-service router against a real Postgres.
//
// Entra's userinfo (graph.microsoft.com/oidc/userinfo) carries no
// email_verified claim, so before allowed_email_domains existed every Entra
// staff sign-in failed closed. The list relaxes that one gate, and only under
// all of these conditions — each has a subtest that removes exactly it:
//
//   - the provider is a Microsoft admin-login app (Google and sign-up
//     providers refuse a list on save);
//   - its authorize AND token URLs name one Entra directory, not common /
//     organizations / consumers / the personal-account directory (refused on
//     save, re-checked at sign-in);
//   - the email's domain is EXACTLY an entry: ASCII, case-insensitive, no
//     subdomains, no lookalikes;
//   - the IdP did not send email_verified at all (an explicit false wins).
//
// An empty list is today's behaviour. The provider-trust gate (last writer
// must outrank the person signing in) is unchanged and still applies.
//
// Needs TEST_DATABASE_URL (skips otherwise). It borrows the takeover fixture's
// users and audit capture, owns the (microsoft, admin_login) provider slot
// while it runs, and removes that row at cleanup.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lib/pq"
)

// entraTenantSegment is the directory the fake Entra endpoints are pinned to.
const entraTenantSegment = "0b6f3c9e-1d2a-4c5b-9e8f-7a6b5c4d3e2f"

type entraFixture struct {
	*ssoTakeoverFixture
	entra    *httptest.Server
	mu       sync.Mutex
	userinfo string
}

func newEntraFixture(t *testing.T) *entraFixture {
	t.Helper()
	base := newSSOTakeoverFixture(t)
	f := &entraFixture{ssoTakeoverFixture: base}

	// Every provider row this test writes carries client_id entra-staff-app,
	// whatever its type or purpose — including a row a regressed save wrongly
	// accepts. Sweep them before (a previous run that died mid-way) and after,
	// so one failed run cannot poison every later run on the same database.
	sweep := func() {
		_, _ = base.db.Exec(`DELETE FROM platform_sso_providers WHERE client_id = 'entra-staff-app'`)
	}
	sweep()
	t.Cleanup(sweep)

	var existing int
	if err := base.db.QueryRow(`SELECT COUNT(*) FROM platform_sso_providers WHERE provider_type = 'microsoft' AND purpose = 'admin_login'`).Scan(&existing); err != nil {
		t.Fatalf("count providers: %v", err)
	}
	if existing != 0 {
		t.Fatalf("the integration database already has a (microsoft, admin_login) identity provider; this test needs the slot")
	}

	// Entra-shaped endpoints: /<authority>/oauth2/v2.0/{authorize,token} for
	// any authority (so a provider re-pointed at /common/ still gets a token
	// and the refusal is the gate's, not a 404), and a Graph-style userinfo.
	f.entra = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_, _ = w.Write([]byte(`{"access_token":"fake-entra-access-token","token_type":"Bearer"}`))
		case r.URL.Path == "/oidc/userinfo":
			f.mu.Lock()
			body := f.userinfo
			f.mu.Unlock()
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.entra.Close)
	return f
}

func (f *entraFixture) endpoint(authority, leaf string) string {
	return f.entra.URL + "/" + authority + "/oauth2/v2.0/" + leaf
}

// body builds an identity-provider write. domains is raw JSON ("" omits it).
func (f *entraFixture) body(providerType, purpose, authority, domains string) string {
	b := `{"provider_type":"` + providerType + `","purpose":"` + purpose + `","client_id":"entra-staff-app",` +
		`"client_secret":"` + ssoTakeoverClientSecret + `",` +
		`"auth_url":"` + f.endpoint(authority, "authorize") + `","token_url":"` + f.endpoint(authority, "token") + `",` +
		`"userinfo_url":"` + f.entra.URL + `/oidc/userinfo","is_enabled":true`
	if domains != "" {
		b += `,"allowed_email_domains":` + domains
	}
	return b + "}"
}

func (f *entraFixture) providerID() string {
	f.t.Helper()
	var id string
	if err := f.db.QueryRow(`SELECT id FROM platform_sso_providers WHERE provider_type = 'microsoft' AND purpose = 'admin_login'`).Scan(&id); err != nil {
		f.t.Fatalf("providerID: %v", err)
	}
	return id
}

func (f *entraFixture) storedDomains() []string {
	f.t.Helper()
	var d []string
	if err := f.db.QueryRow(`SELECT allowed_email_domains FROM platform_sso_providers WHERE provider_type = 'microsoft' AND purpose = 'admin_login'`).Scan(pq.Array(&d)); err != nil {
		f.t.Fatalf("storedDomains: %v", err)
	}
	return d
}

// callback runs the public Microsoft staff SSO callback with the fake Entra
// userinfo returning userinfo.
func (f *entraFixture) callback(userinfo string) (string, bool) {
	f.t.Helper()
	f.mu.Lock()
	f.userinfo = userinfo
	f.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin-service/admin/sso/microsoft/callback?state=st&code=cd", nil)
	req.AddCookie(&http.Cookie{Name: "admin_sso_state", Value: "st"})
	w := httptest.NewRecorder()
	f.srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		f.t.Fatalf("callback status = %d, want 302; body=%s", w.Code, w.Body.String())
	}
	session := false
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "platform_access_token" && ck.Value != "" {
			session = true
		}
	}
	return w.Header().Get("Location"), session
}

// entraUserinfo is what graph.microsoft.com/oidc/userinfo returns: no
// email_verified claim at all.
func entraUserinfo(email string) string {
	return `{"sub":"AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ","name":"Staff Member","email":"` + email + `"}`
}

// expectRefusal asserts the callback refused with the unverified-email
// redirect, issued no session, and audited reason.
func (f *entraFixture) expectRefusal(t *testing.T, userinfo, reason string) {
	t.Helper()
	f.drainAudits()
	loc, session := f.callback(userinfo)
	if loc != "/login?error=sso_email_unverified" || session {
		t.Fatalf("Location = %q, session = %v; want the unverified-email refusal and no session", loc, session)
	}
	ev := f.waitAudit("auth.sso_login")
	if ev["success"] != false || ev["error_code"] != reason {
		t.Fatalf("refusal audit = %v, want success=false error_code=%s", ev, reason)
	}
}

func TestIntegration_StaffSSOEntraAllowedDomains_RealRouter(t *testing.T) {
	f := newEntraFixture(t)
	domain := "sso-takeover.example.test" // every fixture user's mail domain
	victim := f.email("victim")           // an active super administrator

	// ---- writes: who, what and where a list may be stored ------------------

	t.Run("stock platform_admin cannot set allowed domains", func(t *testing.T) {
		code, body := f.admin(f.platformAdmin, http.MethodPost, "/identity-providers",
			f.body("microsoft", "admin_login", entraTenantSegment, `["`+domain+`"]`))
		ssoTakeoverExpect(t, "platform_admin create", code, body, http.StatusForbidden)
	})

	for name, tc := range map[string]struct{ typ, purpose, authority, domains string }{
		"multi-tenant common endpoint":        {"microsoft", "admin_login", "common", `["` + domain + `"]`},
		"multi-tenant organizations endpoint": {"microsoft", "admin_login", "organizations", `["` + domain + `"]`},
		"personal-account directory endpoint": {"microsoft", "admin_login", "9188040d-6c67-4c5b-b112-36a304b66dad", `["` + domain + `"]`},
		"a Google provider":                   {"google", "admin_login", entraTenantSegment, `["` + domain + `"]`},
		"a sign-up provider":                  {"microsoft", "signup", entraTenantSegment, `["` + domain + `"]`},
		"a wildcard entry":                    {"microsoft", "admin_login", entraTenantSegment, `["*.example.test"]`},
		"an email address entry":              {"microsoft", "admin_login", entraTenantSegment, `["a@` + domain + `"]`},
		"a trailing-dot entry":                {"microsoft", "admin_login", entraTenantSegment, `["` + domain + `."]`},
		"a non-ASCII lookalike entry":         {"microsoft", "admin_login", entraTenantSegment, `["sso-t\u0430keover.example.test"]`},
	} {
		t.Run("a list is refused on save for "+name, func(t *testing.T) {
			// A wrongly accepted row fails THIS subtest only, not every later one.
			t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM platform_sso_providers WHERE client_id = 'entra-staff-app'`) })
			code, body := f.admin(f.superA, http.MethodPost, "/identity-providers", f.body(tc.typ, tc.purpose, tc.authority, tc.domains))
			ssoTakeoverExpect(t, "create", code, body, http.StatusBadRequest)
			var n int
			_ = f.db.QueryRow(`SELECT COUNT(*) FROM platform_sso_providers WHERE client_id = 'entra-staff-app'`).Scan(&n)
			if n != 0 {
				t.Fatalf("a refused create wrote %d provider rows", n)
			}
		})
	}

	t.Run("super_admin creates a single-directory Entra provider with a list, and it is normalised and audited", func(t *testing.T) {
		f.drainAudits()
		code, body := f.admin(f.superA, http.MethodPost, "/identity-providers",
			f.body("microsoft", "admin_login", entraTenantSegment, `[" SSO-Takeover.Example.TEST ","`+domain+`"]`))
		ssoTakeoverExpect(t, "create", code, body, http.StatusCreated)
		if got := f.storedDomains(); len(got) != 1 || got[0] != domain {
			t.Fatalf("stored allowed_email_domains = %v, want [%s] (trimmed, lower-cased, de-duplicated)", got, domain)
		}
		ev := f.waitAudit("platform_identity_provider.created")
		raw, _ := json.Marshal(ev)
		if nv, _ := ev["new_values"].(map[string]interface{}); nv == nil || !strings.Contains(string(raw), domain) {
			t.Fatalf("create audit should record the allowed domains: %s", raw)
		}
		code, body = f.admin(f.platformAdmin, http.MethodGet, "/identity-providers", "")
		ssoTakeoverExpect(t, "list", code, body, http.StatusOK)
		if !strings.Contains(body, `"allowed_email_domains":["`+domain+`"]`) {
			t.Fatalf("list should return the stored domains: %s", body)
		}
	})

	// ---- sign-in -------------------------------------------------------------

	t.Run("Entra userinfo without email_verified signs in an allow-listed staff member", func(t *testing.T) {
		f.drainAudits()
		loc, session := f.callback(entraUserinfo(strings.ToUpper(victim[:1]) + victim[1:]))
		if loc != "/" || !session {
			t.Fatalf("Location = %q, session = %v; want a session", loc, session)
		}
		ev := f.waitAudit("auth.sso_login")
		meta, _ := ev["metadata"].(map[string]interface{})
		if ev["success"] != true || ev["user_id"] != f.superVictim.String() || meta["email_verified_by"] != "allowed_domain" {
			t.Fatalf("sign-in audit = %v, want success for the victim with email_verified_by=allowed_domain", ev)
		}
	})

	t.Run("an explicit email_verified=false is believed over the list", func(t *testing.T) {
		f.expectRefusal(t, `{"sub":"x","email":"`+victim+`","email_verified":false}`, "email_not_verified")
	})

	t.Run("an explicit email_verified=true still signs in", func(t *testing.T) {
		if loc, session := f.callback(`{"sub":"x","email":"` + victim + `","email_verified":true}`); loc != "/" || !session {
			t.Fatalf("Location = %q, session = %v; want a session", loc, session)
		}
	})

	local := strings.SplitN(victim, "@", 2)[0]
	for name, email := range map[string]string{
		"a different domain":                         local + "@other.example.test",
		"a lookalike suffix":                         local + "@" + domain + ".evil.test",
		"a lookalike prefix":                         local + "@evil" + domain,
		"a subdomain":                                local + "@mail." + domain,
		"a trailing dot":                             local + "@" + domain + ".",
		"a Kelvin sign that lower-cases to k":        local + "@sso-ta\u212Aeover.example.test",
		"a Cyrillic lookalike":                       local + "@sso-t\u0430keover.example.test",
		"a second @ smuggling the allowed domain in": local + "@evil.test@" + domain,
	} {
		t.Run("Entra userinfo is refused for "+name, func(t *testing.T) {
			f.expectRefusal(t, entraUserinfo(email), "email_domain_not_allowed")
		})
	}

	t.Run("a verified non-ASCII lookalike of a staff address matches no account", func(t *testing.T) {
		// strings.ToLower folds U+212A KELVIN SIGN onto "k", which used to map
		// this address onto the victim's. The IdP vouching for the lookalike
		// mailbox must not make it the victim's.
		lookalike := local + "@sso-ta\u212Aeover.example.test"
		loc, session := f.callback(`{"sub":"x","email":"` + lookalike + `","email_verified":true}`)
		if loc != "/login?error=no_admin_account" || session {
			t.Fatalf("Location = %q, session = %v; want no_admin_account and no session", loc, session)
		}
	})

	t.Run("re-pointing the provider at a multi-tenant endpoint while it has a list is refused", func(t *testing.T) {
		code, body := f.admin(f.superA, http.MethodPut, "/identity-providers/"+f.providerID(),
			`{"auth_url":"`+f.endpoint("common", "authorize")+`","token_url":"`+f.endpoint("common", "token")+`","userinfo_url":"`+f.entra.URL+`/oidc/userinfo","is_enabled":true}`)
		ssoTakeoverExpect(t, "re-point", code, body, http.StatusBadRequest)
	})

	t.Run("a row re-pointed at a multi-tenant endpoint behind the API does not relax the gate", func(t *testing.T) {
		if _, err := f.db.Exec(`UPDATE platform_sso_providers SET token_url = $1 WHERE provider_type = 'microsoft' AND purpose = 'admin_login'`,
			f.endpoint("common", "token")); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = f.db.Exec(`UPDATE platform_sso_providers SET token_url = $1 WHERE provider_type = 'microsoft' AND purpose = 'admin_login'`,
				f.endpoint(entraTenantSegment, "token"))
		}()
		f.expectRefusal(t, entraUserinfo(victim), "allowed_domains_multi_tenant_authority")
	})

	t.Run("the provider-trust gate still applies to a domain-verified sign-in", func(t *testing.T) {
		// A security manager (not a super administrator) saves the provider:
		// the domain rule verifies the address, but the super administrator is
		// still refused by gate 2.
		code, body := f.admin(f.secMgr, http.MethodPut, "/identity-providers/"+f.providerID(),
			`{"userinfo_url":"`+f.entra.URL+`/oidc/userinfo","is_enabled":true}`)
		ssoTakeoverExpect(t, "security manager re-save", code, body, http.StatusOK)
		if got := f.storedDomains(); len(got) != 1 || got[0] != domain {
			t.Fatalf("an update that omits allowed_email_domains must keep them; got %v", got)
		}
		loc, session := f.callback(entraUserinfo(victim))
		if loc != "/login?error=sso_super_admin_untrusted_provider" || session {
			t.Fatalf("Location = %q, session = %v; want the super-admin refusal", loc, session)
		}
	})

	t.Run("clearing the list restores today's behaviour and is audited", func(t *testing.T) {
		f.drainAudits()
		code, body := f.admin(f.superA, http.MethodPut, "/identity-providers/"+f.providerID(),
			`{"userinfo_url":"`+f.entra.URL+`/oidc/userinfo","is_enabled":true,"allowed_email_domains":[]}`)
		ssoTakeoverExpect(t, "clear", code, body, http.StatusOK)
		if got := f.storedDomains(); len(got) != 0 {
			t.Fatalf("allowed_email_domains = %v, want []", got)
		}
		ev := f.waitAudit("platform_identity_provider.updated")
		fields, _ := ev["changed_fields"].([]interface{})
		found := false
		for _, fl := range fields {
			if fl == "allowed_email_domains" {
				found = true
			}
		}
		if !found {
			t.Fatalf("update audit changed_fields = %v, want allowed_email_domains named", ev["changed_fields"])
		}
		f.expectRefusal(t, entraUserinfo(victim), "email_not_verified")
	})
}
