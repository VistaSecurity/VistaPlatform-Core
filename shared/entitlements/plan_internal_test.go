package entitlements

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The plan block's decision table (spec §3 "Resolved plan"), DB-free.
//
// Mutations this table was run against (each turns a case red):
//   - PlanFor returns the tier display_name on Enterprise       → "enterprise" cases
//   - drop the `facts.TierIsTrial &&` condition                  → "msp, plan is not a trial"
//   - drop `omitempty` from Plan.Trial                           → TestPlan_EnterpriseJSONNeverSaysTrial
//   - EffectiveEdition ignores expiry (returns l.Edition)        → "expired enterprise"
func TestPlanFor(t *testing.T) {
	now := time.Now()
	ends := now.Add(10 * 24 * time.Hour)
	onCommunityTrial := TenantPlanFacts{TierDisplayName: "Community", TierIsTrial: true, TrialEndsAt: &ends}
	onPremium := TenantPlanFacts{TierDisplayName: "Premium", TrialEndsAt: &ends}

	ent := &License{Edition: EditionEnterprise, ExpiresAt: now.Add(48 * time.Hour), Licensee: "Acme Corp"}
	msp := &License{Edition: EditionMSP, ExpiresAt: now.Add(48 * time.Hour), Licensee: "Acme MSP"}
	expired := &License{Edition: EditionEnterprise, ExpiresAt: now.Add(-time.Minute), Licensee: "Acme Corp"}

	cases := []struct {
		name      string
		lic       *License
		facts     TenantPlanFacts
		edition   Edition
		display   string
		licensee  string // "" = nil
		trial     bool
		hideTiers bool
	}{
		{"no licence", nil, onCommunityTrial, EditionCore, PlanDisplayNameCore, "", false, false},
		{"expired enterprise", expired, onCommunityTrial, EditionCore, PlanDisplayNameCore, "", false, false},
		{"enterprise, tenant on a trial tier", ent, onCommunityTrial, EditionEnterprise, PlanDisplayNameEnterprise, "Acme Corp", false, true},
		{"enterprise, tenant on a paid tier", ent, onPremium, EditionEnterprise, PlanDisplayNameEnterprise, "Acme Corp", false, true},
		{"msp, trial plan with an end date", msp, onCommunityTrial, EditionMSP, "Community", "Acme MSP", true, false},
		{"msp, plan is not a trial", msp, onPremium, EditionMSP, "Premium", "Acme MSP", false, false},
		{"msp, trial plan without an end date", msp, TenantPlanFacts{TierDisplayName: "Try", TierIsTrial: true}, EditionMSP, "Try", "Acme MSP", false, false},
		{"msp, no tier", msp, TenantPlanFacts{}, EditionMSP, PlanDisplayNameUnassigned, "Acme MSP", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := PlanFor(tc.lic, now, tc.facts)
			if p.Edition != tc.edition || p.DisplayName != tc.display {
				t.Fatalf("plan = %+v, want edition %s display %q", p, tc.edition, tc.display)
			}
			gotLicensee := ""
			if p.Licensee != nil {
				gotLicensee = *p.Licensee
			}
			if gotLicensee != tc.licensee {
				t.Errorf("licensee = %q, want %q", gotLicensee, tc.licensee)
			}
			if (p.Trial != nil) != tc.trial {
				t.Errorf("trial = %+v, want present=%v", p.Trial, tc.trial)
			}
			if p.HidesTierDetail() != tc.hideTiers {
				t.Errorf("HidesTierDetail = %v, want %v", p.HidesTierDetail(), tc.hideTiers)
			}
			if tc.edition == EditionCore && p.ExpiresAt != nil {
				t.Errorf("Core plan carries an expiry %v", p.ExpiresAt)
			}
			if tc.edition != EditionCore && (p.ExpiresAt == nil || !p.ExpiresAt.Equal(tc.lic.ExpiresAt)) {
				t.Errorf("expires_at = %v, want the licence expiry %v", p.ExpiresAt, tc.lic.ExpiresAt)
			}
		})
	}
}

// The copy guard's unit half: an Enterprise plan serialises without the word
// "trial" (or "community") anywhere, key names included, whatever tier the
// tenant row points at.
func TestPlan_EnterpriseJSONNeverSaysTrial(t *testing.T) {
	now := time.Now()
	ends := now.Add(time.Hour)
	p := PlanFor(&License{Edition: EditionEnterprise, ExpiresAt: now.Add(time.Hour), Licensee: "Acme"}, now,
		TenantPlanFacts{TierDisplayName: "community", TierIsTrial: true, TrialEndsAt: &ends})
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{"trial", "community"} {
		if strings.Contains(strings.ToLower(string(raw)), word) {
			t.Errorf("Enterprise plan JSON contains %q: %s", word, raw)
		}
	}
	// Positive control: the MSP trial plan does say it.
	m := PlanFor(&License{Edition: EditionMSP, ExpiresAt: now.Add(time.Hour)}, now,
		TenantPlanFacts{TierDisplayName: "Starter", TierIsTrial: true, TrialEndsAt: &ends})
	raw, _ = json.Marshal(m)
	if !strings.Contains(string(raw), `"trial":{"ends_at"`) {
		t.Errorf("MSP trial plan JSON lacks the trial block: %s", raw)
	}
}

// The retention step of the licence: on Enterprise retention_days resolves to
// the platform cap (unlimited when unset); an explicit per-tenant override
// still wins; MSP and Core keep their own rows.
//
// Mutation: drop the `key == RetentionItemKey` branch in applyLicense → the
// "enterprise, capped" case reads unlimited.
func TestApplyLicense_RetentionFollowsThePlatformCap(t *testing.T) {
	now := time.Now()
	capDays := 400
	tierRetention := func() *EffectiveEntitlement {
		return ent(RetentionItemKey, KindNumericCap, `{"quantity": 365}`, SourceTier, nil)
	}
	cases := []struct {
		name   string
		lic    *License
		in     *EffectiveEntitlement
		want   *int // nil = unlimited
		source Source
	}{
		{"enterprise, no cap", &License{Edition: EditionEnterprise, ExpiresAt: now.Add(time.Hour)}, tierRetention(), nil, SourceEdition},
		{"enterprise, capped", &License{Edition: EditionEnterprise, ExpiresAt: now.Add(time.Hour), RetentionMaxDays: &capDays}, tierRetention(), &capDays, SourceEdition},
		{"enterprise, per-tenant override", &License{Edition: EditionEnterprise, ExpiresAt: now.Add(time.Hour), RetentionMaxDays: &capDays},
			ent(RetentionItemKey, KindNumericCap, `{"quantity": 30}`, SourceOverride, nil), intp(30), SourceOverride},
		{"msp keeps the plan value", &License{Edition: EditionMSP, ExpiresAt: now.Add(time.Hour), RetentionMaxDays: &capDays}, tierRetention(), intp(365), SourceTier},
		{"core keeps the tier value", nil, tierRetention(), intp(365), SourceTier},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applyLicense(tc.in, tc.lic, now)
			qty, ok := tc.in.QuantityValue()
			if !ok {
				t.Fatalf("malformed value %s", tc.in.Value)
			}
			if (qty == nil) != (tc.want == nil) || (qty != nil && *qty != *tc.want) {
				t.Fatalf("retention = %v (%s), want %v", qty, tc.in.Value, tc.want)
			}
			if tc.in.Source != tc.source {
				t.Errorf("source = %s, want %s", tc.in.Source, tc.source)
			}
		})
	}
}

func intp(v int) *int { return &v }

func TestRetentionSettingParsing(t *testing.T) {
	good := map[string]*int{`null`: nil, `1`: intp(1), `730`: intp(730), `36500`: intp(36500)}
	for raw, want := range good {
		got, err := ParseRetentionSetting([]byte(raw))
		if err != nil {
			t.Errorf("parse %s: %v", raw, err)
			continue
		}
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("parse %s = %v, want %v", raw, got, want)
		}
		if string(EncodeRetentionSetting(got)) != raw {
			t.Errorf("encode(parse(%s)) = %s", raw, EncodeRetentionSetting(got))
		}
	}
	for _, raw := range []string{`0`, `-5`, `36501`, `12.5`, `"730"`, `{"days":730}`, `true`, ``} {
		if got, err := ParseRetentionSetting([]byte(raw)); err == nil {
			t.Errorf("parse %q = %v, want an error", raw, got)
		}
	}
}
