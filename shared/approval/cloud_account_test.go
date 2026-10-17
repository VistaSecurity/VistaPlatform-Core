package approval

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// cloudObservation is what the cloud intake projects a resource onto: the
// `cloud` source (from the envelope) and the account the provider placed it in.
func cloudObservation(account string) Discovery {
	return Discovery{
		TenantID:       uuid.New(),
		Metadata:       []byte(`{"source":"cloud_discovery","discovery_method":"cloud_api"}`),
		CloudAccountID: account,
	}
}

// TestApprovalRules_NoCloudPrefixSource pins the retirement of the prefix
// editor's "Cloud discoveries" source (ADR-0009 D5). It was inert — the cloud
// intake never called this package — so a prefix rule naming the cloud
// source is now refused at write time AND at evaluation time, and the prefix
// generator cannot produce one.
func TestApprovalRules_NoCloudPrefixSource(t *testing.T) {
	prefixID := uuid.New().String()
	for _, q := range []string{
		"source:cloud and network.ownership:internal and network.prefix_id=" + prefixID,
		"source in (sensor, cloud) and network.prefix_id=" + prefixID,
		"network.prefix_id=" + prefixID + " and not (source != cloud)",
	} {
		if _, err := ValidateRuleQuery(q); !errors.Is(err, ErrCloudSourceOnPrefixRule) {
			t.Errorf("ValidateRuleQuery(%q) = %v; want ErrCloudSourceOnPrefixRule", q, err)
		}
		r := ruleWithQuery(q, true)
		seg := uuid.MustParse(prefixID)
		matched, err := NewRuleEvaluator().EvaluateRule(r, cloudObservation("1"), onPrefix(seg))
		if matched || !errors.Is(err, ErrCloudSourceOnPrefixRule) {
			t.Errorf("EvaluateRule(%q) = %v, %v; want no match and ErrCloudSourceOnPrefixRule", q, matched, err)
		}
	}

	// The other polarity: what is still legal.
	for _, q := range []string{
		"source:sensor and network.prefix_id=" + prefixID, // a prefix rule about the sensor
		"not source:cloud and network.prefix_id=" + prefixID,
		CloudAccountApprovalQuery("123456789012"), // an account rule names cloud and no prefix
	} {
		if _, err := ValidateRuleQuery(q); err != nil {
			t.Errorf("ValidateRuleQuery(%q) refused a legal rule: %v", q, err)
		}
	}
}

// TestCloudAccountRule pins the account rule end to end through the one
// evaluator, both polarities.
func TestCloudAccountRule(t *testing.T) {
	svc := NewService(nil)
	rule := ruleWithQuery(CloudAccountApprovalQuery("123456789012"), true)
	// A cloud observation carries no prefix classification that matters.
	cls := &Classification{Ownership: "internal", Type: "cloud"}

	ok, id, err := svc.EvaluateAutoApprovalWithRules([]*Rule{rule}, cloudObservation("123456789012"), cls)
	if err != nil || !ok || id == nil || *id != rule.ID {
		t.Fatalf("a resource in the account must be approved by the account rule: ok=%v id=%v err=%v", ok, id, err)
	}
	for name, d := range map[string]Discovery{
		"another account":        cloudObservation("999999999999"),
		"no account (absent)":    cloudObservation(""),
		"a sensor in no account": Discovery{TenantID: uuid.New()}.WithConfidence(1),
	} {
		ok, _, err := svc.EvaluateAutoApprovalWithRules([]*Rule{rule}, d, cls)
		if err != nil || ok {
			t.Errorf("%s: approved=%v err=%v; the account rule must not reach it", name, ok, err)
		}
	}
	// A sensor observation that somehow states the account is still not
	// `source:cloud`.
	sensorInAccount := Discovery{TenantID: uuid.New(), CloudAccountID: "123456789012"}
	if ok, _, _ := svc.EvaluateAutoApprovalWithRules([]*Rule{rule}, sensorInAccount, cls); ok {
		t.Error("the account rule approved a sensor observation")
	}
}

func TestCloudAccountIDFromQuery(t *testing.T) {
	for q, want := range map[string]string{
		CloudAccountApprovalQuery("123456789012"):                                "123456789012",
		`source:cloud and cloud.account_id = "my-project-1"`:                     "my-project-1",
		`cloud.account_id:3b0a1c2d-0000-4000-8000-000000000001 and source:cloud`: "3b0a1c2d-0000-4000-8000-000000000001",
	} {
		got, ok := CloudAccountIDFromQuery(q)
		if !ok || got != want {
			t.Errorf("CloudAccountIDFromQuery(%q) = %q, %v; want %q", q, got, ok, want)
		}
	}
	for _, q := range []string{"", "source:cloud", "network.prefix_id=" + uuid.NewString()} {
		if got, ok := CloudAccountIDFromQuery(q); ok {
			t.Errorf("CloudAccountIDFromQuery(%q) = %q; want none", q, got)
		}
	}
}
