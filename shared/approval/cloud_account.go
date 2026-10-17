package approval

// Cloud auto-approval is decided at the ACCOUNT (asset-inventory ADR-0009 D5).
//
// A prefix is the wrong boundary for a cloud resource: most of them
// (buckets, key stores, CDN distributions) have no address to put in a
// prefix, and a VPC is not what a tenant consents to. The account is — the
// tenant handed us credentials for it. So the setting lives on the cloud
// integration (`platform_integrations.auto_approve_resources`), and
// device-interrogation-service derives ONE rule per account from it:
//
//	source:cloud and cloud.account_id="<account>"
//
// That rule is an ordinary row of discovery_auto_approval_rules, evaluated by
// this package exactly like a prefix rule. There is no second evaluator for
// cloud: the cloud intake projects its resource onto the `observation` target
// with the account filled in (Discovery.CloudAccountID) and calls the same
// Service everything else calls.
//
// The other half of the decision is that a PREFIX rule does not cover cloud
// discoveries at all ( decided it for the network segments the prefixes
// replaced, DCIM row 1.6): the generator writes `source:sensor`, validation
// refuses a prefix rule naming the cloud source, and evaluation ignores one
// (prefixRuleIgnoresCloud).

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
)

// SourceCloud is the `source` value a cloud provider's listing carries on the
// observation target.
const SourceCloud = "cloud"

// ErrCloudSourceOnPrefixRule is the refusal for a rule that scopes on a prefix
// AND names the cloud source. Account-level approval is the only way a cloud
// discovery is auto-approved.
var ErrCloudSourceOnPrefixRule = errors.New(
	"a prefix rule cannot auto-approve cloud discoveries; cloud resources are auto-approved per account, on the cloud integration")

// CloudAccountApprovalQuery is the rule a cloud integration's
// auto_approve_resources setting stands for. The account id is quoted so an
// Azure subscription uuid or a GCP project id with dashes stays one literal.
func CloudAccountApprovalQuery(accountID string) string {
	return "source:" + SourceCloud + " and cloud.account_id=" + strconv.Quote(strings.TrimSpace(accountID))
}

// CloudAccountIDFromQuery extracts the `cloud.account_id=<id>` term an
// account-generated rule carries, so device-interrogation-service can find the
// rule it owns for an account. Like PrefixIDFromQuery it reads the AST rather
// than the text, so `cloud.account_id = "1"` and `cloud.account_id:1` are one
// predicate.
func CloudAccountIDFromQuery(src string) (string, bool) {
	if strings.TrimSpace(src) == "" {
		return "", false
	}
	res, err := parser.Parse(src)
	if err != nil {
		return "", false
	}
	var found string
	ast.Walk(res.Root, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		cmp, isCmp := n.(*ast.Compare)
		if !isCmp {
			return true
		}
		if !strings.EqualFold(cmp.Field.Text, "cloud.account_id") {
			return true
		}
		if cmp.Op != ast.OpEq && cmp.Op != ast.OpColon {
			return true
		}
		if v := strings.TrimSpace(cmp.Value.Value); v != "" {
			found = v
			return false
		}
		return true
	})
	return found, found != ""
}

// ruleScope is what a CHECKED rule says about its own scope: whether it is
// scoped to a prefix, and whether it names the cloud source.
type ruleScope struct {
	prefix bool
	cloud  bool
}

// scopeOf reads a validated AST. It looks at the RESOLVED accessor column, so
// the surface spelling of a field does not matter, and it tracks negation: a
// rule saying `not source:cloud` is a rule that EXCLUDES cloud, which is the
// opposite of naming it.
func scopeOf(node ast.Node) ruleScope {
	var sc ruleScope
	var walk func(n ast.Node, negated bool)
	walk = func(n ast.Node, negated bool) {
		switch x := n.(type) {
		case nil:
		case *ast.And:
			for _, c := range x.Children {
				walk(c, negated)
			}
		case *ast.Or:
			for _, c := range x.Children {
				walk(c, negated)
			}
		case *ast.Not:
			walk(x.Child, !negated)
		case *ast.Compare:
			switch x.Field.Accessor.Column {
			case "network_prefix_id":
				sc.prefix = true
			case "source":
				if !strings.EqualFold(strings.TrimSpace(x.Value.Value), SourceCloud) {
					return
				}
				switch x.Op {
				case ast.OpEq, ast.OpColon:
					sc.cloud = sc.cloud || !negated
				case ast.OpNe:
					sc.cloud = sc.cloud || negated // `not (source != cloud)`
				}
			}
		case *ast.InSet:
			if x.Field.Accessor.Column != "source" {
				return
			}
			for _, v := range x.Values {
				if strings.EqualFold(strings.TrimSpace(v.Value), SourceCloud) && x.Negated == negated {
					sc.cloud = true
				}
			}
		case *ast.Exists:
			if x.Field.Accessor.Column == "network_prefix_id" {
				sc.prefix = true
			}
		}
	}
	walk(node, false)
	return sc
}

// checkPrefixCloud refuses a prefix-scoped rule that names the cloud source.
func checkPrefixCloud(node ast.Node) error {
	if sc := scopeOf(node); sc.prefix && sc.cloud {
		return ErrCloudSourceOnPrefixRule
	}
	return nil
}

// prefixRuleIgnoresCloud is the evaluation-time half: a prefix-scoped rule
// never matches a cloud observation, whatever else it says. A rule with no
// source term would otherwise reach cloud resources through the cloud subnet
// prefix their address falls in — the very path D5 retires.
func prefixRuleIgnoresCloud(node ast.Node, source string) bool {
	return source == SourceCloud && scopeOf(node).prefix
}

// wrapRuleErr names the rule in an error, as rule.ast() does for a parse
// failure.
func wrapRuleErr(r *Rule, err error) error {
	return fmt.Errorf("auto-approval rule %s (%q): %w", r.ID, r.Name, err)
}
