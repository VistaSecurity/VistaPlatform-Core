package tools

import (
	"context"
	"net/http"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

type complianceSummaryInput struct {
	FrameworkID string `json:"framework_id" jsonschema:"UUID of the platform framework to evaluate (from vistaplatform_list_compliance_frameworks)"`
	Environment string `json:"environment,omitempty" jsonschema:"Restrict evaluation to one environment, e.g. production"`
	Severity    string `json:"severity,omitempty" jsonschema:"Restrict to one severity: CRITICAL, HIGH, MEDIUM or LOW"`
}

type controlFindingsInput struct {
	ControlID   string `json:"control_id" jsonschema:"UUID of the control (from vistaplatform_get_compliance_summary controls list)"`
	FrameworkID string `json:"framework_id" jsonschema:"UUID of the framework the control belongs to"`
	Page        int    `json:"page,omitempty" jsonschema:"Page number, starting at 1"`
	PageSize    int    `json:"page_size,omitempty" jsonschema:"Results per page, 1-100 (default 25)"`
}

func registerComplianceTools(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_compliance_frameworks",
		Description: "List compliance frameworks visible to the tenant: published frameworks with subscription/licensing state, " +
			"plus per-framework evaluation status and scores for the frameworks the tenant is licensed for. " +
			"Note: full control detail and evaluation require an active subscription to the framework.",
		Annotations: readOnly("List compliance frameworks"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "compliance.read", in, func() (any, error) {
			frameworks, err := d.Client.Get(ctx, d.Client.ComplianceURL, "/api/v1/compliance-engine/frameworks", nil)
			if err != nil {
				return nil, err
			}
			status, err := d.Client.Get(ctx, d.Client.ComplianceURL, "/api/v1/compliance-engine/frameworks/status", nil)
			if err != nil {
				return nil, err
			}
			return map[string]any{"frameworks": frameworks, "evaluation_status": status}, nil
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_compliance_summary",
		Description: "Evaluate one licensed framework against the tenant's inventory: overall score, failing-control count, affected assets, " +
			"per-family pass/warn/fail rollup and the per-control status list. Use vistaplatform_get_control_findings to drill into a failing control. " +
			"A framework that is published but not activated for the tenant answers {\"available\": false, \"reason\": \"framework_not_activated\"} instead of a summary.",
		Annotations: readOnly("Get compliance summary"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in complianceSummaryInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "compliance.read", in, func() (any, error) {
			id, err := requireUUID("framework_id", in.FrameworkID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			q.Set("framework_id", id)
			set(q, "environment", in.Environment)
			set(q, "severity", in.Severity)
			v, err := d.Client.Get(ctx, d.Client.ComplianceURL, "/api/v1/compliance-engine/summary", q)
			if err == nil {
				return v, nil
			}
			// A published framework this tenant has not activated is a fact to
			// report, not a server fault. The platform identifies it with a
			// machine-readable `reason` (a 403 has other meanings — a role
			// without the permission, a scope-narrowed token — and those must
			// stay real errors), so match it positively.
			if status, message, ok := platform.HTTPStatus(err); ok &&
				status == http.StatusForbidden && platform.Reason(err) == sharedapi.ReasonFrameworkNotActivated {
				return unavailableInstead(sharedapi.ReasonFrameworkNotActivated,
					"framework not activated: "+message,
					"vistaplatform_list_compliance_frameworks shows which frameworks this organization has activated "+
						"(subscription state); a tenant administrator activates a framework in the Vista Platform UI under "+
						"Risk & Compliance. Summarise one of the already-active frameworks in the meantime."), nil
			}
			return nil, err
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_control_findings",
		Description: "Drill into one compliance control: its description, rationale, evidence summary by severity, the paginated findings " +
			"(each tied to a concrete subject) and any active overrides. " +
			"On an embedded asset, `asset_type` is the asset's CLASS KEY from the class tree (e.g. `server`, " +
			"`network_device.switch`) — resolve it with vistaplatform_list_asset_classes, and use " +
			"vistaplatform_get_asset for its identifiers and endpoints. " +
			"The finding's own `subject_type` is a different field: it says which KIND of object the measurement " +
			"was taken on (asset or certificate), and `subject_id` is that object's id. A cryptographic-configuration " +
			"measurement is taken per ASSET; the configurations it was read from are listed in " +
			"`evidence.crypto_implementation_ids`, so follow those to reach them rather than reading `subject_id` as one. " +
			"`producer` says which producer judged it; compliance findings also carry `control_id`. " +
			"A control with no findings is not automatically a pass — check its status, because a control nothing " +
			"was measured for is NOT ASSESSED.",
		Annotations: readOnly("Get control findings"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in controlFindingsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "compliance.read", in, func() (any, error) {
			controlID, err := requireUUID("control_id", in.ControlID)
			if err != nil {
				return nil, err
			}
			frameworkID, err := requireUUID("framework_id", in.FrameworkID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			q.Set("framework_id", frameworkID)
			page, size := clampPage(in.Page, in.PageSize)
			q.Set("page", page)
			q.Set("page_size", size)
			return d.Client.Get(ctx, d.Client.ComplianceURL, "/api/v1/compliance-engine/controls/"+controlID, q)
		})
	})
}
