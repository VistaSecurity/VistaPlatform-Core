package tools

import (
	"context"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
			"per-family pass/warn/fail rollup and the per-control status list. Use vistaplatform_get_control_findings to drill into a failing control.",
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
			return d.Client.Get(ctx, d.Client.ComplianceURL, "/api/v1/compliance-engine/summary", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_control_findings",
		Description: "Drill into one compliance control: its description, rationale, evidence summary by severity, the paginated findings " +
			"(each tied to a concrete asset) and any active overrides.",
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
