package tools

import (
	"context"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listArtifactsInput struct {
	ScopeID string `json:"scope_id,omitempty" jsonschema:"Only artifacts generated from this scope UUID"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum artifacts to return, 1-100 (default 25)"`
}

type getArtifactInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the CBOM artifact"`
}

type compareArtifactsInput struct {
	BaseID string `json:"base_id" jsonschema:"UUID of the older (baseline) CBOM artifact"`
	HeadID string `json:"head_id" jsonschema:"UUID of the newer CBOM artifact to compare against the baseline"`
}

func registerCBOMTools(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "vistaplatform_list_cbom_scopes",
		Description: "List the tenant's CBOM scopes — named, versioned asset-boundary predicates (e.g. All, Production) that define what a CBOM artifact includes.",
		Annotations: readOnly("List CBOM scopes"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "reports.read", in, func() (any, error) {
			return d.Client.Get(ctx, d.Client.CBOMURL, "/api/v1/cbom-service/scopes", nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_cbom_artifacts",
		Description: "List the tenant's CBOM artifacts — immutable, content-hashed CycloneDX snapshots of the cryptographic inventory, newest first. " +
			"Each entry includes the scope it was generated from, its content hash, component count and signing status.",
		Annotations: readOnly("List CBOM artifacts"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listArtifactsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "reports.read", in, func() (any, error) {
			q := url.Values{}
			if in.ScopeID != "" {
				id, err := requireUUID("scope_id", in.ScopeID)
				if err != nil {
					return nil, err
				}
				q.Set("scope_id", id)
			}
			limit := in.Limit
			switch {
			case limit < 1:
				limit = 25
			case limit > 100:
				limit = 100
			}
			q.Set("limit", strconv.Itoa(limit))
			return d.Client.Get(ctx, d.Client.CBOMURL, "/api/v1/cbom-service/cbom/artifacts", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_cbom_artifact",
		Description: "Fetch one CBOM artifact's metadata by UUID: scope snapshot, content hash, size, component count, data freshness and signature info. " +
			"(Metadata only — download the CycloneDX document itself from the VistaPlatform UI.)",
		Annotations: readOnly("Get CBOM artifact"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getArtifactInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "reports.read", in, func() (any, error) {
			id, err := requireUUID("artifact_id", in.ArtifactID)
			if err != nil {
				return nil, err
			}
			return d.Client.Get(ctx, d.Client.CBOMURL, "/api/v1/cbom-service/cbom/artifacts/"+id, nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_compare_cbom_artifacts",
		Description: "Diff two CBOM artifacts of the same tenant. Components are matched by purl/OID/fingerprint and every change is categorized as " +
			"improvement, regression, drift or neutral with a one-phrase reason — ideal for answering \"did our crypto posture regress since the last snapshot?\".",
		Annotations: readOnly("Compare CBOM artifacts"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in compareArtifactsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "reports.read", in, func() (any, error) {
			baseID, err := requireUUID("base_id", in.BaseID)
			if err != nil {
				return nil, err
			}
			headID, err := requireUUID("head_id", in.HeadID)
			if err != nil {
				return nil, err
			}
			return d.Client.Get(ctx, d.Client.CBOMURL, "/api/v1/cbom-service/cbom/compare/"+baseID+"/"+headID, nil)
		})
	})
}
