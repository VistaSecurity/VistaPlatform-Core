package tools

import (
	"context"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type queryAssetsInput struct {
	Search                   string   `json:"search,omitempty" jsonschema:"Free-text search across hostname, IP address, FQDN and description"`
	AssetType                []string `json:"asset_type,omitempty" jsonschema:"Filter by asset type, e.g. server, endpoint, network_device, service"`
	Environment              []string `json:"environment,omitempty" jsonschema:"Filter by environment, e.g. production, staging, dev"`
	RiskLevel                []string `json:"risk_level,omitempty" jsonschema:"Filter by risk level: critical, high, medium or low"`
	BusinessUnit             []string `json:"business_unit,omitempty" jsonschema:"Filter by business unit"`
	AssetStatus              []string `json:"asset_status,omitempty" jsonschema:"Filter by lifecycle status, e.g. active, pending, archived"`
	HasCertificates          *bool    `json:"has_certificates,omitempty" jsonschema:"Only assets with (true) or without (false) TLS certificates"`
	CertExpiringWithinDays   int      `json:"cert_expiring_within_days,omitempty" jsonschema:"Only assets with a certificate expiring within this many days"`
	UsesDeprecatedAlgorithms *bool    `json:"uses_deprecated_algorithms,omitempty" jsonschema:"Only assets using deprecated cryptographic algorithms"`
	Page                     int      `json:"page,omitempty" jsonschema:"Page number, starting at 1"`
	PageSize                 int      `json:"page_size,omitempty" jsonschema:"Results per page, 1-100 (default 25)"`
	SortBy                   string   `json:"sort_by,omitempty" jsonschema:"Sort column, e.g. created_at, hostname, risk_score"`
	SortOrder                string   `json:"sort_order,omitempty" jsonschema:"asc or desc"`
}

type getAssetInput struct {
	AssetID string `json:"asset_id" jsonschema:"UUID of the infrastructure asset"`
}

type queryCertificatesInput struct {
	Search       string `json:"search,omitempty" jsonschema:"Free-text search across subject, issuer and common name"`
	ExpiringDays int    `json:"expiring_days,omitempty" jsonschema:"Only certificates expiring within this many days"`
	Issuer       string `json:"issuer,omitempty" jsonschema:"Substring match on the issuer DN"`
	Algorithm    string `json:"algorithm,omitempty" jsonschema:"Public key algorithm filter, e.g. RSA, ECDSA"`
	KeySizeMin   int    `json:"key_size_min,omitempty" jsonschema:"Minimum public key size in bits"`
	SelfSigned   *bool  `json:"self_signed,omitempty" jsonschema:"Only self-signed (true) or CA-issued (false) certificates"`
	Page         int    `json:"page,omitempty" jsonschema:"Page number, starting at 1"`
	PageSize     int    `json:"page_size,omitempty" jsonschema:"Results per page, 1-100 (default 25)"`
	SortBy       string `json:"sort_by,omitempty" jsonschema:"Sort column, default not_after (expiry)"`
	SortOrder    string `json:"sort_order,omitempty" jsonschema:"asc or desc"`
}

type queryCryptoConfigurationsInput struct {
	Page     int `json:"page,omitempty" jsonschema:"Page number, starting at 1"`
	PageSize int `json:"page_size,omitempty" jsonschema:"Results per page, 1-100 (default 25)"`
}

type queryAlgorithmsInput struct {
	Category          string `json:"category,omitempty" jsonschema:"Algorithm category, e.g. symmetric, asymmetric, hash, kem, signature"`
	Strength          string `json:"strength,omitempty" jsonschema:"Assessment filter: weak, acceptable, strong or recommended"`
	DeprecationStatus string `json:"deprecation_status,omitempty" jsonschema:"Deprecation filter, e.g. active, deprecated, forbidden"`
	PQC               *bool  `json:"pqc,omitempty" jsonschema:"Only post-quantum (true) or classical (false) algorithms"`
}

type emptyInput struct{}

func registerInventoryTools(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_query_assets",
		Description: "Search and filter the tenant's infrastructure asset inventory (servers, endpoints, network devices, services). " +
			"Returns assets with their crypto posture, risk level and discovery metadata, plus pagination info. " +
			"Use filters to narrow by environment, risk, certificate expiry or deprecated-crypto usage.",
		Annotations: readOnly("Query infrastructure assets"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryAssetsInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			q := url.Values{}
			set(q, "search", in.Search)
			setAll(q, "asset_type", in.AssetType)
			setAll(q, "environment", in.Environment)
			setAll(q, "risk_level", in.RiskLevel)
			setAll(q, "business_unit", in.BusinessUnit)
			setAll(q, "asset_status", in.AssetStatus)
			setBool(q, "has_certificates", in.HasCertificates)
			if in.CertExpiringWithinDays > 0 {
				q.Set("cert_expiring_within", strconv.Itoa(in.CertExpiringWithinDays))
			}
			setBool(q, "uses_deprecated_algorithms", in.UsesDeprecatedAlgorithms)
			page, size := clampPage(in.Page, in.PageSize)
			q.Set("page", page)
			q.Set("page_size", size)
			set(q, "sort_by", in.SortBy)
			set(q, "sort_order", in.SortOrder)
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v2/inventory-service/infrastructure-assets", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "vistaplatform_get_asset",
		Description: "Fetch one infrastructure asset by UUID with full detail, including its crypto configurations and linked certificates.",
		Annotations: readOnly("Get asset detail"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getAssetInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v2/inventory-service/infrastructure-assets/"+id, nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_query_certificates",
		Description: "Search the tenant's X.509 certificate inventory. Filter by expiry window, issuer, key algorithm/size or self-signed status. " +
			"PEM bodies are omitted; fingerprints, subjects, validity windows and key parameters are included.",
		Annotations: readOnly("Query certificates"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryCertificatesInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			q := url.Values{}
			set(q, "search", in.Search)
			if in.ExpiringDays > 0 {
				q.Set("expiring_days", strconv.Itoa(in.ExpiringDays))
			}
			set(q, "issuer", in.Issuer)
			set(q, "algorithm", in.Algorithm)
			if in.KeySizeMin > 0 {
				q.Set("key_size_min", strconv.Itoa(in.KeySizeMin))
			}
			setBool(q, "self_signed", in.SelfSigned)
			page, size := clampPage(in.Page, in.PageSize)
			q.Set("page", page)
			q.Set("page_size", size)
			set(q, "sort_by", in.SortBy)
			set(q, "sort_order", in.SortOrder)
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v2/inventory-service/certificates", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "vistaplatform_query_crypto_configurations",
		Description: "List the tenant's discovered cryptographic configurations (protocol, version, cipher suite, key exchange, signature and hash algorithms per asset). Paginated.",
		Annotations: readOnly("Query crypto configurations"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryCryptoConfigurationsInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			q := url.Values{}
			page, size := clampPage(in.Page, in.PageSize)
			q.Set("page", page)
			q.Set("page_size", size)
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v2/inventory-service/crypto-configurations", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_query_algorithms",
		Description: "Look up the platform's authoritative cryptographic algorithm assessments: strength, deprecation status, post-quantum classification, " +
			"risk score, migration guidance and recommended alternatives. This catalog is the source of truth for whether an algorithm is considered weak or quantum-vulnerable.",
		Annotations: readOnly("Query algorithm assessments"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryAlgorithmsInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			q := url.Values{}
			set(q, "category", in.Category)
			set(q, "strength", in.Strength)
			set(q, "deprecation_status", in.DeprecationStatus)
			setBool(q, "pqc", in.PQC)
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v2/inventory-service/algorithms", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_pqc_readiness",
		Description: "Get the tenant's post-quantum readiness: totals of PQC-ready, quantum-safe-symmetric and needs-migration crypto implementations, " +
			"broken down by algorithm family with suggested migration targets.",
		Annotations: readOnly("Get PQC readiness"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v1/inventory-service/pqc/progress", nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "vistaplatform_get_risk_summary",
		Description: "Get the tenant's top-line crypto risk posture: asset counts by risk level, total crypto implementations and critical findings.",
		Annotations: readOnly("Get risk summary"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return run(ctx, "assets.read", func() (any, error) {
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v1/inventory-service/risk/summary", nil)
		})
	})
}

func set(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func setAll(q url.Values, k string, vs []string) {
	for _, v := range vs {
		if v != "" {
			q.Add(k, v)
		}
	}
}

func setBool(q url.Values, k string, v *bool) {
	if v != nil {
		q.Set(k, strconv.FormatBool(*v))
	}
}
