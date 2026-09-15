package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// The asset tools speak the query language and nothing else.
//
// The per-field filter arguments (`asset_type`, `environment`, `risk_level`,
// `has_certificates`, `cert_expiring_within_days`, …) are GONE, with no
// deprecation window, per ADR-0007 D2.4. There is no install to carry: the
// arguments were a second, weaker way of saying what `query` says, and two
// filter vocabularies on one tool is how an agent learns the wrong one. The
// tool description below teaches the language instead.
//
// Every asset tool that returns rows also returns the CANONICAL query the
// platform ran (ADR-0008 D4.4), which is not always the string that was sent:
// the platform AND-s in its own default scope. An agent repeating an answer
// shows that string, not its input.

// queryLanguagePrimer is appended to every tool description that takes a
// `query`. One text, so the five examples and the namespace list cannot come to
// disagree between tools.
const queryLanguagePrimer = "" +
	"QUERY LANGUAGE. One line of text; adjacent terms mean AND. " +
	"Operators: `:` loose/case-insensitive (substring on text fields, subtree on `class`), " +
	"`=` exact, `!=`, `<` `<=` `>` `>=`, `in (a, b)`, `~ \"regex\"`, `field:[lo to hi]`, " +
	"`*` wildcard, `exists(field)`, `not`/`-` to negate, parentheses to group. " +
	"Child collections are EXISTS sub-predicates: `endpoint:(…)`, `cert:(…)`, `crypto:(…)`, " +
	"`software:(…)`, `finding:(…)`, `identifier:(…)`. " +
	"Dates: `now`, `now-30d`, `now+7d` (units s m h d w mo y). There is no null literal — use `exists(field)`.\n" +
	"FIELD NAMESPACES: bare names are first-class asset columns (class, display_name, hostname, " +
	"primary_address, environment, business_unit, owner_email, support_group, site, region, zone, " +
	"status, ownership, stale_status, source, risk, risk_score, risk_assessed_by, confidence_score, " +
	"first_seen, last_seen); `attr.` a class attribute (attr.os_version); `fact.` a registered fact key " +
	"(fact.os.name); `id.` an identifier kind (id.serial_number, id.mac, id.any); `tag.` a tenant tag " +
	"(tag.owner). A bare name NEVER resolves to an attribute, fact, identifier or tag — the prefix is required.\n" +
	"EXAMPLES:\n" +
	"  1. environment:production class:hardware.computer.server not exists(owner_email)\n" +
	"     — production servers nobody owns.\n" +
	"  2. cert:(not_after < now+30d)\n" +
	"     — anything with a certificate expiring in the next 30 days.\n" +
	"  3. risk >= high and last_seen > now-7d\n" +
	"     — high or critical risk, seen in the last week.\n" +
	"  4. crypto:(algorithm.deprecated:true) and environment in (production, staging)\n" +
	"     — deprecated algorithms outside dev.\n" +
	"  5. risk:not_assessed and class:hardware\n" +
	"     — hardware NOBODY HAS SCORED. This is not `risk:informational`, which means " +
	"\"we looked and it scored zero\". The two are different sets and neither implies the other.\n" +
	"A query that does not validate is REFUSED, never guessed at: the tool returns the diagnostics " +
	"(code, message, byte span, suggestion) and no rows. Read them, fix the query, call again.\n" +
	"DEFAULT SCOPE: with no `status` term the platform adds `status:monitoring` — approved inventory only. " +
	"It is a default, not a floor: name `status` yourself and it steps aside, so " +
	"`status:pending_approval` reaches the approval queue and `status:archived` reaches assets that were " +
	"archived or merged away. The echoed query is how you tell which happened."

// honestyNote is appended wherever a risk number is returned. Same text
// everywhere, because the distinction is the same everywhere.
const honestyNote = "HONESTY: `risk_score` 0 with an EMPTY `risk_assessed_by` means NOT ASSESSED — nobody looked. " +
	"0 with a non-empty `risk_assessed_by` means assessed and clean. Never report the first as \"no risk\"."

type queryAssetsInput struct {
	Query  string `json:"query,omitempty" jsonschema:"A query-language predicate over assets. Empty means every asset in inventory. See the tool description for the grammar and examples."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque continuation token. Pass back the next_cursor from a previous result of this tool; do not construct one."`
}

type getAssetInput struct {
	AssetID string `json:"asset_id" jsonschema:"UUID of the asset"`
}

type assetHistoryInput struct {
	AssetID string `json:"asset_id" jsonschema:"UUID of the asset"`
}

type assetSoftwareInput struct {
	AssetID string `json:"asset_id" jsonschema:"UUID of the asset"`
	Query   string `json:"query,omitempty" jsonschema:"Case-insensitive substring matched against the product name, vendor, purl and CPE. Empty means every install on the asset."`
	Status  string `json:"status,omitempty" jsonschema:"Filter to one install status: active, stale or removed. Omit for all three."`
	Limit   int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-200 (default 50)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging. The result's total describes the whole match, not the page."`
}

type assetFacetsInput struct {
	Query  string   `json:"query,omitempty" jsonschema:"The same query-language predicate the asset list takes. The counts describe exactly the set that query selects; empty means all of inventory."`
	Facets []string `json:"facets" jsonschema:"Facet names to count, 1-8 of: class, risk, status, environment, ownership, stale_status, site, region, zone, segment, owner_email, business_unit, support_group, operating_system, source, proposed_by, tag, has_findings, has_endpoints"`
	Limit  int      `json:"limit,omitempty" jsonschema:"Maximum buckets per facet, 1-200 (default 50)"`
}

type searchInput struct {
	Text  string `json:"text" jsonschema:"What to look for. Matched case-insensitively as a substring."`
	Limit int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
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

type assetRelationshipsInput struct {
	AssetID   string `json:"asset_id" jsonschema:"UUID of the asset"`
	Direction string `json:"direction,omitempty" jsonschema:"out (this asset is the from end), in (it is the to end), or both (default)"`
	Type      string `json:"type,omitempty" jsonschema:"One relationship type: runs_on, hosted_on, virtualized_by, depends_on, connects_to, member_of, contains, manages, sends_data_to or impacts"`
	Status    string `json:"status,omitempty" jsonschema:"pending, active, rejected or stale. Omit to get everything except rejected."`
	Limit     int    `json:"limit,omitempty" jsonschema:"Edges to return, 1-200 (default 50)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Edges to skip, for paging through total"`
}

type neighbourhoodInput struct {
	AssetID        string `json:"asset_id" jsonschema:"UUID of the asset at the centre"`
	Depth          int    `json:"depth,omitempty" jsonschema:"Hops from the asset, 1-3 (default 2). Larger is refused, not clamped."`
	IncludePending bool   `json:"include_pending,omitempty" jsonschema:"Also draw pending (unapproved) edges and the assets only they reach. Default false."`
}

type impactInput struct {
	AssetID   string `json:"asset_id" jsonschema:"UUID of the asset"`
	Direction string `json:"direction,omitempty" jsonschema:"downstream (default) for what depends on this asset, upstream for what this asset depends on"`
	Depth     int    `json:"depth,omitempty" jsonschema:"Hops to follow, 1-10 (default 6)"`
}

type askInput struct {
	Question string `json:"question" jsonschema:"A question about this tenant's inventory, in plain words. Not a query-language predicate — use vistaplatform_query_assets for one of those."`
}

type emptyInput struct{}

// Base paths on inventory-service. Named once so a tool cannot drift from the
// route the gateway publishes.
const (
	assetsPath       = "/api/v2/inventory-service/infrastructure-assets"
	assetClassesPath = "/api/v2/inventory-service/asset-classes"
	askPath          = "/api/v2/inventory-service/ask"
)

func registerInventoryTools(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_query_assets",
		Description: "Search the tenant's asset inventory with a query-language predicate. " +
			"An asset is any configuration item the platform tracks — servers, network devices, cloud resources, " +
			"applications, endpoints — classified into a hierarchical class tree (see vistaplatform_list_asset_classes). " +
			"Returns a page of assets with their class, primary endpoint, identifiers, risk and counts, " +
			"plus `query`: THE CANONICAL QUERY THAT ACTUALLY RAN. Show that string, not the one you sent — " +
			"the platform AND-s its own default scope in (normally `status:monitoring`, i.e. approved inventory only), " +
			"so the two differ. Use vistaplatform_asset_facets for counts rather than paging through rows.\n" +
			queryLanguagePrimer + "\n" + honestyNote,
		Annotations: readOnly("Query assets"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryAssetsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			page, err := cursorPage(in.Cursor)
			if err != nil {
				return nil, err
			}
			size := clampLimit(in.Limit, 25, 100)
			q := url.Values{}
			set(q, "query", in.Query)
			q.Set("page", strconv.Itoa(page))
			q.Set("page_size", strconv.Itoa(size))
			v, err := d.Client.Get(ctx, d.Client.InventoryURL, assetsPath, q)
			if err != nil {
				return nil, err
			}
			return withNextCursor(v, page), nil
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_asset",
		Description: "Fetch one asset by UUID with full detail: its class and how the class was decided " +
			"(`class_source_kind` measured/declared/imported/inferred, `class_source_ref`, `class_confidence`), " +
			"all of its identifiers (serial number, MAC, cloud resource id, …), all of its endpoints " +
			"(address, port, transport, protocol, service), its class attributes and tags, its risk, " +
			"and its crypto configurations and linked certificates. " +
			"An empty `endpoints` array is a real answer, not a gap — an at-rest cloud resource has no endpoint at all. " +
			"If the result carries `merged_into`, this id is a TOMBSTONE: the asset was merged into the one that field " +
			"names, and it answers 200 with `asset_status: archived` rather than 404 so a stale id still resolves. " +
			"Follow the pointer and report the survivor — never present a tombstone as live inventory.\n" +
			honestyNote,
		Annotations: readOnly("Get asset detail"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getAssetInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/"+id, nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_asset_history",
		Description: "The change history of one asset, newest first: what changed, who or what changed it " +
			"(`source`, `actor_user_id`), and when. Use it to answer \"when did this move / get re-classified / " +
			"change owner?\" and to date a posture change. History records what the platform observed or was told; " +
			"it is not an audit log of user sessions.",
		Annotations: readOnly("Get asset history"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in assetHistoryInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/"+id+"/history", nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_asset_software",
		Description: "The software installed on one asset: product name, vendor, version, purl, CPE, licence, " +
			"where the claim came from (`source_kind` measured/declared/imported/inferred, `source_ref`) and " +
			"when it was first and last seen. Use it to answer \"is <package> on this host?\" and " +
			"\"what version of <library> is this running?\".\n" +
			"AN EMPTY LIST IS NOT \"NO SOFTWARE\". It means nothing has enumerated software on this asset — no " +
			"bill of materials uploaded, no host agent. The `sw.package_count` fact is what distinguishes " +
			"\"we looked and found none\" from \"nobody looked\"; read it with vistaplatform_get_asset before " +
			"reporting an empty list as a clean one.\n" +
			"ROWS WITH `status: removed` ARE INCLUDED by default and are not current. A removed install is one a " +
			"later document did not list; its row is kept so \"this library was here last month\" stays " +
			"answerable. Pass `status: active` for what is present now, and never count removed rows as installed.\n" +
			"`version` is the raw string the source wrote. `version_sort` is the normalised ordering key, and it " +
			"is null when the version has no numeric component — which means a version comparison against that " +
			"product has no answer rather than a false one.",
		Annotations: readOnly("List asset software"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in assetSoftwareInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "q", in.Query)
			set(q, "status", in.Status)
			q.Set("limit", strconv.Itoa(clampLimit(in.Limit, 50, 200)))
			if in.Offset > 0 {
				q.Set("offset", strconv.Itoa(in.Offset))
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/"+id+"/software", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_asset_classes",
		Description: "The asset class taxonomy: every class with its key, parent, full dotted path, human label, " +
			"description, the identifier kinds that establish identity for it, and its attribute schema. " +
			"`is_fixed` distinguishes a platform class from a tenant-defined subclass. " +
			"Read this BEFORE writing a `class:` term — `class:hardware` matches the whole subtree " +
			"(server, switch, everything under it) while `class=server` matches that one class exactly, " +
			"and the attribute schema tells you which `attr.` fields exist for a class.",
		Annotations: readOnly("List asset classes"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			return d.Client.Get(ctx, d.Client.InventoryURL, assetClassesPath, nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_asset_facets",
		Description: "Count assets by one or more facets over the set a query selects — the way to answer " +
			"\"how many, broken down by …?\" without paging through rows. " +
			"Returns, per requested facet, its buckets as {key, count}, plus `query`: the canonical query the counts " +
			"were taken over. The counts and vistaplatform_query_assets run the SAME predicate, so a total here and " +
			"a list there always describe the same set.\n" +
			queryLanguagePrimer + "\n" +
			"NOTE ON `risk`: the risk facet bands the persisted per-asset score. Assets nobody has scored land in the " +
			"not-assessed bucket rather than in the zero bucket — do not add them to \"low risk\".",
		Annotations: readOnly("Count assets by facet"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in assetFacetsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			return d.assetFacets(ctx, in)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_ask",
		Description: "Ask a question about this tenant's inventory in plain words and get back the GROUNDED answer: " +
			"the query-language predicate the platform wrote and ran, the rows it selected, and a summary in which " +
			"every sentence cites a returned row as `[row:<asset id>]`. Sentences that cited nothing, or cited a row " +
			"that was not returned, were dropped before you saw them.\n" +
			"PREFER THIS over composing a predicate yourself when you are not sure of the field names: the platform's " +
			"translator is validated against the live catalogue and a query that does not validate is refused with " +
			"diagnostics rather than guessed at. Use vistaplatform_query_assets directly when you already know the " +
			"predicate you want — it is one call instead of several, and the answer is yours to summarise.\n" +
			"Read the result in order of authority: `query` first (the CANONICAL predicate that ran, including the " +
			"default scope the platform AND-s in — repeat THAT string, not the question), then `rows`, then `text`. " +
			"`provenance.model_id` names what wrote the summary; `source_kind` is always `inferred`.\n" +
			"ENTERPRISE, and provider-dependent. When this deployment cannot answer, the result is " +
			"`{\"available\": false, \"reason\": …}` — an honest refusal naming which of edition / provider / a tenant " +
			"switch is in the way, and never a fabricated answer. Treat it as \"use vistaplatform_query_assets " +
			"instead\", not as \"the inventory is empty\", and do not retry.\n" +
			honestyNote,
		Annotations: readOnly("Ask about inventory"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in askInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			return d.ask(ctx, in)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_search",
		Description: "Find assets by free text when you do not know a field to filter on — a hostname fragment, " +
			"a serial number, a service name, a tag. Matches, case-insensitively and as a substring: display name, " +
			"hostname, every identifier value, and tag keys and values. It matches NOTHING ELSE — not descriptions, " +
			"not finding summaries — so a search cannot silently widen. " +
			"This is the query language's free-text term with the text quoted for you; " +
			"use vistaplatform_query_assets when you can name a field, because a field term is exact and this is not.\n" +
			honestyNote,
		Annotations: readOnly("Search assets by free text"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			text := strings.TrimSpace(in.Text)
			if text == "" {
				return nil, fmt.Errorf("text is required and must not be blank")
			}
			q := url.Values{}
			q.Set("query", quoteQueryValue(text))
			q.Set("page", "1")
			q.Set("page_size", strconv.Itoa(clampLimit(in.Limit, 25, 100)))
			v, err := d.Client.Get(ctx, d.Client.InventoryURL, assetsPath, q)
			if err != nil {
				return nil, err
			}
			return withNextCursor(v, 1), nil
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_query_certificates",
		Description: "Search the tenant's X.509 certificate inventory. Filter by expiry window, issuer, key algorithm/size or self-signed status. " +
			"PEM bodies are omitted; fingerprints, subjects, validity windows and key parameters are included. " +
			"To find the ASSETS behind expiring certificates instead, use vistaplatform_query_assets with " +
			"`cert:(not_after < now+30d)`.",
		Annotations: readOnly("Query certificates"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryCertificatesInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
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
		Name: "vistaplatform_query_crypto_configurations",
		Description: "List the tenant's discovered cryptographic configurations (protocol, version, cipher suite, key exchange, signature and hash algorithms per asset). Paginated. " +
			"A configuration's `risk_score` is the worst score of its linked catalogue algorithms.\n" +
			honestyNote,
		Annotations: readOnly("Query crypto configurations"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryCryptoConfigurationsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
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
			"risk score, migration guidance and recommended alternatives. This catalog is the source of truth for whether an algorithm is considered weak or quantum-vulnerable — " +
			"cite it rather than judging an algorithm yourself.",
		Annotations: readOnly("Query algorithm assessments"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in queryAlgorithmsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
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
			"broken down by algorithm family with suggested migration targets. " +
			"The four categories are mutually exclusive and sum to the total; `unclassified` means the catalogue could not " +
			"decide, NOT that the item is safe.",
		Annotations: readOnly("Get PQC readiness"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v1/inventory-service/pqc/progress", nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_risk_summary",
		Description: "Get the tenant's top-line risk posture: asset counts by risk band, total crypto implementations and critical findings. " +
			"Bands are the CVSS qualitative ratings ×10 (Critical ≥90, High 70-89, Medium 40-69, Low 1-39, Informational 0).\n" +
			honestyNote,
		Annotations: readOnly("Get risk summary"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			return d.Client.Get(ctx, d.Client.InventoryURL, "/api/v1/inventory-service/risk/summary", nil)
		})
	})

	// Relationships (ADR-0003), registered now that workstream 2.8 has built
	// the routes behind them. Read-only, through inventory-service HTTP under
	// the caller's own tenant, like every other tool here.

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_asset_relationships",
		Description: "The typed relationships attached to one asset — what it runs on, hosts, depends on, connects to, " +
			"is a member of, manages, and is used by. Returns each edge with the PEER's summary (id, display name, class, " +
			"status, strongest identifier), the provenance, the confidence, and when it was first and last seen, plus " +
			"`total`.\n" +
			"DIRECTION AND LABEL ARE RELATIVE TO THE ASSET YOU ASKED ABOUT, not properties of the edge. An edge is stored " +
			"once in its canonical direction and the reverse label is derived, so the same edge reads `runs_on` from one " +
			"end and `runs` from the other. Report the `label`, which is already correct for the asset in your request.\n" +
			"PROVENANCE decides how much the edge is worth: `measured` was observed by a collector, `declared` was asserted " +
			"by a user, `imported` came from a CMDB, `inferred` is the platform's own guess and is NOT agreed fact — an " +
			"inferred edge sits `pending` until a person accepts it in Approvals. Say which when it matters.\n" +
			"Read `total`, not the array's length: the page stops at `limit`. Rejected edges are excluded unless you ask " +
			"for `status: \"rejected\"` — someone decided those were wrong.",
		Annotations: readOnly("Get asset relationships"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in assetRelationshipsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "direction", in.Direction)
			set(q, "type", in.Type)
			set(q, "status", in.Status)
			q.Set("limit", strconv.Itoa(clampLimit(in.Limit, 50, 200)))
			if in.Offset > 0 {
				q.Set("offset", strconv.Itoa(in.Offset))
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/"+id+"/relationships", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_asset_neighbourhood",
		Description: "The graph around one asset to N hops: the assets reached and the edges between them. " +
			"Use it to answer \"what is this connected to\" and to describe a segment's shape; use " +
			"vistaplatform_get_asset_impact for \"what breaks if this changes\", which is a narrower and different walk.\n" +
			"Each node carries its SHORTEST hop count from the root, so a node reachable by several routes appears once.\n" +
			"CAPS ARE REAL AND MUST BE REPORTED. Depth is 1-3. At most 500 nodes and 2000 edges come back; past that the " +
			"response sets `truncated: true` and still reports `total_nodes` and `total_edges` — the true sizes. When " +
			"`truncated` is true you are looking at a PREFIX: say so, give the real totals, and never describe the result " +
			"as the complete picture.\n" +
			"Active edges only unless `include_pending` is set. A pending edge is a proposal nobody has agreed to; if you " +
			"include them, label them as proposals rather than as connections that exist.",
		Annotations: readOnly("Get asset neighbourhood"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in neighbourhoodInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			if in.Depth < 0 || in.Depth > maxNeighbourhoodDepth {
				// Refused here rather than clamped, for the reason the endpoint
				// refuses it: an agent handed three hops when it asked for five
				// would describe a partial graph as the whole one.
				return nil, fmt.Errorf("depth must be between 1 and %d, got %d — "+
					"beyond three hops the neighbourhood of an ordinary asset is the whole datacentre",
					maxNeighbourhoodDepth, in.Depth)
			}
			q := url.Values{}
			if in.Depth > 0 {
				q.Set("depth", strconv.Itoa(in.Depth))
			}
			if in.IncludePending {
				q.Set("include_pending", "true")
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/"+id+"/neighbourhood", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_asset_impact",
		Description: "What is affected if this asset changes — the blast radius. Returns the reachable assets with the " +
			"hop distance of each, a per-depth breakdown, and `total`.\n" +
			"DIRECTION: `downstream` (the default) is the DEPENDENTS — what breaks if you take this asset down. " +
			"`upstream` is what this asset itself rests on. People asking \"what depends on this\" want downstream.\n" +
			"The walk follows the NINE impact-bearing relationship types, echoed back as `types`. `connects_to` is the " +
			"one exclusion: an observed network flow is not a dependency, and including it would make almost any " +
			"asset's blast radius the entire tenant. Quote the answer as being over those types, not as \"everything " +
			"related\".\n" +
			"Each type is walked in the direction its own meaning implies, so `downstream` of a controller lists the " +
			"access points it manages and `downstream` of a virtual network lists the subnets it contains, while " +
			"`downstream` of a server lists the applications that run on it. A user-declared `impacts` edge to a " +
			"business service is included as the LAST hop; the walk does not continue past the service.\n" +
			"Only ACTIVE edges count, so an impact answer never rests on a proposal nobody has agreed to. The asset itself " +
			"is excluded from its own result. Depth is 1-10, default 6. If `truncated` is true the closure hit the 500-node " +
			"cap and `total` is a floor — say so rather than reporting a count as complete.\n" +
			"This is a read of recorded relationships, not a prediction. It can only know what has been collected or " +
			"declared: an empty result means no impact-bearing edges are RECORDED, which is not the same as \"nothing " +
			"depends on this\".",
		Annotations: readOnly("Get asset impact"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in impactInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, "assets.read", in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			if in.Depth < 0 || in.Depth > maxImpactDepth {
				// 0 means "unset" in this struct and takes the endpoint's
				// default; anything else out of range is refused rather than
				// quietly turned into a different question.
				return nil, fmt.Errorf("depth must be between 1 and %d, got %d", maxImpactDepth, in.Depth)
			}
			q := url.Values{}
			set(q, "direction", in.Direction)
			if in.Depth > 0 {
				q.Set("depth", strconv.Itoa(in.Depth))
			}
			return d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/"+id+"/impact", q)
		})
	})
}

// The caps the relationship endpoints enforce, mirrored here so the tool can
// refuse an out-of-range argument with a sentence instead of relaying a 400.
const (
	maxNeighbourhoodDepth = 3
	maxImpactDepth        = 10
)

// --------------------------------------------------------------- facets --

// maxFacetsPerCall bounds the fan-out: the platform counts one facet level per
// request, so N facets is N round trips.
const maxFacetsPerCall = 8

// askUnavailable is what `vistaplatform_ask` returns when this deployment
// cannot answer: a RESULT, not an error.
//
// The distinction is the whole point. A tool error invites a retry, and none of
// these three can succeed on a retry — a Core deployment does not gain the seam
// by being asked twice, and a tenant that switched the assistant off did not do
// it by accident. So the answer is a structured fact with a machine-readable
// reason and a named alternative that works in every edition, and the agent
// moves on rather than spending the conversation on it.
//
// `available: false` is stated explicitly rather than implied by an absent
// `answer` key: "we could not answer" and "we answered and found nothing" are
// different facts, and an agent reading the second for the first would report a
// clean inventory nobody measured.
type askUnavailable struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Instead   string `json:"instead"`
}

// The reasons, each pointing somewhere different.
const (
	askReasonEdition     = "edition"      // a purchase
	askReasonNoProvider  = "no_provider"  // an administrator's ten minutes
	askReasonTenantOff   = "tenant_off"   // a switch this organization owns
	askReasonNotGrounded = "not_grounded" // a provider answered; the query did not validate
)

// unavailable builds the refusal. A constructor rather than four struct
// literals, so `available` cannot be left to a zero value at one call site and
// set at the others — the field is the claim, and a claim made by omission is
// the shape this repository keeps finding.
func unavailable(reason, message string) askUnavailable {
	return askUnavailable{Available: false, Reason: reason, Message: message, Instead: askInstead}
}

const askInstead = "Use vistaplatform_query_assets with a query-language predicate, or " +
	"vistaplatform_search for free text. Both answer from the same inventory in every edition, " +
	"with no model involved."

// ask forwards the question to inventory-service's `/ask` and hands the
// grounded answer back unchanged.
//
// It deliberately adds NOTHING to the answer. The endpoint already holds the
// seam, the tool layer, the tenant's kill switch and the audit rail; a second
// implementation here would be a second place for the citation rule, the row
// projection and the canonical echo to be got wrong, and they would drift the
// way every duplicated rule in this repository has.
func (d *Deps) ask(ctx context.Context, in askInput) (any, error) {
	question := strings.TrimSpace(in.Question)
	if question == "" {
		return nil, fmt.Errorf("question is required and must not be blank")
	}

	v, err := d.Client.Post(ctx, d.Client.InventoryURL, askPath, map[string]any{"question": question})
	if err == nil {
		return v, nil
	}

	status, message, ok := platform.HTTPStatus(err)
	if !ok {
		// A transport failure or a credential rejection: a real error, reported
		// as one, because a retry might genuinely work.
		return nil, err
	}
	switch status {
	case http.StatusPaymentRequired:
		return unavailable(askReasonEdition, message), nil
	case http.StatusServiceUnavailable:
		return unavailable(askReasonNoProvider, message), nil
	case http.StatusForbidden:
		// FOUR different things answer 403 on this route — a role without
		// assets.read, a scope-narrowed API token, a missing CSRF token, a
		// session that must change its password — and exactly ONE of them is an
		// availability answer. So the availability answer identifies ITSELF,
		// with `reason`, and everything else stays a real error the caller must
		// see and act on.
		//
		// The polarity is the point. Matching the prose of the OTHER refusals
		// and defaulting to "switched off" is what this did first, and it read
		// "Permission outside token scope" — the scope-narrowed-token 403,
		// capital P, no lowercase "permission" anywhere in it — as the tenant
		// having turned the assistant off. That sends an operator to a settings
		// page that is already correct while the real fix is a differently
		// scoped token.
		if platform.Reason(err) == seams.ReasonAssistantDisabled {
			return unavailable(askReasonTenantOff, message), nil
		}
		return nil, err
	case http.StatusUnprocessableEntity:
		// A provider answered and what it wrote did not validate. The
		// diagnostics are in `message` verbatim — they are what an agent acts
		// on, and this is the one refusal where composing the predicate itself
		// is the obvious next move.
		return unavailable(askReasonNotGrounded, message), nil
	default:
		return nil, err
	}
}

func (d *Deps) assetFacets(ctx context.Context, in assetFacetsInput) (any, error) {
	facets := make([]string, 0, len(in.Facets))
	for _, f := range in.Facets {
		if f = strings.TrimSpace(f); f != "" {
			facets = append(facets, f)
		}
	}
	if len(facets) == 0 {
		return nil, fmt.Errorf("facets is required: name at least one of class, risk, status, environment, " +
			"ownership, stale_status, site, region, zone, segment, owner_email, business_unit, support_group, " +
			"operating_system, source, proposed_by, tag, has_findings, has_endpoints")
	}
	if len(facets) > maxFacetsPerCall {
		return nil, fmt.Errorf("at most %d facets per call, got %d — the platform counts one facet per request", maxFacetsPerCall, len(facets))
	}

	limit := clampLimit(in.Limit, 50, 200)
	out := map[string]any{}
	// canonical is read from the platform's echo rather than assembled here:
	// the counts were taken over the predicate the platform compiled, and this
	// tool has no business claiming to know what that was.
	var canonical string
	for _, level := range facets {
		q := url.Values{}
		q.Set("level", level)
		set(q, "query", in.Query)
		q.Set("limit", strconv.Itoa(limit))
		v, err := d.Client.Get(ctx, d.Client.InventoryURL, assetsPath+"/facets", q)
		if err != nil {
			return nil, fmt.Errorf("facet %q: %w", level, err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("facet %q: unexpected response shape", level)
		}
		out[level] = m["buckets"]
		if canonical == "" {
			if s, ok := m["query"].(string); ok {
				canonical = s
			}
		}
	}

	res := map[string]any{"facets": out}
	if canonical != "" {
		res["query"] = canonical
	}
	return res, nil
}

// ---------------------------------------------------------- pagination --

// cursorPrefix keeps a cursor recognisably ours, so a token from somewhere else
// is refused rather than silently read as page 1.
const cursorPrefix = "page:"

// encodeCursor mints the opaque continuation token for the page AFTER n.
//
// Opaque on purpose: the platform pages by number today and may not always, and
// a cursor an agent can read is a cursor an agent will construct. The only
// supported use is passing back what a previous result returned.
func encodeCursor(next int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + strconv.Itoa(next)))
}

// cursorPage resolves a cursor to a page number, defaulting to the first page.
// A cursor that is not one of ours is an ERROR, not a silent reset: answering
// page 1 to a malformed continuation would replay rows the caller already has
// and look like the list had changed.
func cursorPage(cursor string) (int, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 1, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("cursor is not a token this tool issued; omit it to start from the first page")
	}
	s, ok := strings.CutPrefix(string(raw), cursorPrefix)
	if !ok {
		return 0, fmt.Errorf("cursor is not a token this tool issued; omit it to start from the first page")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("cursor is not a token this tool issued; omit it to start from the first page")
	}
	return n, nil
}

// withNextCursor attaches next_cursor when the platform says another page
// exists, and attaches NOTHING when it does not — an absent next_cursor is how
// the caller knows it has seen everything, so minting one unconditionally would
// make every list look infinite.
func withNextCursor(v any, page int) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	pag, ok := m["pagination"].(map[string]any)
	if !ok {
		return v
	}
	if hasNext, _ := pag["has_next"].(bool); hasNext {
		m["next_cursor"] = encodeCursor(page + 1)
	}
	return m
}

// --------------------------------------------------------------- values --

// quoteQueryValue renders text as a query-language string literal, so a value
// containing a space, a parenthesis or a quote cannot change the SHAPE of the
// query built around it. The same escapes inventory-service uses when it
// renders a legacy filter as a query.
func quoteQueryValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "\r", `\r`)
	return `"` + r.Replace(v) + `"`
}

func set(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func setBool(q url.Values, k string, v *bool) {
	if v != nil {
		q.Set(k, strconv.FormatBool(*v))
	}
}
