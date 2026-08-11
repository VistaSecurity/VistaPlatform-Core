package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/handlers"
	adminservices "github.com/vistasecurity/vistaplatform/admin-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/cache"
)

// This file is the Core/Enterprise seam for admin-service. There are two
// independent Enterprise surfaces behind it: *billing* (monetization) and
// *MSP* (the multi-tenant management plane).
//
// The open-core split is "who is the buyer":
//
//	Core       — the barebones operator console a SINGLE ORGANIZATION needs:
//	             platform users, roles/RBAC and platform-admin auth; platform
//	             settings (SMTP, password/session policy); branding; legal
//	             document authoring; identity providers and staff SSO; storage
//	             config; platform integrations; security events and the
//	             platform's own compliance posture; System Health; and the tier
//	             /billable-item catalog including tier ASSIGNMENT, so
//	             shared/entitlements resolves correctly with no Enterprise code
//	             present.
//	MSP        — the management plane you only need when you operate OTHER
//	             organizations: the whole /admin/tenants/** surface, tenant
//	             lifecycle, per-tenant entitlement overrides, cross-tenant
//	             stats/dashboard/cost aggregates, announcements, maintenance
//	             windows, support tickets, and the cross-tenant legal
//	             acceptance ledger. Mechanically identifiable: it either serves
//	             a /platform aggregate or reads the BYPASSRLS handle to span
//	             tenants.
//	Enterprise — the commercial layer that turns tenants into customers:
//	             Stripe, subscriptions, invoices, coupons, dunning, trials,
//	             contract renewals and billing analytics.
//
// Core declares the seam; the implementation lives under
// services/admin-service/ee/ and is absent from the open-source tree. A Core
// build leaves the hooks nil, so the billing routes are simply never mounted
// and the billing background workers never exist. That is a supported product
// configuration, not a degraded one — nothing in Core reads a Stripe object.
//
// IMPORTANT — what deliberately stays in Core: tier *assignment*.
// adminservices.TierService.AssignTier and the free/manual assignment path in
// handlers/tier_management.go are Core code. A Core deployment can still put a
// tenant on a tier, which is what shared/entitlements resolves against, so
// entitlements work with no billing package present. The only thing Core loses
// is the Stripe Product/Price auto-provisioning that a *stripe-billed* tier
// would trigger on save — see TierPricer below.
//
// See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5 for the
// repo-wide pattern.

// BillingDeps is the plumbing the Enterprise billing surface needs in order to
// mount itself. It is deliberately a small bag of already-constructed
// primitives rather than the *Server: the seam must not widen into "EE can
// reach into anything the server holds".
type BillingDeps struct {
	// DB is the RLS-enforcing pool (crypto_app).
	DB *sql.DB
	// BypassDB is the BYPASSRLS pool (crypto_bypass) used by the deliberately
	// cross-tenant billing reads (platform invoice list, analytics rollups).
	BypassDB *sql.DB
	// Config is the loaded service configuration, including the STRIPE_* keys.
	Config *config.Config

	// AdminGroup is the unauthenticated service root group
	// (/api/v1/admin-service). The tenant-facing billing lanes hang off this
	// and apply their own tenant-cookie auth.
	AdminGroup *gin.RouterGroup
	// Protected is the platform-admin group (/api/v1/admin-service/admin)
	// with JWT auth + StringifyUserID already applied. Permission gates are
	// added per-subgroup by the caller via RequirePlatformPermission.
	Protected *gin.RouterGroup

	// RequirePlatformPermission builds a platform-RBAC gate middleware. Handed
	// over as a function so EE never needs the *rbac.RBACService itself.
	RequirePlatformPermission func(permission string) gin.HandlerFunc

	// CachedHandlers is the Redis-backed handler cache, or nil when Redis is
	// unavailable. EE uses it only to invalidate the tenant cache after a
	// tenant-billing write.
	CachedHandlers *handlers.CachedHandlers
}

// MSPDeps is the plumbing the MSP management plane needs in order to mount
// itself. Same design rule as BillingDeps: a small bag of already-constructed
// primitives, never the *Server.
type MSPDeps struct {
	// DB is the RLS-enforcing pool (crypto_app).
	DB *sql.DB
	// BypassDB is the BYPASSRLS pool (crypto_bypass). Every cross-tenant read
	// in the MSP plane goes through this handle — that is the mechanical tell
	// for what belongs on this side of the seam.
	BypassDB *sql.DB
	// Config is the loaded service configuration. MSP reads
	// EncryptionMasterKey (tenant integration credentials) and the
	// monitoring/resource-tracker peer URLs (dashboard aggregation).
	Config *config.Config

	// Protected is the platform-admin group (/api/v1/admin-service/admin) with
	// JWT auth + StringifyUserID already applied. Permission gates are added
	// per-subgroup by the callee via RequirePlatformPermission.
	Protected *gin.RouterGroup

	// RequirePlatformPermission builds a platform-RBAC gate middleware. Handed
	// over as a function so MSP never needs the *rbac.RBACService itself.
	RequirePlatformPermission func(permission string) gin.HandlerFunc

	// Cache is the Redis client, or nil when Redis is unavailable. MSP uses it
	// to build its own cached cross-tenant reads (tenant list, platform stats);
	// with nil it mounts the uncached handlers instead.
	Cache *cache.Client
	// CachedHandlers is Core's cache janitor, or nil when Redis is
	// unavailable. MSP uses it only for WrapWithCacheInvalidation around its
	// tenant mutations.
	CachedHandlers *handlers.CachedHandlers
}

// MSPRuntime is the handle to MSP background work — currently the dashboard
// aggregator's hub and polling goroutines. Core never has one, so the server's
// start/stop paths are nil-tolerant.
type MSPRuntime interface {
	// Start launches any MSP background workers. Non-blocking.
	Start()
	// Stop signals them to wind down.
	Stop()
}

// BillingRuntime is the handle to the Enterprise billing background workers
// (Stripe webhook processor + contract renewal-notice sweep). Core never has
// one, so the server's start/stop paths are nil-tolerant.
type BillingRuntime interface {
	// Start launches the workers. Non-blocking.
	Start()
	// Stop signals the workers to wind down.
	Stop()
}

// EditionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil. The Enterprise build
// supplies real implementations from cmd/edition_ee.go, which is guarded by
// `//go:build ee` and is the only file permitted to import
// services/admin-service/ee/. Neither that file nor the ee/ tree exists in the
// open-source repository, so a Core checkout cannot accidentally link
// Enterprise code — there is nothing to link.
//
// Hooks are wired at process start rather than resolved per request: this
// boundary decides which *code* is present, while shared/entitlements decides
// which *tenant* may use it. Both gates apply in an Enterprise build.
type EditionHooks struct {
	// RegisterBilling mounts the whole billing HTTP surface (platform billing
	// admin, tenant /my-billing, onboarding /billing, the provider webhook)
	// and returns a handle to its background workers. Returning nil is legal
	// and means "routes mounted, no workers".
	//
	// Nil in Core, so none of those routes exist.
	RegisterBilling func(BillingDeps) BillingRuntime

	// RegisterMSP mounts the whole MSP management plane (/admin/tenants/**,
	// /admin/stats/**, /admin/dashboard/**, /admin/costs/**,
	// /admin/announcements, /admin/maintenance-windows, /admin/support-tickets,
	// /admin/legal/acceptances, /admin/monitoring/metrics) and returns a handle
	// to its background work. Returning nil is legal and means "routes mounted,
	// no workers".
	//
	// Nil in Core, so a Core console is exactly the single-organization
	// operator surface: it has no tenant directory to show and no cross-tenant
	// aggregate to compute, because that code is not in the binary.
	RegisterMSP func(MSPDeps) MSPRuntime

	// ApplyEditionToken verifies an entitlement token and seeds the grants it
	// carries. Nil in Core, which is why a Core build has no notion of a
	// license token at all — not a disabled check, an absent one.
	//
	// Called once at boot with the platform DB. It must never be fatal: a
	// missing token is the Core edition, and a malformed one is an operator
	// error that should not become an outage.
	ApplyEditionToken func(db *sql.DB)

	// NewTierPricer returns the provisioner that mints a Stripe Product/Price
	// when a stripe-billed tier is saved. Nil in Core: tiers are still fully
	// creatable, editable and assignable, they just carry no Stripe price.
	NewTierPricer func(cfg *config.Config) adminservices.TierPricer
}

// Edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
//
// Both Enterprise surfaces are wired from the same `//go:build ee` file, so in
// practice they are set together; the check is written as "any hook present" so
// it stays honest if that ever changes.
func (h EditionHooks) Edition() string {
	if h.RegisterBilling == nil && h.RegisterMSP == nil {
		return "core"
	}
	return "enterprise"
}

// EditionCapabilities reports which OPTIONAL admin-service surfaces the running
// binary actually mounted. This is the machine-readable half of the edition
// read-out and the half clients should gate on.
//
// It is derived from hook presence, which is the same fact that decides whether
// the routes exist at all — so it cannot drift from reality the way a
// hand-maintained capability list would. `msp` true means /admin/tenants/**,
// /admin/stats/**, /admin/dashboard/**, /admin/costs/**, /admin/announcements,
// /admin/maintenance-windows, /admin/support-tickets and
// /admin/legal/acceptances are mounted; `billing` true means /admin/billing/**
// and /admin/tenants/:id/billing are.
//
// Deliberately NOT a list of every paid capability in the product: this service
// can only speak for its own routes. SIEM export (audit-service/ee/siemexport),
// CMDB sync (inventory-service/ee/cmdbsync) and the rest live in other binaries
// and keep their own response probes — see packages/primitives/src/features/
// edition.ts. Adding them here would be a guess dressed up as a fact.
type EditionCapabilities struct {
	// MSP reports whether the multi-tenant management plane is mounted.
	MSP bool `json:"msp"`
	// Billing reports whether the Enterprise billing surface is mounted.
	Billing bool `json:"billing"`
}

// EditionInfo is the wire shape of GET /admin/platform/edition.
//
// `edition` is deliberately COARSE — "core" or "enterprise", matching
// Edition(). A single ee binary serves both the Enterprise and MSP editions
// (both hooks are wired from the same //go:build ee file), so the binary cannot
// honestly claim to be MSP-licensed rather than Enterprise-licensed; which
// grants a deployment holds is an entitlement-token question, not a build one.
// Clients gate on Capabilities, which IS mechanically exact.
type EditionInfo struct {
	Edition      string              `json:"edition"`
	Capabilities EditionCapabilities `json:"capabilities"`
}

// Info resolves the build's edition read-out.
func (h EditionHooks) Info() EditionInfo {
	return EditionInfo{
		Edition: h.Edition(),
		Capabilities: EditionCapabilities{
			MSP:     h.RegisterMSP != nil,
			Billing: h.RegisterBilling != nil,
		},
	}
}

// PlatformEdition serves the edition read-out at
// GET /api/v1/admin-service/admin/platform/edition.
//
// This handler is CORE code and must stay that way: its whole job is to be
// answerable by a build that has no ee/ tree, so that the admin console can
// stop offering navigation whose backend was never mounted. A Core console that
// shows a Tenants tab is not a licensing problem, it is a broken product — the
// 404 behind that tab is correct behaviour and the tab is the bug.
//
// Authenticated (it hangs off the platform-admin group) but NOT permission
// gated: every operator's navigation depends on it, exactly like
// /admin/auth/me and /admin/user/permissions.
//
// `info` is resolved once at mount time rather than per request because hooks
// are wired at process start and cannot change while the process runs.
func PlatformEdition(info EditionInfo) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, info)
	}
}
