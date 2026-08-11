package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// LimitEnforcementService is the legacy facade over the entitlements
// resolver. New code should reach for shared/entitlements directly — this
// type exists so the seven existing callers (auth-service features
// endpoint, compliance-engine framework/threshold handlers, cluster-sensor
// OT gate, middleware checker, etc.) keep working through the cutover.
//
// All resolution now flows through entitlements.PostgresResolver, which
// reads from billable_items / tier_entitlements / tenant_entitlements
// (introduced in PR 1). The legacy subscription_tiers.max_* columns and
// tenant_limit_overrides table are no longer consulted by these methods;
// PR 4 drops them after the admin UI migration lands.
//
// One behavior preserved at this layer (not in the resolver): when a
// tenant has no subscription_tier_id (onboarding), CheckFeatureAccess
// returns true for capabilities that are NOT edition-gated. The resolver
// itself falls through to default_value (conservative); the legacy
// carve-out keeps unfinished signups from being hard-blocked. Paid-edition
// capabilities are excluded from the carve-out — see CheckFeatureAccess.
// Numeric caps still resolve to the resolver's default value during
// onboarding (which is conservative — usually 0 — so callers should
// provision the Free tier ASAP at tenant creation).
type LimitEnforcementService struct {
	db       *sql.DB
	resolver entitlements.Resolver
}

// NewLimitEnforcementService wires the legacy facade to the resolver.
func NewLimitEnforcementService(db *sql.DB) *LimitEnforcementService {
	return &LimitEnforcementService{
		db:       db,
		resolver: entitlements.NewPostgresResolver(db),
	}
}

// LimitCheckResult is the legacy result struct callers and middleware
// already serialize. Kept intentionally compatible.
type LimitCheckResult struct {
	Allowed       bool   `json:"allowed"`
	CurrentUsage  int    `json:"current_usage"`
	Limit         *int   `json:"limit"` // nil = unlimited
	Message       string `json:"message"`
	UpgradePrompt string `json:"upgrade_prompt,omitempty"`
}

// limitTypeToItemKey maps the legacy limitType string the existing callers
// use to the new catalog key. Adding a new resource type here is a one-
// line change once the corresponding billable_items row exists.
var limitTypeToItemKey = map[string]string{
	"sensor":               "max_sensors",
	"asset":                "max_assets",
	"user":                 "max_users",
	"compliance_framework": "compliance_frameworks_max",
	"integration":          "integrations_max",
	"retention":            "retention_days",
}

// GetEffectiveLimit returns the included quantity for a legacy limitType.
// Nil = unlimited. Returns an error for unrecognised limitType.
func (s *LimitEnforcementService) GetEffectiveLimit(tenantID uuid.UUID, limitType string) (*int, error) {
	key, ok := limitTypeToItemKey[limitType]
	if !ok {
		return nil, fmt.Errorf("unknown limit type: %s", limitType)
	}
	return entitlements.GetQuantity(context.Background(), s.resolver, tenantID, key)
}

// CheckSensorLimit checks if tenant can register another sensor.
func (s *LimitEnforcementService) CheckSensorLimit(tenantID uuid.UUID) (*LimitCheckResult, error) {
	current, err := s.countSensors(tenantID)
	if err != nil {
		return nil, err
	}
	return s.checkCap(tenantID, "max_sensors", current, 1,
		"Sensor", "Upgrade your plan or contact support to add more sensors")
}

// CheckAssetLimit checks if tenant can add `additionalCount` assets.
func (s *LimitEnforcementService) CheckAssetLimit(tenantID uuid.UUID, additionalCount int) (*LimitCheckResult, error) {
	current, err := s.countAssets(tenantID)
	if err != nil {
		return nil, err
	}
	return s.checkCap(tenantID, "max_assets", current, additionalCount,
		"Asset", "Upgrade your plan or contact support to add more assets")
}

// CheckUserLimit checks if the tenant can add another user. A "seat"
// is an active user OR a pending unexpired invitation — invites reserve the
// seat so a tenant can't queue up more members than the plan allows. Resolves
// the max_users billable item; tiers without an entitlement row fall through
// to the catalog default (unlimited), so the gate fails open on absent config.
func (s *LimitEnforcementService) CheckUserLimit(tenantID uuid.UUID) (*LimitCheckResult, error) {
	current, err := s.countUsers(tenantID)
	if err != nil {
		return nil, err
	}
	pending, err := s.countPendingInvitations(tenantID)
	if err != nil {
		return nil, err
	}
	return s.checkCap(tenantID, "max_users", current+pending, 1,
		"User", "Upgrade your plan or contact support to add more users")
}

// CheckFeatureAccess returns true if `feature` resolves to enabled=true.
//
// Preserves the legacy onboarding carve-out: if the tenant has no
// subscription_tier_id yet, allow access. That keeps the signup flow from
// hard-blocking before a tier is chosen.
//
// The carve-out is deliberately NOT extended to paid-edition capabilities
// (entitlements.IsEditionGated). Tenants are created with a NULL
// subscription_tier_id, and a single-org Core deployment may never assign one
// at all — so an unconditional carve-out would resolve every Enterprise/MSP
// capability to enabled on exactly the deployments that are not entitled to
// them. Gated items require an active tenant override (the layer seeded by a
// verified edition token) rather than trusting seeded tier rows; otherwise a
// Core/no-token deployment could unlock paid surfaces by assigning the
// Enterprise tier.
//
// Unknown feature keys return (false, nil) — same shape as the legacy
// implementation. They are *not* treated as an error here so a missing
// catalog row doesn't cascade into a 500 from a gate that's incidental
// to the request.
func (s *LimitEnforcementService) CheckFeatureAccess(tenantID uuid.UUID, feature string) (bool, error) {
	hasTier, err := s.tenantHasTier(tenantID)
	if err != nil {
		return false, err
	}
	return checkFeatureAccess(context.Background(), s.resolver, tenantID, feature, hasTier)
}

func checkFeatureAccess(ctx context.Context, resolver entitlements.Resolver, tenantID uuid.UUID, feature string, hasTier bool) (bool, error) {
	editionGated := entitlements.IsEditionGated(feature)
	if !hasTier && !editionGated {
		return true, nil
	}
	ent, err := resolver.Resolve(ctx, tenantID, feature)
	if errors.Is(err, entitlements.ErrUnknownItem) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if ent.Item.Kind != entitlements.KindBoolean {
		return false, fmt.Errorf("entitlements: item %s is %s, expected boolean", feature, ent.Item.Kind)
	}
	enabled, _ := ent.BooleanValue()
	if !enabled {
		return false, nil
	}
	if editionGated && ent.Source != entitlements.SourceOverride {
		return false, nil
	}
	return true, nil
}

// GetComplianceFrameworkUsage returns (current_subscriptions, limit) for
// the compliance_frameworks_max gate. Excludes the auto-licensed Best
// Practices framework and every other zero-cost framework (FreeFrameworkCodes)
// from the current count.
func (s *LimitEnforcementService) GetComplianceFrameworkUsage(tenantID uuid.UUID) (current int, limit *int, err error) {
	current, err = s.countActiveFrameworkSubscriptions(tenantID)
	if err != nil {
		return 0, nil, err
	}
	limit, err = entitlements.GetQuantity(context.Background(), s.resolver, tenantID, "compliance_frameworks_max")
	if err != nil {
		return current, nil, err
	}
	return current, limit, nil
}

// CheckComplianceFrameworkCountLimit checks whether the tenant can add the
// given count of compliance frameworks. Use when concrete framework IDs
// aren't available (e.g., middleware). All requested frameworks are
// assumed to be non-Best-Practices.
func (s *LimitEnforcementService) CheckComplianceFrameworkCountLimit(tenantID uuid.UUID, count int) (*LimitCheckResult, error) {
	current, err := s.countActiveFrameworkSubscriptions(tenantID)
	if err != nil {
		return nil, err
	}
	return s.checkCap(tenantID, "compliance_frameworks_max", current, count,
		"Compliance framework", "Upgrade your plan to subscribe to more compliance frameworks")
}

// CheckComplianceFrameworkLimit checks whether the tenant can subscribe to
// the given set of framework IDs. Frameworks that cost nothing — the
// auto-licensed platform default plus every code in FreeFrameworkCodes — do
// not consume cap and are excluded from the request (CMP-6).
func (s *LimitEnforcementService) CheckComplianceFrameworkLimit(tenantID uuid.UUID, frameworkIDs []uuid.UUID) (*LimitCheckResult, error) {
	chargeable, err := s.countChargeableFrameworks(frameworkIDs)
	if err != nil {
		return nil, err
	}
	return s.CheckComplianceFrameworkCountLimit(tenantID, chargeable)
}

// countChargeableFrameworks returns how many of the given frameworks count
// against compliance_frameworks_max.
//
// Deliberately conservative in both directions: duplicate ids are collapsed
// first, and an id that matches NO platform_frameworks row (deleted, or a
// tenant framework passed by mistake) counts as chargeable rather than being
// waved through by a failed lookup.
func (s *LimitEnforcementService) countChargeableFrameworks(frameworkIDs []uuid.UUID) (int, error) {
	unique := make([]uuid.UUID, 0, len(frameworkIDs))
	seen := make(map[uuid.UUID]struct{}, len(frameworkIDs))
	for _, id := range frameworkIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return 0, nil
	}

	ids := make([]string, len(unique))
	for i, id := range unique {
		ids[i] = id.String()
	}

	var free int
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM platform_frameworks
		WHERE id = ANY($1)
		  AND (COALESCE(is_platform_default, false) = true OR code = ANY($2))
	`, pq.Array(ids), pq.Array(FreeFrameworkCodes)).Scan(&free)
	if err != nil {
		return 0, fmt.Errorf("count free frameworks: %w", err)
	}
	return len(unique) - free, nil
}

// GetCurrentUsage returns the live count for a legacy limitType. Provided
// for callers that want the count without running a full cap check.
func (s *LimitEnforcementService) GetCurrentUsage(tenantID uuid.UUID, limitType string) (int, error) {
	switch limitType {
	case "sensor":
		return s.countSensors(tenantID)
	case "asset":
		return s.countAssets(tenantID)
	case "user":
		return s.countUsers(tenantID)
	case "compliance_framework":
		return s.countActiveFrameworkSubscriptions(tenantID)
	default:
		return 0, fmt.Errorf("unknown limit type: %s", limitType)
	}
}

// checkCap composes the resolver-backed cap check into the legacy
// LimitCheckResult shape. resourceLabel is used in the human-readable
// Message; upgradePrompt is shown when Allowed=false.
func (s *LimitEnforcementService) checkCap(
	tenantID uuid.UUID,
	itemKey string,
	current, additional int,
	resourceLabel, upgradePrompt string,
) (*LimitCheckResult, error) {
	cc, err := entitlements.CheckCap(context.Background(), s.resolver, tenantID, itemKey, current, additional, upgradePrompt)
	if err != nil {
		return nil, err
	}
	res := &LimitCheckResult{
		Allowed:      cc.Allowed,
		CurrentUsage: current,
		Limit:        cc.Limit,
	}
	if cc.Limit == nil {
		res.Message = fmt.Sprintf("%s limit: unlimited", resourceLabel)
	} else if cc.Allowed {
		if additional == 0 || additional == 1 {
			res.Message = fmt.Sprintf("%s limit: %d/%d", resourceLabel, current, *cc.Limit)
		} else {
			res.Message = fmt.Sprintf("%s limit: %d/%d (adding %d)", resourceLabel, current, *cc.Limit, additional)
		}
	} else {
		if additional == 0 || additional == 1 {
			res.Message = fmt.Sprintf("%s limit exceeded: %d/%d", resourceLabel, current, *cc.Limit)
		} else {
			res.Message = fmt.Sprintf("%s limit would be exceeded: %d + %d = %d (limit: %d)",
				resourceLabel, current, additional, current+additional, *cc.Limit)
		}
		res.UpgradePrompt = upgradePrompt
	}
	return res, nil
}

// --- counting helpers (unchanged shape from the legacy implementation) ---

func (s *LimitEnforcementService) countSensors(tenantID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count sensors: %w", err)
	}
	return n, nil
}

func (s *LimitEnforcementService) countAssets(tenantID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count assets: %w", err)
	}
	return n, nil
}

func (s *LimitEnforcementService) countUsers(tenantID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// countPendingInvitations counts live (pending, unexpired) invitations —
// seats reserved but not yet accepted. Runs on the service's own handle;
// under enforced RLS this handle is the bypass-capable pool the caller
// constructed the service with, same as countUsers above.
func (s *LimitEnforcementService) countPendingInvitations(tenantID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM invitations
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at > NOW()
	`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending invitations: %w", err)
	}
	return n, nil
}

// countActiveFrameworkSubscriptions counts the tenant's active platform
// framework licenses that consume cap — i.e. excluding the auto-licensed
// platform default and every zero-cost framework (CMP-6). It must stay in step
// with countChargeableFrameworks: counting a free activation here while the
// gate lets it through would let six free activations exhaust a paid tenant's
// cap.
func (s *LimitEnforcementService) countActiveFrameworkSubscriptions(tenantID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON pf.id = tfl.platform_framework_id
		WHERE tfl.tenant_id = $1
		  AND tfl.subscription_status = 'active'
		  AND COALESCE(pf.is_platform_default, false) = false
		  AND pf.code <> ALL($2)
	`, tenantID, pq.Array(FreeFrameworkCodes)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active framework subscriptions: %w", err)
	}
	return n, nil
}

func (s *LimitEnforcementService) tenantHasTier(tenantID uuid.UUID) (bool, error) {
	var tier sql.NullString
	err := s.db.QueryRow(`SELECT subscription_tier_id FROM tenants WHERE id = $1`, tenantID).Scan(&tier)
	if err != nil {
		return false, fmt.Errorf("look up tenant tier: %w", err)
	}
	return tier.Valid && tier.String != "", nil
}
