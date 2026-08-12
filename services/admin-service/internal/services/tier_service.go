package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// Billable-item keys for the numeric caps surfaced by GetEffectiveLimits.
// These mirror the seeded billable_items rows and are the same keys the
// enforcement path resolves against, so the displayed limits agree with
// what's actually enforced (override > tier > default).
const (
	itemMaxSensors              = "max_sensors"
	itemMaxAssets               = "max_assets"
	itemMaxUsers                = "max_users"
	itemRetentionDays           = "retention_days"
	itemComplianceFrameworksMax = "compliance_frameworks_max"
	itemIntegrationsMax         = "integrations_max"
)

// TierPricer provisions Stripe Product/Price objects for a tier so admins
// never touch the Stripe dashboard. Implemented by *billing.StripeProvider;
// optional — nil when Stripe is unconfigured or in tests, in which case tier
// CRUD proceeds without provisioning.
type TierPricer interface {
	ProvisionTierPricing(
		tierID uuid.UUID, tierName, displayName, existingProductID string,
		priceCents int, annualPriceCents *int,
	) (productID, monthlyPriceID, annualPriceID string, err error)
	// ArchivePrice deactivates a superseded/retired Stripe Price (Prices can't
	// be deleted). ArchiveProduct deactivates a deprecated plan's Product.
	ArchivePrice(priceID string) error
	ArchiveProduct(productID string) error
}

// TierService handles subscription tier management
type TierService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS connection (crypto_bypass) exposed via BypassDB()
	// for callers running cross-tenant platform aggregates (Phase 4).
	bypassDB *sql.DB
	pricer   TierPricer
}

// NewTierService creates a new tier service.
// bypassDB is the cross-tenant (BYPASSRLS) handle exposed via BypassDB().
func NewTierService(db, bypassDB *sql.DB) *TierService {
	return &TierService{db: db, bypassDB: bypassDB}
}

// SetPricer wires the Stripe price provisioner used when saving stripe-billed
// plans. Safe to leave unset (provisioning is skipped).
func (s *TierService) SetPricer(p TierPricer) {
	s.pricer = p
}

// provisionStripePricing creates/refreshes the tier's Stripe Product + Price
// objects and persists the resulting ids (product id in metadata, price ids in
// their columns). No-op when no pricer is wired. Stripe Prices are immutable,
// so this mints new Prices and repoints the columns; the old Prices remain for
// already-subscribed tenants until migrated.
func (s *TierService) provisionStripePricing(tier *models.SubscriptionTier) error {
	if s.pricer == nil {
		return nil
	}
	existingProductID := ""
	if tier.Metadata != nil {
		if v, ok := tier.Metadata["stripe_product_id"].(string); ok {
			existingProductID = v
		}
	}
	// Capture the prices we're about to supersede so they can be archived.
	oldMonthly, oldAnnual := "", ""
	if tier.StripePriceID != nil {
		oldMonthly = *tier.StripePriceID
	}
	if tier.StripePriceIDAnnual != nil {
		oldAnnual = *tier.StripePriceIDAnnual
	}

	productID, monthlyID, annualID, err := s.pricer.ProvisionTierPricing(
		tier.ID, tier.Name, tier.DisplayName, existingProductID, tier.PriceCents, tier.AnnualPriceCents,
	)
	if err != nil {
		return err
	}

	meta := tier.Metadata
	if meta == nil {
		meta = map[string]interface{}{}
	}
	meta["stripe_product_id"] = productID
	metaJSON, _ := json.Marshal(meta)

	if _, err := s.db.Exec(`
		UPDATE subscription_tiers
		SET metadata = $1,
		    stripe_price_id = NULLIF($2, ''),
		    stripe_price_id_annual = NULLIF($3, ''),
		    updated_at = NOW()
		WHERE id = $4
	`, metaJSON, monthlyID, annualID, tier.ID); err != nil {
		return fmt.Errorf("persist stripe price ids: %w", err)
	}

	// Archive the superseded Prices (immutable, so this is the only cleanup).
	// Best-effort — the new prices are already persisted; a stale archived
	// Price just lingers harmlessly in Stripe if this fails.
	if oldMonthly != "" && oldMonthly != monthlyID {
		if aerr := s.pricer.ArchivePrice(oldMonthly); aerr != nil {
			log.Printf("tier %s: archive superseded monthly price %s failed (non-fatal): %v", tier.ID, oldMonthly, aerr)
		}
	}
	if oldAnnual != "" && oldAnnual != annualID {
		if aerr := s.pricer.ArchivePrice(oldAnnual); aerr != nil {
			log.Printf("tier %s: archive superseded annual price %s failed (non-fatal): %v", tier.ID, oldAnnual, aerr)
		}
	}
	return nil
}

// DB returns the database connection
func (s *TierService) DB() *sql.DB {
	return s.db
}

// BypassDB returns the BYPASSRLS connection (crypto_bypass) for the
// deliberately cross-tenant platform aggregates (Phase 4).
func (s *TierService) BypassDB() *sql.DB {
	return s.bypassDB
}

// GetTier retrieves a tier by ID
func (s *TierService) GetTier(tierID uuid.UUID) (*models.SubscriptionTier, error) {
	query := `
		SELECT id, name, display_name, max_sensors, max_assets, max_users,
		       retention_days, price_cents, annual_price_cents, billing_interval,
		       billing_method, stripe_price_id, stripe_price_id_annual,
		       features, limits, addon_pricing, metadata, is_active, is_custom,
		       owner_tenant_id, display_order, deprecated_at, created_at, updated_at
		FROM subscription_tiers
		WHERE id = $1
	`

	var tier models.SubscriptionTier
	var maxSensors, maxAssets, maxUsers, annualPriceCents sql.NullInt64
	var stripePriceID, stripePriceIDAnnual sql.NullString
	var ownerTenantID uuid.NullUUID
	var featuresJSON, limitsJSON, addonPricingJSON, metadataJSON []byte
	var deprecatedAt sql.NullTime

	err := s.db.QueryRow(query, tierID).Scan(
		&tier.ID, &tier.Name, &tier.DisplayName,
		&maxSensors, &maxAssets, &maxUsers,
		&tier.RetentionDays, &tier.PriceCents, &annualPriceCents, &tier.BillingInterval,
		&tier.BillingMethod, &stripePriceID, &stripePriceIDAnnual,
		&featuresJSON, &limitsJSON, &addonPricingJSON, &metadataJSON,
		&tier.IsActive, &tier.IsCustom, &ownerTenantID, &tier.DisplayOrder,
		&deprecatedAt, &tier.CreatedAt, &tier.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get tier: %w", err)
	}

	if annualPriceCents.Valid {
		val := int(annualPriceCents.Int64)
		tier.AnnualPriceCents = &val
	}
	if stripePriceID.Valid {
		tier.StripePriceID = &stripePriceID.String
	}
	if stripePriceIDAnnual.Valid {
		tier.StripePriceIDAnnual = &stripePriceIDAnnual.String
	}
	if ownerTenantID.Valid {
		tier.OwnerTenantID = &ownerTenantID.UUID
	}

	// Convert nullable integers
	if maxSensors.Valid {
		val := int(maxSensors.Int64)
		if val == -1 {
			tier.MaxSensors = nil // Unlimited
		} else {
			tier.MaxSensors = &val
		}
	}
	if maxAssets.Valid {
		val := int(maxAssets.Int64)
		if val == -1 {
			tier.MaxAssets = nil
		} else {
			tier.MaxAssets = &val
		}
	}
	if maxUsers.Valid {
		val := int(maxUsers.Int64)
		if val == -1 {
			tier.MaxUsers = nil
		} else {
			tier.MaxUsers = &val
		}
	}

	// Parse JSONB fields
	if err := json.Unmarshal(featuresJSON, &tier.Features); err != nil {
		tier.Features = make(map[string]interface{})
	}
	if err := json.Unmarshal(limitsJSON, &tier.Limits); err != nil {
		tier.Limits = make(map[string]interface{})
	}
	if err := json.Unmarshal(addonPricingJSON, &tier.AddonPricing); err != nil {
		tier.AddonPricing = make(map[string]interface{})
	}
	if err := json.Unmarshal(metadataJSON, &tier.Metadata); err != nil {
		tier.Metadata = make(map[string]interface{})
	}

	if deprecatedAt.Valid {
		tier.DeprecatedAt = &deprecatedAt.Time
	}

	return &tier, nil
}

// GetTierByName retrieves a tier by name
func (s *TierService) GetTierByName(name string) (*models.SubscriptionTier, error) {
	query := `
		SELECT id, name, display_name, max_sensors, max_assets, max_users, 
		       retention_days, price_cents, billing_interval, features, limits,
		       addon_pricing, metadata, is_active, is_custom, display_order,
		       deprecated_at, created_at, updated_at
		FROM subscription_tiers
		WHERE name = $1
	`

	var tier models.SubscriptionTier
	var maxSensors, maxAssets, maxUsers sql.NullInt64
	var featuresJSON, limitsJSON, addonPricingJSON, metadataJSON []byte
	var deprecatedAt sql.NullTime

	err := s.db.QueryRow(query, name).Scan(
		&tier.ID, &tier.Name, &tier.DisplayName,
		&maxSensors, &maxAssets, &maxUsers,
		&tier.RetentionDays, &tier.PriceCents, &tier.BillingInterval,
		&featuresJSON, &limitsJSON, &addonPricingJSON, &metadataJSON,
		&tier.IsActive, &tier.IsCustom, &tier.DisplayOrder,
		&deprecatedAt, &tier.CreatedAt, &tier.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get tier by name: %w", err)
	}

	// Convert nullable integers (same logic as GetTier)
	if maxSensors.Valid {
		val := int(maxSensors.Int64)
		if val == -1 {
			tier.MaxSensors = nil
		} else {
			tier.MaxSensors = &val
		}
	}
	if maxAssets.Valid {
		val := int(maxAssets.Int64)
		if val == -1 {
			tier.MaxAssets = nil
		} else {
			tier.MaxAssets = &val
		}
	}
	if maxUsers.Valid {
		val := int(maxUsers.Int64)
		if val == -1 {
			tier.MaxUsers = nil
		} else {
			tier.MaxUsers = &val
		}
	}

	// Parse JSONB fields
	if err := json.Unmarshal(featuresJSON, &tier.Features); err != nil {
		tier.Features = make(map[string]interface{})
	}
	if err := json.Unmarshal(limitsJSON, &tier.Limits); err != nil {
		tier.Limits = make(map[string]interface{})
	}
	if err := json.Unmarshal(addonPricingJSON, &tier.AddonPricing); err != nil {
		tier.AddonPricing = make(map[string]interface{})
	}
	if err := json.Unmarshal(metadataJSON, &tier.Metadata); err != nil {
		tier.Metadata = make(map[string]interface{})
	}

	if deprecatedAt.Valid {
		tier.DeprecatedAt = &deprecatedAt.Time
	}

	return &tier, nil
}

// ListTiers retrieves all active tiers, ordered by display_order
func (s *TierService) ListTiers(includeDeprecated bool) ([]models.SubscriptionTier, error) {
	query := `
		SELECT id, name, display_name, max_sensors, max_assets, max_users,
		       retention_days, price_cents, annual_price_cents, billing_interval,
		       billing_method, stripe_price_id, stripe_price_id_annual,
		       features, limits, addon_pricing, metadata, is_active, is_custom,
		       owner_tenant_id, display_order, deprecated_at, created_at, updated_at
		FROM subscription_tiers
		WHERE is_active = true
	`
	if !includeDeprecated {
		query += " AND deprecated_at IS NULL"
	}
	query += " ORDER BY display_order ASC, name ASC"

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list tiers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tiers []models.SubscriptionTier
	for rows.Next() {
		var tier models.SubscriptionTier
		var maxSensors, maxAssets, maxUsers, annualPriceCents sql.NullInt64
		var stripePriceID, stripePriceIDAnnual sql.NullString
		var ownerTenantID uuid.NullUUID
		var featuresJSON, limitsJSON, addonPricingJSON, metadataJSON []byte
		var deprecatedAt sql.NullTime

		err := rows.Scan(
			&tier.ID, &tier.Name, &tier.DisplayName,
			&maxSensors, &maxAssets, &maxUsers,
			&tier.RetentionDays, &tier.PriceCents, &annualPriceCents, &tier.BillingInterval,
			&tier.BillingMethod, &stripePriceID, &stripePriceIDAnnual,
			&featuresJSON, &limitsJSON, &addonPricingJSON, &metadataJSON,
			&tier.IsActive, &tier.IsCustom, &ownerTenantID, &tier.DisplayOrder,
			&deprecatedAt, &tier.CreatedAt, &tier.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tier: %w", err)
		}

		if annualPriceCents.Valid {
			val := int(annualPriceCents.Int64)
			tier.AnnualPriceCents = &val
		}
		if stripePriceID.Valid {
			tier.StripePriceID = &stripePriceID.String
		}
		if stripePriceIDAnnual.Valid {
			tier.StripePriceIDAnnual = &stripePriceIDAnnual.String
		}
		if ownerTenantID.Valid {
			tier.OwnerTenantID = &ownerTenantID.UUID
		}

		// Convert nullable integers
		if maxSensors.Valid {
			val := int(maxSensors.Int64)
			if val == -1 {
				tier.MaxSensors = nil
			} else {
				tier.MaxSensors = &val
			}
		}
		if maxAssets.Valid {
			val := int(maxAssets.Int64)
			if val == -1 {
				tier.MaxAssets = nil
			} else {
				tier.MaxAssets = &val
			}
		}
		if maxUsers.Valid {
			val := int(maxUsers.Int64)
			if val == -1 {
				tier.MaxUsers = nil
			} else {
				tier.MaxUsers = &val
			}
		}

		// Parse JSONB fields
		if err := json.Unmarshal(featuresJSON, &tier.Features); err != nil {
			tier.Features = make(map[string]interface{})
		}
		if err := json.Unmarshal(limitsJSON, &tier.Limits); err != nil {
			tier.Limits = make(map[string]interface{})
		}
		if err := json.Unmarshal(addonPricingJSON, &tier.AddonPricing); err != nil {
			tier.AddonPricing = make(map[string]interface{})
		}
		if err := json.Unmarshal(metadataJSON, &tier.Metadata); err != nil {
			tier.Metadata = make(map[string]interface{})
		}

		if deprecatedAt.Valid {
			tier.DeprecatedAt = &deprecatedAt.Time
		}

		tiers = append(tiers, tier)
	}

	return tiers, nil
}

// CreateTier creates a new subscription tier
func (s *TierService) CreateTier(req models.TierCreateRequest) (*models.SubscriptionTier, error) {
	// Validate name uniqueness
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM subscription_tiers WHERE name = $1)", req.Name).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("failed to check tier name: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("tier with name '%s' already exists", req.Name)
	}

	// Convert nil pointers to -1 for unlimited
	maxSensors := sql.NullInt64{Valid: req.MaxSensors != nil}
	if req.MaxSensors != nil {
		maxSensors.Int64 = int64(*req.MaxSensors)
	} else {
		maxSensors.Int64 = -1
	}

	maxAssets := sql.NullInt64{Valid: req.MaxAssets != nil}
	if req.MaxAssets != nil {
		maxAssets.Int64 = int64(*req.MaxAssets)
	} else {
		maxAssets.Int64 = -1
	}

	maxUsers := sql.NullInt64{Valid: req.MaxUsers != nil}
	if req.MaxUsers != nil {
		maxUsers.Int64 = int64(*req.MaxUsers)
	} else {
		maxUsers.Int64 = -1
	}

	// Marshal JSONB fields
	featuresJSON, _ := json.Marshal(req.Features)
	limitsJSON, _ := json.Marshal(req.Limits)
	addonPricingJSON, _ := json.Marshal(req.AddonPricing)
	metadataJSON, _ := json.Marshal(req.Metadata)

	// billing_method defaults to "stripe" when unset; reject anything else.
	billingMethod := req.BillingMethod
	if billingMethod == "" {
		billingMethod = "stripe"
	}
	if billingMethod != "stripe" && billingMethod != "invoice" {
		return nil, fmt.Errorf("invalid billing_method %q (want 'stripe' or 'invoice')", billingMethod)
	}

	annualPriceCents := sql.NullInt64{Valid: req.AnnualPriceCents != nil}
	if req.AnnualPriceCents != nil {
		annualPriceCents.Int64 = int64(*req.AnnualPriceCents)
	}
	ownerTenantID := uuid.NullUUID{Valid: req.OwnerTenantID != nil}
	if req.OwnerTenantID != nil {
		ownerTenantID.UUID = *req.OwnerTenantID
	}

	query := `
		INSERT INTO subscription_tiers (
			name, display_name, max_sensors, max_assets, max_users,
			retention_days, price_cents, annual_price_cents, billing_interval,
			billing_method, features, limits, addon_pricing, metadata,
			is_active, is_custom, owner_tenant_id, display_order
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true, $15, $16, $17)
		RETURNING id, created_at, updated_at
	`

	var tierID uuid.UUID
	var createdAt, updatedAt time.Time
	err = s.db.QueryRow(
		query,
		req.Name, req.DisplayName, maxSensors, maxAssets, maxUsers,
		req.RetentionDays, req.PriceCents, annualPriceCents, req.BillingInterval,
		billingMethod, featuresJSON, limitsJSON, addonPricingJSON, metadataJSON,
		req.IsCustom, ownerTenantID, req.DisplayOrder,
	).Scan(&tierID, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create tier: %w", err)
	}

	// Persist the billable-item composition to tier_entitlements (the
	// enforced layer). This is the source of truth for what the plan
	// grants — the legacy subscription_tiers.* columns above are kept only
	// for display back-compat. A bad item_key fails the whole create.
	if len(req.Entitlements) > 0 {
		if err := NewEntitlementsService(s.db, s.bypassDB).ReplaceTierEntitlements(
			tierID, toServiceEntitlementInputs(req.Entitlements),
		); err != nil {
			// Roll back the orphaned tier row so create is all-or-nothing.
			_, _ = s.db.Exec(`DELETE FROM subscription_tiers WHERE id = $1`, tierID)
			return nil, fmt.Errorf("failed to write tier entitlements: %w", err)
		}
	}

	created, err := s.GetTier(tierID)
	if err != nil {
		return nil, err
	}

	// Auto-provision Stripe Product/Price for card-billed paid plans. Best-effort:
	// a Stripe failure leaves the plan created (admin can retry by re-saving)
	// rather than blocking plan creation. Invoice plans and free plans skip this.
	if billingMethod == "stripe" && req.PriceCents > 0 && s.pricer != nil {
		if perr := s.provisionStripePricing(created); perr != nil {
			log.Printf("create tier %s: stripe pricing provision failed (non-fatal): %v", tierID, perr)
		} else if refreshed, rerr := s.GetTier(tierID); rerr == nil {
			created = refreshed
		}
	}
	return created, nil
}

// toServiceEntitlementInputs converts the models DTO (carried on tier
// requests to avoid a models→services import cycle) into the services
// type ReplaceTierEntitlements expects.
func toServiceEntitlementInputs(in []models.TierEntitlementInput) []TierEntitlementInput {
	out := make([]TierEntitlementInput, 0, len(in))
	for _, e := range in {
		out = append(out, TierEntitlementInput{
			ItemKey:           e.ItemKey,
			IncludedValue:     e.IncludedValue,
			OveragePriceCents: e.OveragePriceCents,
			OverageUnitSize:   e.OverageUnitSize,
		})
	}
	return out
}

// UpdateTier updates an existing tier (grandfathers existing tenants)
func (s *TierService) UpdateTier(tierID uuid.UUID, req models.TierUpdateRequest, changedBy uuid.UUID) (*models.SubscriptionTier, error) {
	// Get existing tier
	existing, err := s.GetTier(tierID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing tier: %w", err)
	}

	// Build update query dynamically
	updates := []string{}
	args := []interface{}{}
	argPos := 1

	// Track changes for history
	changes := make(map[string]interface{})

	if req.DisplayName != nil {
		updates = append(updates, fmt.Sprintf("display_name = $%d", argPos))
		args = append(args, *req.DisplayName)
		changes["display_name"] = map[string]interface{}{"before": existing.DisplayName, "after": *req.DisplayName}
		argPos++
	}

	if req.MaxSensors != nil {
		val := -1
		if *req.MaxSensors >= 0 {
			val = *req.MaxSensors
		}
		updates = append(updates, fmt.Sprintf("max_sensors = $%d", argPos))
		args = append(args, val)
		changes["max_sensors"] = map[string]interface{}{"before": existing.MaxSensors, "after": req.MaxSensors}
		argPos++
	}

	if req.MaxAssets != nil {
		val := -1
		if *req.MaxAssets >= 0 {
			val = *req.MaxAssets
		}
		updates = append(updates, fmt.Sprintf("max_assets = $%d", argPos))
		args = append(args, val)
		changes["max_assets"] = map[string]interface{}{"before": existing.MaxAssets, "after": req.MaxAssets}
		argPos++
	}

	if req.MaxUsers != nil {
		val := -1
		if *req.MaxUsers >= 0 {
			val = *req.MaxUsers
		}
		updates = append(updates, fmt.Sprintf("max_users = $%d", argPos))
		args = append(args, val)
		changes["max_users"] = map[string]interface{}{"before": existing.MaxUsers, "after": req.MaxUsers}
		argPos++
	}

	if req.RetentionDays != nil {
		updates = append(updates, fmt.Sprintf("retention_days = $%d", argPos))
		args = append(args, *req.RetentionDays)
		changes["retention_days"] = map[string]interface{}{"before": existing.RetentionDays, "after": *req.RetentionDays}
		argPos++
	}

	if req.PriceCents != nil {
		updates = append(updates, fmt.Sprintf("price_cents = $%d", argPos))
		args = append(args, *req.PriceCents)
		changes["price_cents"] = map[string]interface{}{"before": existing.PriceCents, "after": *req.PriceCents}
		argPos++
	}

	if req.AnnualPriceCents != nil {
		updates = append(updates, fmt.Sprintf("annual_price_cents = $%d", argPos))
		args = append(args, *req.AnnualPriceCents)
		changes["annual_price_cents"] = map[string]interface{}{"before": existing.AnnualPriceCents, "after": *req.AnnualPriceCents}
		argPos++
	}

	if req.BillingInterval != nil {
		updates = append(updates, fmt.Sprintf("billing_interval = $%d", argPos))
		args = append(args, *req.BillingInterval)
		changes["billing_interval"] = map[string]interface{}{"before": existing.BillingInterval, "after": *req.BillingInterval}
		argPos++
	}

	if req.BillingMethod != nil {
		if *req.BillingMethod != "stripe" && *req.BillingMethod != "invoice" {
			return nil, fmt.Errorf("invalid billing_method %q (want 'stripe' or 'invoice')", *req.BillingMethod)
		}
		updates = append(updates, fmt.Sprintf("billing_method = $%d", argPos))
		args = append(args, *req.BillingMethod)
		changes["billing_method"] = map[string]interface{}{"before": existing.BillingMethod, "after": *req.BillingMethod}
		argPos++
	}

	if req.Features != nil {
		featuresJSON, _ := json.Marshal(req.Features)
		updates = append(updates, fmt.Sprintf("features = $%d", argPos))
		args = append(args, featuresJSON)
		changes["features"] = map[string]interface{}{"before": existing.Features, "after": req.Features}
		argPos++
	}

	if req.Limits != nil {
		limitsJSON, _ := json.Marshal(req.Limits)
		updates = append(updates, fmt.Sprintf("limits = $%d", argPos))
		args = append(args, limitsJSON)
		changes["limits"] = map[string]interface{}{"before": existing.Limits, "after": req.Limits}
		argPos++
	}

	if req.AddonPricing != nil {
		addonPricingJSON, _ := json.Marshal(req.AddonPricing)
		updates = append(updates, fmt.Sprintf("addon_pricing = $%d", argPos))
		args = append(args, addonPricingJSON)
		changes["addon_pricing"] = map[string]interface{}{"before": existing.AddonPricing, "after": req.AddonPricing}
		argPos++
	}

	if req.Metadata != nil {
		metadataJSON, _ := json.Marshal(req.Metadata)
		updates = append(updates, fmt.Sprintf("metadata = $%d", argPos))
		args = append(args, metadataJSON)
		changes["metadata"] = map[string]interface{}{"before": existing.Metadata, "after": req.Metadata}
		argPos++
	}

	if req.IsActive != nil {
		updates = append(updates, fmt.Sprintf("is_active = $%d", argPos))
		args = append(args, *req.IsActive)
		changes["is_active"] = map[string]interface{}{"before": existing.IsActive, "after": *req.IsActive}
		argPos++
	}

	if req.IsCustom != nil {
		updates = append(updates, fmt.Sprintf("is_custom = $%d", argPos))
		args = append(args, *req.IsCustom)
		changes["is_custom"] = map[string]interface{}{"before": existing.IsCustom, "after": *req.IsCustom}
		argPos++
	}

	if req.OwnerTenantID != nil {
		updates = append(updates, fmt.Sprintf("owner_tenant_id = $%d", argPos))
		args = append(args, *req.OwnerTenantID)
		changes["owner_tenant_id"] = map[string]interface{}{"before": existing.OwnerTenantID, "after": *req.OwnerTenantID}
		argPos++
	}

	if req.DisplayOrder != nil {
		updates = append(updates, fmt.Sprintf("display_order = $%d", argPos))
		args = append(args, *req.DisplayOrder)
		changes["display_order"] = map[string]interface{}{"before": existing.DisplayOrder, "after": *req.DisplayOrder}
		argPos++
	}

	// Nothing to do at all (no column changes and no entitlement payload).
	if len(updates) == 0 && req.Entitlements == nil {
		return existing, nil
	}

	// Apply column updates, if any.
	if len(updates) > 0 {
		// Add updated_at
		updates = append(updates, "updated_at = NOW()")
		args = append(args, tierID)
		argPos++

		// Build final query
		setClause := ""
		for i, update := range updates {
			if i > 0 {
				setClause += ", "
			}
			setClause += update
		}

		query := fmt.Sprintf(`
			UPDATE subscription_tiers
			SET %s
			WHERE id = $%d
		`, setClause, argPos)

		if _, err = s.db.Exec(query, args...); err != nil {
			return nil, fmt.Errorf("failed to update tier: %w", err)
		}
	}

	// Bulk-replace the billable-item composition (the enforced layer) when a
	// payload is supplied. A nil slice means "leave entitlements untouched";
	// a non-nil (even empty) slice replaces them.
	if req.Entitlements != nil {
		if err := NewEntitlementsService(s.db, s.bypassDB).ReplaceTierEntitlements(
			tierID, toServiceEntitlementInputs(req.Entitlements),
		); err != nil {
			return nil, fmt.Errorf("failed to update tier entitlements: %w", err)
		}
		changes["entitlements"] = map[string]interface{}{"replaced": len(req.Entitlements)}
	}

	// Log change to history (trigger handles this, but we can add notes)
	if len(changes) > 0 {
		changesJSON, _ := json.Marshal(changes)
		_, _ = s.db.Exec(`
			INSERT INTO subscription_tier_history (tier_id, change_type, changes_json, changed_by, notes)
			VALUES ($1, 'modified', $2, $3, 'Updated via admin API')
		`, tierID, changesJSON, changedBy)
	}

	updated, err := s.GetTier(tierID)
	if err != nil {
		return nil, err
	}

	// Re-provision Stripe pricing when a card-billed plan's price changed, it
	// just switched to stripe billing, or it has no Stripe Price yet. Prices
	// are immutable so this mints new ones; best-effort (non-fatal on error).
	if s.pricer != nil && updated.BillingMethod == "stripe" && updated.PriceCents > 0 {
		priceChanged := req.PriceCents != nil || req.AnnualPriceCents != nil
		switchedToStripe := req.BillingMethod != nil && existing.BillingMethod != "stripe"
		if priceChanged || switchedToStripe || updated.StripePriceID == nil {
			if perr := s.provisionStripePricing(updated); perr != nil {
				log.Printf("update tier %s: stripe pricing provision failed (non-fatal): %v", tierID, perr)
			} else if refreshed, rerr := s.GetTier(tierID); rerr == nil {
				updated = refreshed
			}
		}
	}
	return updated, nil
}

// AssignTierResult summarizes assigning a plan to a tenant.
type AssignTierResult struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	TierID        uuid.UUID `json:"tier_id"`
	TierName      string    `json:"tier_name"`
	BillingMethod string    `json:"billing_method"`
	PaymentStatus string    `json:"payment_status,omitempty"`
	Activated     bool      `json:"activated"`
}

// AssignTierToTenant assigns a (typically custom/enterprise) plan to a tenant.
//
// For an invoice-billed plan this is "record-only": NO Stripe subscription is
// created. The tenant is pointed at the plan, marked active, and a manual
// billing_subscriptions row is recorded so the admin billing view reflects it.
// Entitlements take effect immediately because the resolver reads the tenant's
// tier from tier_entitlements. Sales invoices the customer out-of-band.
//
// For a stripe-billed plan this only sets the tier; card collection still flows
// through the normal checkout (HandleCreateSubscription), so payment_status is
// left untouched.
func (s *TierService) AssignTierToTenant(tierID, tenantID uuid.UUID) (*AssignTierResult, error) {
	tier, err := s.GetTier(tierID)
	if err != nil {
		return nil, fmt.Errorf("tier not found: %w", err)
	}

	// A private custom plan may only be assigned to its owning tenant.
	if tier.OwnerTenantID != nil && *tier.OwnerTenantID != tenantID {
		return nil, fmt.Errorf("plan %q is private to another tenant", tier.Name)
	}

	var exists bool
	if err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1 AND deleted_at IS NULL)`, tenantID,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check tenant: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("tenant not found")
	}

	// A custom plan assigned without a prior owner claims that tenant as owner,
	// so it stays private going forward.
	if tier.IsCustom && tier.OwnerTenantID == nil {
		if _, err := s.db.Exec(
			`UPDATE subscription_tiers SET owner_tenant_id = $1, updated_at = NOW() WHERE id = $2`,
			tenantID, tierID,
		); err != nil {
			return nil, fmt.Errorf("claim plan ownership: %w", err)
		}
	}

	res := &AssignTierResult{TenantID: tenantID, TierID: tierID, TierName: tier.Name, BillingMethod: tier.BillingMethod}

	if tier.BillingMethod == "invoice" {
		if _, err := s.db.Exec(
			`UPDATE tenants SET subscription_tier_id = $1, payment_status = 'active', updated_at = NOW() WHERE id = $2`,
			tierID, tenantID,
		); err != nil {
			return nil, fmt.Errorf("assign invoice plan: %w", err)
		}
		res.PaymentStatus = "active"
		res.Activated = true
		// Best-effort: the plan is already assigned + enforced even if the
		// billing-view mirror fails.
		if err := s.recordManualSubscription(tenantID, tier); err != nil {
			log.Printf("assign tier %s to tenant %s: manual subscription mirror failed (non-fatal): %v", tierID, tenantID, err)
		}
		return res, nil
	}

	if _, err := s.db.Exec(
		`UPDATE tenants SET subscription_tier_id = $1, updated_at = NOW() WHERE id = $2`,
		tierID, tenantID,
	); err != nil {
		return nil, fmt.Errorf("assign plan: %w", err)
	}
	return res, nil
}

// recordManualSubscription writes a billing_subscriptions row under a synthetic
// "manual" provider so invoice-billed tenants surface in the admin billing view.
func (s *TierService) recordManualSubscription(tenantID uuid.UUID, tier *models.SubscriptionTier) error {
	var providerID uuid.UUID
	if err := s.db.QueryRow(`
		INSERT INTO billing_providers (key, display_name, is_active)
		VALUES ('manual', 'Manual / Invoice', true)
		ON CONFLICT (key) DO UPDATE SET is_active = true
		RETURNING id
	`).Scan(&providerID); err != nil {
		return fmt.Errorf("ensure manual provider: %w", err)
	}
	// billing_subscriptions is RLS-scoped and tenantID is an INPUT here, so the
	// write runs inside a tenant-scoped transaction. Unwrapped on the crypto_app
	// handle the INSERT trips the policy's WITH CHECK and the whole invoice-plan
	// assignment fails. (billing_providers above carries no policy.)
	if err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.Exec(`
		INSERT INTO billing_subscriptions (tenant_id, provider_id, external_subscription_id, plan_key, status)
		VALUES ($1, $2, $3, $4, 'active')
		ON CONFLICT (tenant_id, provider_id) DO UPDATE
		SET external_subscription_id = EXCLUDED.external_subscription_id,
		    plan_key = EXCLUDED.plan_key,
		    status = 'active',
		    updated_at = NOW()
	`, tenantID, providerID, "invoice:"+tier.ID.String(), tier.Name)
		return e
	}); err != nil {
		return fmt.Errorf("write manual subscription: %w", err)
	}
	return nil
}

// DeprecateTier marks a tier as deprecated (grandfathers existing tenants)
func (s *TierService) DeprecateTier(tierID uuid.UUID, changedBy uuid.UUID) error {
	// Fetch the tier first so we have its Stripe ids to archive after deprecating.
	tier, terr := s.GetTier(tierID)

	// Check if any tenants are using this tier
	var tenantCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM tenants WHERE subscription_tier_id = $1 AND deleted_at IS NULL", tierID).Scan(&tenantCount)
	if err != nil {
		return fmt.Errorf("failed to check tenant usage: %w", err)
	}

	// Set deprecated_at
	_, err = s.db.Exec(`
		UPDATE subscription_tiers
		SET deprecated_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`, tierID)
	if err != nil {
		return fmt.Errorf("failed to deprecate tier: %w", err)
	}

	// Log to history
	changesJSON, _ := json.Marshal(map[string]interface{}{
		"deprecated_at": time.Now(),
		"tenant_count":  tenantCount,
	})
	_, _ = s.db.Exec(`
		INSERT INTO subscription_tier_history (tier_id, change_type, changes_json, changed_by, notes)
		VALUES ($1, 'deprecated', $2, $3, $4)
	`, tierID, changesJSON, changedBy, fmt.Sprintf("Deprecated tier. %d tenants still using this tier (grandfathered).", tenantCount))

	// Archive the plan's Stripe objects so retired plans don't accumulate in
	// Stripe. Prices can't be deleted (immutable) — archive blocks new use and
	// hides them; existing grandfathered subscriptions on these Prices keep
	// billing unaffected. Archive Prices first, then the Product. Best-effort
	// and non-fatal: deprecation already succeeded above. No-op for invoice
	// plans (no Stripe ids).
	if s.pricer != nil && terr == nil {
		if tier.StripePriceID != nil {
			if aerr := s.pricer.ArchivePrice(*tier.StripePriceID); aerr != nil {
				log.Printf("deprecate tier %s: archive price failed (non-fatal): %v", tierID, aerr)
			}
		}
		if tier.StripePriceIDAnnual != nil {
			if aerr := s.pricer.ArchivePrice(*tier.StripePriceIDAnnual); aerr != nil {
				log.Printf("deprecate tier %s: archive annual price failed (non-fatal): %v", tierID, aerr)
			}
		}
		if tier.Metadata != nil {
			if pid, ok := tier.Metadata["stripe_product_id"].(string); ok && pid != "" {
				if aerr := s.pricer.ArchiveProduct(pid); aerr != nil {
					log.Printf("deprecate tier %s: archive product failed (non-fatal): %v", tierID, aerr)
				}
			}
		}
	}

	return nil
}

// GetTierHistory retrieves change history for a tier
func (s *TierService) GetTierHistory(tierID uuid.UUID) ([]models.TierHistory, error) {
	query := `
		SELECT id, tier_id, change_type, changes_json, changed_by, changed_at, notes
		FROM subscription_tier_history
		WHERE tier_id = $1
		ORDER BY changed_at DESC
	`

	rows, err := s.db.Query(query, tierID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tier history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var history []models.TierHistory
	for rows.Next() {
		var h models.TierHistory
		var changesJSON []byte
		var changedBy sql.NullString
		var notes sql.NullString

		err := rows.Scan(
			&h.ID, &h.TierID, &h.ChangeType, &changesJSON, &changedBy, &h.ChangedAt, &notes,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan history: %w", err)
		}

		if err := json.Unmarshal(changesJSON, &h.Changes); err != nil {
			h.Changes = make(map[string]interface{})
		}

		if changedBy.Valid {
			if id, err := uuid.Parse(changedBy.String); err == nil {
				h.ChangedBy = &id
			}
		}

		if notes.Valid {
			h.Notes = &notes.String
		}

		history = append(history, h)
	}

	return history, nil
}

// GetEffectiveLimits gets effective limits for a tenant (tier + overrides)
func (s *TierService) GetEffectiveLimits(tenantID uuid.UUID) (*models.EffectiveLimits, error) {
	// Get tenant's tier
	var tierID uuid.UUID
	var tierName string
	err := s.db.QueryRow(`
		SELECT t.subscription_tier_id, st.name
		FROM tenants t
		JOIN subscription_tiers st ON t.subscription_tier_id = st.id
		WHERE t.id = $1
	`, tenantID).Scan(&tierID, &tierName)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant tier: %w", err)
	}

	// Get tier limits
	tier, err := s.GetTier(tierID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tier: %w", err)
	}

	// Build effective limits starting with tier values
	effective := &models.EffectiveLimits{
		TenantID:      tenantID,
		TierID:        tierID,
		TierName:      tierName,
		MaxSensors:    tier.MaxSensors,
		MaxAssets:     tier.MaxAssets,
		MaxUsers:      tier.MaxUsers,
		RetentionDays: tier.RetentionDays,
		Features:      tier.Features,
		Overrides:     []models.LimitOverride{},
	}

	// Get compliance frameworks from features
	if val, ok := tier.Features["compliance_frameworks"]; ok {
		if num, ok := val.(float64); ok {
			count := int(num)
			if count == -1 {
				effective.ComplianceFrameworks = nil
			} else {
				effective.ComplianceFrameworks = &count
			}
		}
	}

	// Get max integrations from features
	if val, ok := tier.Features["integrations_max"]; ok {
		if num, ok := val.(float64); ok {
			count := int(num)
			if count == -1 {
				effective.MaxIntegrations = nil
			} else {
				effective.MaxIntegrations = &count
			}
		}
	}

	// The tier columns above are only a fallback. Per-tenant overrides live
	// in tenant_entitlements and are what enforcement actually resolves
	// against (override > tier > default via shared/entitlements). Overlay
	// the resolved caps so this read agrees with enforcement instead of
	// reporting tier-only values ().
	s.applyResolvedLimits(tenantID, effective)

	return effective, nil
}

// applyResolvedLimits overlays the entitlement-resolved numeric caps onto a
// tier-derived EffectiveLimits and populates Overrides/HasOverrides from the
// tenant's active tenant_entitlements rows. It is best-effort: if the
// resolver or the override listing fails, the tier-derived values are left in
// place rather than failing the endpoint, since this view is a display aid and
// the entitlements page is independently authoritative.
func (s *TierService) applyResolvedLimits(tenantID uuid.UUID, effective *models.EffectiveLimits) {
	ctx := context.Background()
	resolver := entitlements.NewPostgresResolver(s.db)

	resolved, err := resolver.ResolveMany(ctx, tenantID, []string{
		itemMaxSensors,
		itemMaxAssets,
		itemMaxUsers,
		itemRetentionDays,
		itemComplianceFrameworksMax,
		itemIntegrationsMax,
	})
	if err != nil {
		log.Printf("admin-service: effective-limits resolve failed for tenant %s: %v", tenantID, err)
	} else {
		// QuantityValue returns (nil, true) for the catalog "unlimited"
		// (quantity: null) shape, which maps to a nil *int — the same
		// "unlimited" convention EffectiveLimits already uses.
		if ent, ok := resolved[itemMaxSensors]; ok {
			if qty, ok := ent.QuantityValue(); ok {
				effective.MaxSensors = qty
			}
		}
		if ent, ok := resolved[itemMaxAssets]; ok {
			if qty, ok := ent.QuantityValue(); ok {
				effective.MaxAssets = qty
			}
		}
		if ent, ok := resolved[itemMaxUsers]; ok {
			if qty, ok := ent.QuantityValue(); ok {
				effective.MaxUsers = qty
			}
		}
		// RetentionDays is a non-pointer int; only override when the resolved
		// value is a concrete cap (an "unlimited" retention can't be
		// represented, so the tier value is kept).
		if ent, ok := resolved[itemRetentionDays]; ok {
			if qty, ok := ent.QuantityValue(); ok && qty != nil {
				effective.RetentionDays = *qty
			}
		}
		if ent, ok := resolved[itemComplianceFrameworksMax]; ok {
			if qty, ok := ent.QuantityValue(); ok {
				effective.ComplianceFrameworks = qty
			}
		}
		if ent, ok := resolved[itemIntegrationsMax]; ok {
			if qty, ok := ent.QuantityValue(); ok {
				effective.MaxIntegrations = qty
			}
		}
	}

	// Surface the tenant's currently-active per-tenant overrides truthfully.
	overrides, err := s.activeTenantOverrides(tenantID)
	if err != nil {
		log.Printf("admin-service: effective-limits overrides list failed for tenant %s: %v", tenantID, err)
		return
	}
	effective.Overrides = overrides
	effective.HasOverrides = len(overrides) > 0
}

// activeTenantOverrides maps the tenant's currently-effective
// tenant_entitlements rows into the EffectiveLimits override shape. "Active"
// mirrors the resolver: effective_from <= now AND (expires_at IS NULL OR
// expires_at > now). Future-scheduled and expired rows are excluded so the
// HasOverrides flag reflects what's actually in force.
func (s *TierService) activeTenantOverrides(tenantID uuid.UUID) ([]models.LimitOverride, error) {
	rows, err := NewEntitlementsService(s.db, s.bypassDB).ListTenantEntitlements(tenantID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	overrides := make([]models.LimitOverride, 0, len(rows))
	for _, te := range rows {
		var expiresAt *time.Time
		if te.ExpiresAt != nil {
			if t, perr := time.Parse(time.RFC3339, *te.ExpiresAt); perr == nil {
				expiresAt = &t
			}
		}
		if from, perr := time.Parse(time.RFC3339, te.EffectiveFrom); perr == nil && from.After(now) {
			continue // not yet effective
		}
		if expiresAt != nil && !expiresAt.After(now) {
			continue // already expired
		}

		var value interface{}
		if len(te.OverrideValue) > 0 {
			_ = json.Unmarshal(te.OverrideValue, &value)
		}
		var reason string
		if te.Reason != nil {
			reason = *te.Reason
		}

		overrides = append(overrides, models.LimitOverride{
			ID:           te.ID,
			OverrideType: te.ItemKind,
			LimitName:    te.ItemKey,
			Value:        value,
			IsPermanent:  expiresAt == nil,
			ExpiresAt:    expiresAt,
			Reason:       reason,
		})
	}
	return overrides, nil
}
