package handlers

// Settings → License & Usage (edition-licensing spec, PR 2).
//
//	GET /admin/license            the install's licence, as admin-service's
//	                              reconciler recorded it in platform_license,
//	                              plus the install id from platform_install.
//	GET /admin/license/retention  the Enterprise data-retention cap.
//	PUT /admin/license/retention  set it (audited).
//
// CORE code, deliberately. A Core build has no reconciler and so never has a
// platform_license row, and that is exactly what the page needs to say: "Vista
// Platform Core — no licence installed". Reading the row needs no Enterprise
// code and no key material; verifying the token that produced it happens in
// ee/edition and nowhere else.
//
// What this never returns: the token, or anything derived from it that would
// let someone reconstruct or replay it. token_sha256 stays in the table.
//
// Retention is the DATA retention cap only (how long tenant inventory and
// history is kept). Log retention is's, and nothing here deletes data:
// the value is what the entitlement resolver reports as retention_days on an
// Enterprise install. The setting is stored on every edition, but only an
// Enterprise licence reads it — MSP retention is per plan, Core's is unchanged —
// so the response says whether it currently applies.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// LicenseInfo is the wire shape of GET /admin/license.
type LicenseInfo struct {
	// Edition is what the install runs as NOW: core, enterprise or msp. An
	// expired licence is core here, as it is in every gate.
	Edition entitlements.Edition `json:"edition"`
	// DisplayName is the edition's product name.
	DisplayName string `json:"display_name"`
	// Status: none (no licence recorded), active, or expired (a row is still
	// recorded but its expiry has passed; the reconciler removes it on its
	// next pass).
	Status string `json:"status"`
	// LicensedEdition is the edition the recorded licence names, even when
	// expired. Null with no licence.
	LicensedEdition *string    `json:"licensed_edition"`
	Licensee        *string    `json:"licensee"`
	Subject         *string    `json:"subject"`
	IssuedAt        *time.Time `json:"issued_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	// DaysLeft is whole days until expiry, rounded up, never negative. Null
	// with no licence.
	DaysLeft   *int       `json:"days_left"`
	MaxTenants *int       `json:"max_tenants"`
	GraceDays  *int       `json:"grace_days"`
	VerifiedAt *time.Time `json:"verified_at"`
	// InstallID identifies this installation (platform_install). An MSP
	// licence is minted for one install id; the operator sends this value to
	// Vista Security to get one. Null until admin-service first records it.
	InstallID *string `json:"install_id"`
	// BoundInstallID is the install id the licence itself carries, if any.
	BoundInstallID *string `json:"bound_install_id"`
}

// RetentionSetting is the wire shape of GET/PUT /admin/license/retention.
type RetentionSetting struct {
	// MaxDays is the cap in days; null means unlimited (the default).
	MaxDays *int `json:"max_days"`
	// Applies reports whether the cap is in force: true only on an active
	// Enterprise licence.
	Applies bool `json:"applies"`
}

type licenseRow struct {
	Subject, Edition, Licensee string
	IssuedAt, VerifiedAt       sql.NullTime
	ExpiresAt                  time.Time
	MaxTenants, GraceDays      sql.NullInt64
	BoundInstallID             sql.NullString
}

// licenseStore is the data seam, so the contract tests run without Postgres.
type licenseStore interface {
	// ReadLicense returns the platform_license row, or nil when there is none.
	ReadLicense(ctx context.Context) (*licenseRow, error)
	// InstallID returns platform_install.install_id, or "" when not recorded.
	InstallID(ctx context.Context) (string, error)
	// ReadRetention returns the stored setting_value, or nil when unset.
	ReadRetention(ctx context.Context) ([]byte, error)
	WriteRetention(ctx context.Context, value []byte, updatedBy *uuid.UUID) error
	// FlushLicense drops the cached licence (and with it the cached retention
	// cap) so this process sees a change at once rather than after the cache
	// TTL. Other services pick it up within entitlements.LicenseCacheTTL.
	FlushLicense()
}

type licenseRepository struct{ db *sql.DB }

// newLicenseStore is the production store. The reads work on the app pool
// (platform_license and platform_install are SELECT-only for crypto_app, which
// is all they need). WriteRetention does NOT: the schema's
// guard_platform_retention_setting trigger lets only the bypass role or the
// owner write platform_settings 'retention.max_days', so UpdateRetention must
// be given the bypass pool (server.go does).
func newLicenseStore(db *sql.DB) licenseStore { return &licenseRepository{db: db} }

func (r *licenseRepository) ReadLicense(ctx context.Context) (*licenseRow, error) {
	var row licenseRow
	err := r.db.QueryRowContext(ctx, `
		SELECT subject, edition, licensee, issued_at, expires_at, max_tenants, grace_days,
		       install_id::text, verified_at
		FROM platform_license LIMIT 1`).Scan(
		&row.Subject, &row.Edition, &row.Licensee, &row.IssuedAt, &row.ExpiresAt,
		&row.MaxTenants, &row.GraceDays, &row.BoundInstallID, &row.VerifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *licenseRepository) InstallID(ctx context.Context) (string, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT install_id::text FROM platform_install LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (r *licenseRepository) ReadRetention(ctx context.Context) ([]byte, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT setting_value FROM platform_settings WHERE setting_key = $1`,
		entitlements.RetentionSettingKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func (r *licenseRepository) WriteRetention(ctx context.Context, value []byte, updatedBy *uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_settings (setting_key, setting_value, description, updated_by, updated_at)
		VALUES ($1, $2::jsonb, 'Enterprise data-retention cap in days; null = unlimited.', $3, NOW())
		ON CONFLICT (setting_key) DO UPDATE SET
			setting_value = EXCLUDED.setting_value,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()`,
		entitlements.RetentionSettingKey, string(value), updatedBy)
	return err
}

func (r *licenseRepository) FlushLicense() { entitlements.FlushLicenseCache() }

// buildLicenseInfo turns the stored row into the wire shape at `now`.
func buildLicenseInfo(row *licenseRow, installID string, now time.Time) LicenseInfo {
	info := LicenseInfo{Edition: entitlements.EditionCore, DisplayName: entitlements.PlanDisplayNameCore, Status: "none"}
	if installID != "" {
		info.InstallID = &installID
	}
	if row == nil {
		return info
	}
	lic := &entitlements.License{Edition: entitlements.Edition(row.Edition), ExpiresAt: row.ExpiresAt}
	info.Edition = lic.EffectiveEdition(now)
	info.Status = "expired"
	if lic.Active(now) {
		info.Status = "active"
	}
	switch info.Edition {
	case entitlements.EditionEnterprise:
		info.DisplayName = entitlements.PlanDisplayNameEnterprise
	case entitlements.EditionMSP:
		info.DisplayName = entitlements.EditionDisplayNameMSP
	}
	info.LicensedEdition = strPtr(row.Edition)
	if row.Licensee != "" {
		info.Licensee = strPtr(row.Licensee)
	}
	info.Subject = strPtr(row.Subject)
	exp := row.ExpiresAt
	info.ExpiresAt = &exp
	days := int(math.Ceil(row.ExpiresAt.Sub(now).Hours() / 24))
	if days < 0 {
		days = 0
	}
	info.DaysLeft = &days
	if row.IssuedAt.Valid {
		t := row.IssuedAt.Time
		info.IssuedAt = &t
	}
	if row.VerifiedAt.Valid {
		t := row.VerifiedAt.Time
		info.VerifiedAt = &t
	}
	if row.MaxTenants.Valid {
		v := int(row.MaxTenants.Int64)
		info.MaxTenants = &v
	}
	if row.GraceDays.Valid {
		v := int(row.GraceDays.Int64)
		info.GraceDays = &v
	}
	if row.BoundInstallID.Valid && row.BoundInstallID.String != "" {
		info.BoundInstallID = strPtr(row.BoundInstallID.String)
	}
	return info
}

func strPtr(s string) *string { return &s }

// GetLicense handles GET /admin/license.
func GetLicense(db *sql.DB) gin.HandlerFunc { return getLicenseWithStore(newLicenseStore(db)) }

func getLicenseWithStore(store licenseStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		row, err := store.ReadLicense(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read licence status"})
			return
		}
		installID, err := store.InstallID(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read licence status"})
			return
		}
		c.JSON(http.StatusOK, buildLicenseInfo(row, installID, time.Now()))
	}
}

// retentionApplies reports whether the Enterprise cap is in force.
func retentionApplies(ctx context.Context, store licenseStore) (bool, error) {
	row, err := store.ReadLicense(ctx)
	if err != nil || row == nil {
		return false, err
	}
	lic := &entitlements.License{Edition: entitlements.Edition(row.Edition), ExpiresAt: row.ExpiresAt}
	return lic.EffectiveEdition(time.Now()) == entitlements.EditionEnterprise, nil
}

// GetRetention handles GET /admin/license/retention.
func GetRetention(db *sql.DB) gin.HandlerFunc { return getRetentionWithStore(newLicenseStore(db)) }

func getRetentionWithStore(store licenseStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		raw, err := store.ReadRetention(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the retention setting"})
			return
		}
		var days *int
		if raw != nil {
			// A malformed stored value reads as unlimited, exactly as the
			// resolver reads it, so this page never shows a cap that is not
			// the one in force.
			if days, err = entitlements.ParseRetentionSetting(raw); err != nil {
				days = nil
			}
		}
		applies, err := retentionApplies(ctx, store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read licence status"})
			return
		}
		c.JSON(http.StatusOK, RetentionSetting{MaxDays: days, Applies: applies})
	}
}

// UpdateRetention handles PUT /admin/license/retention. Body: {"max_days": N}
// or {"max_days": null}. The key is required — an empty body must not read as
// "unlimited". bypassDB must be the bypass pool: the setting is writable only
// by the bypass role or the owner (guard_platform_retention_setting).
func UpdateRetention(bypassDB *sql.DB) gin.HandlerFunc {
	return updateRetentionWithStore(newLicenseStore(bypassDB))
}

func updateRetentionWithStore(store licenseStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		var body map[string]json.RawMessage
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		rawDays, ok := body["max_days"]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "max_days is required (a number of days, or null for unlimited)"})
			return
		}
		days, err := entitlements.ParseRetentionSetting(rawDays)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": entitlements.ErrInvalidRetention.Error()})
			return
		}

		previousRaw, err := store.ReadRetention(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the retention setting"})
			return
		}
		var previous *int
		if previousRaw != nil {
			previous, _ = entitlements.ParseRetentionSetting(previousRaw)
		}

		var actor *uuid.UUID
		if id, perr := uuid.Parse(c.GetString("userID")); perr == nil {
			actor = &id
		}
		if err := store.WriteRetention(ctx, entitlements.EncodeRetentionSetting(days), actor); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the retention setting"})
			return
		}
		store.FlushLicense()

		applies, err := retentionApplies(ctx, store)
		if err != nil {
			applies = false
		}
		if !sameDays(previous, days) {
			recordPlatformAudit(c, PlatformAuditEntry{
				EventType:     "platform.retention_cap_changed",
				Action:        "update",
				EventCategory: "config",
				ResourceType:  "platform_setting",
				Metadata: map[string]interface{}{
					"setting":           entitlements.RetentionSettingKey,
					"previous_max_days": daysForAudit(previous),
					"max_days":          daysForAudit(days),
					"applies":           applies,
				},
			})
		}
		c.JSON(http.StatusOK, RetentionSetting{MaxDays: days, Applies: applies})
	}
}

func sameDays(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// daysForAudit renders a cap for the audit metadata: the number, or the string
// "unlimited" (an explicit value, so a reader can tell it from a missing key).
func daysForAudit(d *int) interface{} {
	if d == nil {
		return "unlimited"
	}
	return *d
}
