package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// PlatformConfig represents public platform configuration
type PlatformConfig struct {
	PlatformName         string  `json:"platform_name"`
	PlatformLogoURL      *string `json:"platform_logo_url,omitempty"`
	PlatformLoginLogoURL *string `json:"platform_login_logo_url,omitempty"`
	PlatformFaviconURL   *string `json:"platform_favicon_url,omitempty"`
	// SignupEnabled tells the public /signup page whether self-service
	// sign-up is open. Enforcement lives in the register handlers;
	// this flag only controls what the page renders.
	SignupEnabled bool `json:"signup_enabled"`
}

// platformSettingsStore is the narrow read interface the public-config handler
// depends on. The concrete repository hits platform_settings; the contract test
// drives a stub so the handler can be exercised without a database.
type platformSettingsStore interface {
	// GetPlatformSetting returns the raw JSON setting_value for setting_key, or
	// an error (e.g. sql.ErrNoRows) when the key is absent.
	GetPlatformSetting(key string) ([]byte, error)
}

// platformSettingsRepository is the production platformSettingsStore backed by
// *sql.DB. The SQL is moved verbatim from the previous inline handler, with the
// three identical per-key reads collapsed into one parameterized lookup.
type platformSettingsRepository struct{ db *sql.DB }

func (r *platformSettingsRepository) GetPlatformSetting(key string) ([]byte, error) {
	var v []byte
	err := r.db.QueryRow(`
		SELECT setting_value
		FROM platform_settings
		WHERE setting_key = $1
		LIMIT 1
	`, key).Scan(&v)
	return v, err
}

// GetPublicPlatformConfig handles GET /platform/config - Get public platform configuration
// This endpoint does not require authentication and returns platform branding info
func GetPublicPlatformConfig(db *sql.DB) gin.HandlerFunc {
	return getPublicPlatformConfigWithStore(&platformSettingsRepository{db: db})
}

// getPublicPlatformConfigWithStore is the store-backed handler core. Each
// setting is best-effort: a read or unmarshal failure leaves the built-in
// default in place (the branding is cosmetic and must never fail the call).
func getPublicPlatformConfigWithStore(store platformSettingsStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Default config
		config := PlatformConfig{
			PlatformName:  "Vista Platform",
			SignupEnabled: true,
		}

		if b, err := store.GetPlatformSetting("registration_enabled"); err == nil {
			var enabled bool
			if json.Unmarshal(b, &enabled) == nil {
				config.SignupEnabled = enabled
			}
		}

		if b, err := store.GetPlatformSetting("platform_name"); err == nil {
			var platformName string
			if json.Unmarshal(b, &platformName) == nil && platformName != "" {
				config.PlatformName = platformName
			}
		}

		if b, err := store.GetPlatformSetting("platform_logo_url"); err == nil {
			var platformLogoURL string
			if json.Unmarshal(b, &platformLogoURL) == nil && platformLogoURL != "" {
				config.PlatformLogoURL = &platformLogoURL
			}
		}

		if b, err := store.GetPlatformSetting("platform_login_logo_url"); err == nil {
			var platformLoginLogoURL string
			if json.Unmarshal(b, &platformLoginLogoURL) == nil && platformLoginLogoURL != "" {
				config.PlatformLoginLogoURL = &platformLoginLogoURL
			}
		}

		if b, err := store.GetPlatformSetting("platform_favicon_url"); err == nil {
			var platformFaviconURL string
			if json.Unmarshal(b, &platformFaviconURL) == nil && platformFaviconURL != "" {
				config.PlatformFaviconURL = &platformFaviconURL
			}
		}

		c.JSON(http.StatusOK, config)
	}
}
