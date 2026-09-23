package entitlements

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
)

// RetentionItemKey is the billable item the platform retention cap replaces on
// an Enterprise install.
const RetentionItemKey = "retention_days"

// RetentionSettingKey is the platform_settings key holding the Enterprise
// data-retention cap. Its setting_value is a JSON number of days, or JSON null
// for unlimited. A missing row is unlimited too, which is the default an
// Enterprise install starts with (edition-licensing spec §1: "unlimited by
// default, optionally capped").
//
// This is the DATA retention cap only — how long a tenant's inventory and
// history may be kept. Log retention is a separate setting with its own spec
// (log-retention-separation), and nothing here sweeps data: the value
// is what the resolver reports as retention_days.
const RetentionSettingKey = "retention.max_days"

// RetentionMaxDaysLimit is the largest cap the setting accepts: 100 years,
// which is past any regulatory retention period and small enough that a typo
// of extra digits is refused rather than stored.
const RetentionMaxDaysLimit = 36500

// ErrInvalidRetention is returned by ValidateRetentionDays and
// ParseRetentionSetting for a value outside 1..RetentionMaxDaysLimit.
var ErrInvalidRetention = errors.New("entitlements: retention cap must be a whole number of days between 1 and 36500, or null for unlimited")

// ValidateRetentionDays checks a cap before it is stored. nil (unlimited) is
// always valid. Zero is refused on purpose: "retain nothing" is not a
// retention policy, and a zero written by a blank form field would read as
// "delete everything" to whatever later enforces it.
func ValidateRetentionDays(days *int) error {
	if days == nil {
		return nil
	}
	if *days < 1 || *days > RetentionMaxDaysLimit {
		return ErrInvalidRetention
	}
	return nil
}

// ParseRetentionSetting decodes a stored setting_value: a JSON number of days
// or JSON null. Anything else — a string, an object, a fraction, a number out
// of range — is an error.
func ParseRetentionSetting(raw []byte) (*int, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRetention, err)
	}
	if v == nil {
		return nil, nil
	}
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) {
		return nil, ErrInvalidRetention
	}
	days := int(f)
	if err := ValidateRetentionDays(&days); err != nil {
		return nil, err
	}
	return &days, nil
}

// EncodeRetentionSetting is the inverse of ParseRetentionSetting.
func EncodeRetentionSetting(days *int) []byte {
	if days == nil {
		return []byte("null")
	}
	return []byte(strconv.Itoa(*days))
}

// selectRetentionSQL reads the Enterprise retention cap. platform_settings is a
// global table readable by every service's pool.
const selectRetentionSQL = `SELECT setting_value FROM platform_settings WHERE setting_key = $1`

// readRetentionCap returns the stored cap, nil for unlimited.
//
// A malformed stored value is logged and read as unlimited rather than failing:
// this read happens inside the licence lookup, and an error there fails every
// feature gate closed on every request. Retention is not an access decision,
// the admin API validates every value it writes, and "unlimited" is the
// install's documented default — so a hand-edited bad row degrades to the
// default instead of taking the product down.
func readRetentionCap(ctx context.Context, q rowQueryer) (*int, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, selectRetentionSQL, RetentionSettingKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("entitlements: read retention setting: %w", err)
	}
	days, perr := ParseRetentionSetting(raw)
	if perr != nil {
		log.Printf("[entitlements] platform_settings %q holds %q, which is not a retention cap — treating as unlimited: %v", RetentionSettingKey, string(raw), perr)
		return nil, nil
	}
	return days, nil
}

// retentionValue renders a cap as a numeric entitlement value.
func retentionValue(days *int) json.RawMessage {
	if days == nil {
		return unlimitedValue
	}
	return json.RawMessage(`{"quantity": ` + strconv.Itoa(*days) + `}`)
}
