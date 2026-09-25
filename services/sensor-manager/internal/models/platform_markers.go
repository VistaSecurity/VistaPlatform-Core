package models

import "strings"

// Platform identity markers ( W2.2, review B1).
//
// A platform-managed sensor — the tenant's "Platform Discovery Sensor" and
// "Platform Device Interrogation Agent" rows — was recognised across the
// codebase by the `system` / `platform` tags and by `platform = 'platform'`.
// Every one of those used to be settable by a TENANT: registration copied the
// tags and platform from the sensor's own request, and PUT /sensors/:id/config
// replaced the tags wholesale. A tenant sensor could therefore pass as the
// platform's device-interrogation sensor, whose rows inventory trusts to name
// the device they belong to.
//
// These values are now reserved for the platform's own provisioning paths (the
// tenant-creation trigger, seed.sql, and the bootstrap-mTLS auto-registration
// in auto_registration.go). Every tenant-originated path strips them. The
// authoritative marker for trust checks is the sensors.platform_managed column,
// which no tenant path writes at all; the tags remain for display.
//
// The `device_interrogation` PROFILE is deliberately not reserved: tenants mint
// registration keys with it for their own device agents (frontend-v2
// sensor-modals.tsx PROFILE_BY_KIND), so it is not, on its own, a claim to be
// the platform.

// ReservedPlatformTags are the tags only the platform may put on a sensor.
var ReservedPlatformTags = []string{"system", "platform"}

// ReservedPlatformName is the `platform` column value only the platform's own
// sensors carry.
const ReservedPlatformName = "platform"

// IsReservedPlatformTag reports whether tag is a platform-only marker.
func IsReservedPlatformTag(tag string) bool {
	t := strings.ToLower(strings.TrimSpace(tag))
	for _, r := range ReservedPlatformTags {
		if t == r {
			return true
		}
	}
	return false
}

// StripReservedTags returns tags without any platform-only marker. Used on
// every tenant-originated write of a sensor's or pending registration's tags.
// A nil input stays nil so "not supplied" is not turned into "cleared".
func StripReservedTags(tags []string) []string {
	if tags == nil {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if !IsReservedPlatformTag(t) {
			out = append(out, t)
		}
	}
	return out
}

// ReplaceTenantTags is a tenant's tag update applied to a sensor that already
// has tags: the requested tags minus the reserved ones, plus whatever reserved
// tags the sensor ALREADY carries. A tenant can neither add a platform marker
// nor strip one from the platform's own sensor through this path.
func ReplaceTenantTags(existing, requested []string) []string {
	out := StripReservedTags(requested)
	if out == nil {
		out = []string{}
	}
	for _, t := range existing {
		if IsReservedPlatformTag(t) {
			out = append(out, t)
		}
	}
	return out
}

// TenantPlatformName is the platform value a tenant-registered sensor is
// stored with: whatever it reported, unless that is the platform's own marker.
func TenantPlatformName(platform string) string {
	if strings.EqualFold(strings.TrimSpace(platform), ReservedPlatformName) {
		return "unknown"
	}
	return platform
}
