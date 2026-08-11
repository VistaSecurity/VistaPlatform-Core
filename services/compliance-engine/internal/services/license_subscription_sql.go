package services

// Predicates for tenant_framework_licenses rows that grant access:
// active status and not past subscription_expires_at (NULL = perpetual).
const (
	sqlActiveSubscription    = `subscription_status = 'active' AND (subscription_expires_at IS NULL OR subscription_expires_at > NOW())`
	sqlActiveSubscriptionTfl = `tfl.subscription_status = 'active' AND (tfl.subscription_expires_at IS NULL OR tfl.subscription_expires_at > NOW())`
)
