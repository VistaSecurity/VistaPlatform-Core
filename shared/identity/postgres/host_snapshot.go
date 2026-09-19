package postgres

import "github.com/google/uuid"

// HostSnapshotLockKey serializes multi-transaction host snapshots with asset
// merges. It sorts before asset lifecycle keys; acquire all session locks in one
// WithSessionAdvisoryLocks call before opening a main-pool transaction.
func HostSnapshotLockKey(tenant uuid.UUID) string {
	return "0-host-inventory-snapshot:" + tenant.String()
}
