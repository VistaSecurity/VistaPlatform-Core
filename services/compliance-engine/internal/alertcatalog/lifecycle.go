package alertcatalog

// The two lifecycles a registry alert type can have (standards/alert-registry.yaml
// `lifecycle`).
const (
	// LifecycleStateful is the default: one row in the alerts table per
	// (tenant, type, subject) that opens, escalates and resolves.
	LifecycleStateful = "stateful"
	// LifecycleEvent is a one-shot notification: each raise is routed once and
	// no alerts row is written (object_changed — a change happened; nothing
	// stays open).
	LifecycleEvent = "event"
)
