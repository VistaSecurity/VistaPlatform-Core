// Package agentconfig is the desired-state contract for sensors and discovery
// agents: what an operator has asked a fleet member to be, how that resolves
// against tenant-wide defaults, and how to tell whether the device has actually
// become it.
//
// "Agents" is used in this package the way CLAUDE.md's vocabulary uses it —
// sensors and discovery agents together. Where the two genuinely differ, the
// field registry says so per [Runtime]; everything else is deliberately common.
//
// # Why one package for both runtimes
//
// sensor-manager and device-interrogation-service own different halves of one
// product, and the halves have already drifted apart once by being written
// twice (see the note above `agent_addresses` in schema.sql, which made the
// same call for the same reason). The settable fields, the inheritance rule and
// the applied/pending decision live here so that neither service can hold a
// private opinion about them.
//
// # What this package replaces
//
// Today a sensor's capture settings are not stored anywhere platform-side. The
// update-config endpoint takes them, queues a one-shot `update_config` command,
// and keeps NOTHING — so the platform cannot say what it asked for, only what
// the sensor last reported. If the command is missed there is no retry, and the
// console shows a value that never took effect. Discovery agents have neither
// the endpoint nor the command channel.
//
// Desired state fixes that by inverting the direction: the platform records what
// the device SHOULD be, the device reports what it IS, and the difference is
// computed rather than assumed. A missed check-in stops being a lost update and
// becomes, correctly, a device that has not converged yet.
//
// # Revisions, not generations
//
// Convergence is decided by comparing a content [Revision] — a hash of the
// effective values — not a counter the platform increments.
//
// A counter forces a fan-out: changing one tenant default would have to bump the
// generation of every device inheriting it, and any device missed by that sweep
// reads as up to date forever. A hash has no sweep. The effective values change,
// the revision changes with them, and every affected device disagrees with its
// reported revision on its next check-in without anything having to remember to
// tell it.
//
// # Constraints
//
//   - Pure Go, no CGO, no database, no HTTP. The standalone sensor must be able
//     to import this to interpret what it is handed (see CLAUDE.md on what the
//     sensor may depend on), and it cross-compiles with CGO_ENABLED=0.
//   - No platform coupling: no pool, no NATS, no tenant context type.
package agentconfig
