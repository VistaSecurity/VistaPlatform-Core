package agentconfig

// Bootstrapping a device's starting position from the device itself.
//
// Desired state is authoritative, but a device that enrolled before the
// control plane existed already HAS a configuration: the values in its own
// file. Resolve alone would answer that device with the built-in defaults —
// values nobody chose — and the first heartbeat would switch off a feature an
// operator had deliberately turned on in the file. That is the "reports success
// while doing nothing" shape from the other direction: the console would show a
// configuration that was never anyone's decision, and the device would obey it.
//
// So the first time a device reports what it is running, the values it is
// running become its own override, and the revision it is handed back describes
// what it is already doing. Nothing changes on that device until somebody
// changes it.

// BootstrapValues picks the settings that a first-reporting device should have
// recorded as its own override.
//
// A key is taken only when ALL of the following hold, and each condition is
// load-bearing:
//
//   - The key applies to this runtime. A fleet default is one document covering
//     both runtimes, and a device must not acquire an override for a setting it
//     has no concept of.
//   - Nothing is set for it at the fleet or device layer. An operator's value
//     is a decision; the device's is only a starting position, and a starting
//     position must never overwrite a decision.
//   - The device reported a value for it, and that value survives the
//     registry's own rules. A device is not a trusted source of configuration:
//     it is reporting, not asking, and a reported value that would be refused
//     from an operator is refused from a device too.
//   - The value DIFFERS from the built-in default. This is the condition that
//     keeps bootstrapping from quietly disabling fleet defaults: seeding a
//     device-level override for every setting would pin each device above the
//     fleet layer forever, so a fleet default set next week would reach nothing.
//     A device running the built-in default needs no override to keep running
//     it — Resolve already answers it with exactly that value.
//
// The result is empty for a device whose file says nothing unusual, which is
// most of them, and for a build too old to report what it is running.
//
// A setting carrying a confirmation requirement is NOT excluded, though nothing
// is confirmed here. Confirmation exists so that somebody acknowledges
// collection that BEGINS; nothing begins here — the device is already doing it,
// and the alternative is to leave the setting resolving to its default and push
// the device an instruction to stop, silently undoing what its operator
// configured. Recording what is true, where an operator can see and change it,
// is the better of the two.
func BootstrapValues(rt Runtime, fleet, device, running Values) Values {
	out := make(Values)
	if len(running) == 0 {
		return out
	}

	candidates := make(Values)
	for _, f := range FieldsFor(rt) {
		if v, ok := fleet[f.Key]; ok && !v.IsZero() {
			continue
		}
		if v, ok := device[f.Key]; ok && !v.IsZero() {
			continue
		}
		v, ok := running[f.Key]
		if !ok || v.IsZero() {
			continue
		}
		candidates[f.Key] = v
	}

	// Floors are raised here exactly as they are for an operator's save, so a
	// device reporting a below-floor interval is recorded as the value that
	// will actually be enforced rather than the one it typed.
	normalized, _ := Normalize(rt, candidates)
	for _, k := range normalized.Keys() {
		v := normalized[k]
		// Per key rather than in one pass: one unusable value from a device
		// must not cost the rest of its configuration.
		if err := Validate(rt, Values{k: v}); err != nil {
			continue
		}
		if f, ok := Registry[k]; ok && v.Equal(f.Default) {
			continue
		}
		out[k] = v
	}
	return out
}
