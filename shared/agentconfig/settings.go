package agentconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Runtime is which kind of fleet member a setting applies to.
type Runtime string

const (
	RuntimeSensor Runtime = "sensor"
	RuntimeAgent  Runtime = "agent"
)

// Key names a setting. The string form is the wire and column spelling, and it
// matches what the device already reads from its own config file where one
// exists — `host_inventory_enabled` is the same key an operator types into
// agent-config.yaml today. Keeping them identical means the bootstrap file and
// the control plane cannot describe the same setting by two names.
type Key string

const (
	// Agent.
	KeyHostInventoryEnabled  Key = "host_inventory_enabled"
	KeyHostInventoryInterval Key = "host_inventory_interval_seconds"
	KeyPollInterval          Key = "poll_interval_seconds"
	KeyHeartbeatInterval     Key = "heartbeat_interval_seconds"

	// Sensor.
	KeyActiveProbing         Key = "active_probing"
	KeyNetworkDiscovery      Key = "network_discovery"
	KeyHostObservation       Key = "host_observation"
	KeyHostObservationWindow Key = "host_observation_window_seconds"
	KeyHostObservationDNS    Key = "host_observation_dns"
	KeyDedupTTLMinutes       Key = "dedup_ttl_minutes"
	KeyReportingInterval     Key = "reporting_interval_seconds"
	// KeyThirdPartyTLSEnrichment lets the sensor's TLS enricher actively
	// handshake with destinations that are NOT the tenant's own ( W5.13,
	// owner decision Q10). Off by default; see shared/probeconsent for what
	// "the tenant's own" means.
	KeyThirdPartyTLSEnrichment Key = "third_party_tls_enrichment"

	// Both.
	KeyLogLevel Key = "log_level"
)

// Kind is a setting's value type. There are three because there are three;
// resist adding a free-text kind, which is how unbounded operator input reaches
// a device.
type Kind string

const (
	KindBool Kind = "bool"
	KindInt  Kind = "int"
	KindEnum Kind = "enum"
)

// Apply says when a change takes effect on the device.
//
// This is display-bearing, not decoration: a setting the device can only adopt
// on restart must not show as "Applied" the moment it check in, or the console
// resumes lying about the thing this feature exists to stop it lying about.
type Apply string

const (
	// ApplyImmediate takes effect on the next check-in.
	ApplyImmediate Apply = "immediate"
	// ApplyOnRestart needs the process to restart. Host observation is the
	// standing example: the BPF capture filter is fixed when the interface
	// handle opens, so switching decoders on without reopening the handle
	// leaves them running and receiving nothing.
	ApplyOnRestart Apply = "restart"
)

// Field describes one setting.
type Field struct {
	Key      Key
	Runtimes []Runtime
	Kind     Kind
	Apply    Apply

	// Default is what the device does when nobody has said otherwise. It is
	// the SAME value the device's own config defaults to; a platform default
	// that disagreed with the binary's would make an unconfigured fleet
	// display a value it is not running.
	Default Value

	// Min, Max bound an int setting, inclusive.
	Min, Max int64
	// Floor raises rather than rejects a too-small int, mirroring the device
	// (the agent raises a sub-hour host-inventory interval and logs that it
	// did). Enforcing it here means the console shows what will actually run
	// instead of what was typed.
	Floor int64
	// Allowed lists an enum's values.
	Allowed []string

	// Confirm marks a setting an operator must confirm explicitly, with the
	// consequence named. Host-observation DNS carries one: an answers-only
	// decode still records which names a network resolved, which is a
	// materially different collection from "these devices are here" (§1a of
	// the feature spec — the confirmation is the condition on which that
	// setting became remotely manageable at all). Third-party TLS enrichment
	// carries one because turning it on sends traffic to parties who never
	// agreed to receive it.
	Confirm string

	// Label is the operator-facing name, for the rare setting whose key reads
	// badly when derived into words. Empty means "derive it from the key",
	// which is what the console does for every setting that has none.
	Label string

	// Description is operator-facing.
	Description string
}

// Registry is every settable field, keyed by Key.
var Registry = func() map[Key]Field {
	fields := []Field{
		{
			Key: KeyHostInventoryEnabled, Runtimes: []Runtime{RuntimeAgent},
			Kind: KindBool, Apply: ApplyImmediate, Default: Bool(false),
			Description: "Describe the host this agent runs on: OS, hardware, software, listening sockets and certificate stores.",
		},
		{
			Key: KeyHostInventoryInterval, Runtimes: []Runtime{RuntimeAgent},
			Kind: KindInt, Apply: ApplyImmediate, Default: Int(86400),
			Min: 3600, Max: 2592000, Floor: 3600,
			Description: "How often the agent re-describes its host. Below one hour is raised to one hour.",
		},
		{
			Key: KeyPollInterval, Runtimes: []Runtime{RuntimeAgent},
			Kind: KindInt, Apply: ApplyImmediate, Default: Int(30),
			Min: 10, Max: 3600,
			Description: "How often the agent asks the platform for work.",
		},
		{
			Key: KeyHeartbeatInterval, Runtimes: []Runtime{RuntimeAgent},
			Kind: KindInt, Apply: ApplyImmediate, Default: Int(60),
			Min: 30, Max: 3600,
			Description: "How often the agent reports that it is alive.",
		},
		{
			Key: KeyActiveProbing, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindBool, Apply: ApplyImmediate, Default: Bool(true),
			Description: "Let the sensor probe a host it has observed, to fill in what passive capture could not see. " +
				"Only your own addresses are probed unless third-party TLS enrichment is also on.",
		},
		{
			Key: KeyNetworkDiscovery, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindBool, Apply: ApplyImmediate, Default: Bool(true),
			Description: "Let the sensor run discovery jobs the platform assigns to it.",
		},
		{
			Key: KeyHostObservation, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindBool, Apply: ApplyOnRestart, Default: Bool(true),
			Description: "Decode ARP, DHCP, mDNS, NetBIOS, LLDP and CDP into host identity.",
		},
		{
			Key: KeyHostObservationWindow, Runtimes: []Runtime{RuntimeSensor},
			// ApplyOnRestart, like its two siblings, and for a related reason:
			// the coalescing window is fixed when the host-observation pipeline
			// is constructed, which happens once, when the capture handle
			// opens. Nothing rebuilds it and the coalescer has no setter, so a
			// change lands in a field nobody reads again.
			//
			// This said ApplyImmediate until review caught it. The sensor
			// duly wrote the value and reported success, and the console showed
			// "Applied" for a merge window that was not in force — the exact
			// dishonesty the restart state exists to prevent, on the sibling of
			// the two settings that already declare it.
			Kind: KindInt, Apply: ApplyOnRestart, Default: Int(60),
			Min: 10, Max: 600,
			Description: "How long observations about one host are merged before being reported.",
		},
		{
			Key: KeyHostObservationDNS, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindBool, Apply: ApplyOnRestart, Default: Bool(false),
			Confirm: "Turning this on records which names this network resolved. " +
				"Only DNS answers are decoded, never the questions — but an answer names what was asked.",
			Description: "Decode unicast DNS answers on UDP 53 into host identity.",
		},
		{
			Key: KeyDedupTTLMinutes, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindInt, Apply: ApplyImmediate, Default: Int(60),
			Min: 1, Max: 1440,
			Description: "How long the sensor rests before re-reporting the same observation.",
		},
		{
			Key: KeyReportingInterval, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindInt, Apply: ApplyImmediate, Default: Int(300),
			Min: 30, Max: 3600,
			Description: "How often the sensor sends what it has collected.",
		},
		{
			// Off by default, and a consent rather than a tuning knob: with it
			// off the enricher handshakes only with the tenant's own address
			// space — private addresses, declared network segments and elevated
			// connections — and every other destination is recorded passively
			// and left alone. The confirmation names the consequence because it
			// is one a third party, not the tenant, experiences.
			Key: KeyThirdPartyTLSEnrichment, Runtimes: []Runtime{RuntimeSensor},
			Kind: KindBool, Apply: ApplyImmediate, Default: Bool(false),
			Label: "Actively enrich third-party TLS connections",
			Confirm: "Sensors will open their own TLS connections to external services your network talks to — " +
				"vendors, SaaS and other third parties — to read their certificates. Those third parties may see these connections.",
			Description: "Off by default. When on, sensors actively connect to external TLS services your network talks to, " +
				"to read their certificates. Third parties may see these connections.",
		},
		{
			Key: KeyLogLevel, Runtimes: []Runtime{RuntimeSensor, RuntimeAgent},
			Kind: KindEnum, Apply: ApplyImmediate, Default: Text("info"),
			Allowed:     []string{"error", "warn", "info", "debug"},
			Description: "How much the device logs locally.",
		},
	}
	m := make(map[Key]Field, len(fields))
	for _, f := range fields {
		m[f.Key] = f
	}
	return m
}()

// FieldsFor returns the fields that apply to a runtime, in key order so the
// output is stable for hashing and for display.
func FieldsFor(rt Runtime) []Field {
	var out []Field
	for _, f := range Registry {
		for _, r := range f.Runtimes {
			if r == rt {
				out = append(out, f)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// AppliesTo reports whether a key is settable on a runtime.
func AppliesTo(k Key, rt Runtime) bool {
	f, ok := Registry[k]
	if !ok {
		return false
	}
	for _, r := range f.Runtimes {
		if r == rt {
			return true
		}
	}
	return false
}

// Value is one setting's value: exactly one of the three is set.
//
// A struct rather than `any` so a caller cannot put an arbitrary type in, and
// so "no value" (every pointer nil) is representable and distinct from false or
// zero — the distinction the whole inheritance model rests on.
type Value struct {
	B *bool
	I *int64
	S *string
}

func Bool(b bool) Value   { return Value{B: &b} }
func Int(i int64) Value   { return Value{I: &i} }
func Text(s string) Value { return Value{S: &s} }

// IsZero reports that no value is set.
func (v Value) IsZero() bool { return v.B == nil && v.I == nil && v.S == nil }

// Equal compares by content. Two Values holding the same scalar are equal even
// though their pointers differ, which is what every comparison in this package
// actually means.
func (v Value) Equal(o Value) bool {
	switch {
	case v.B != nil || o.B != nil:
		return v.B != nil && o.B != nil && *v.B == *o.B
	case v.I != nil || o.I != nil:
		return v.I != nil && o.I != nil && *v.I == *o.I
	case v.S != nil || o.S != nil:
		return v.S != nil && o.S != nil && *v.S == *o.S
	}
	return true
}

func (v Value) String() string {
	switch {
	case v.B != nil:
		return fmt.Sprintf("%t", *v.B)
	case v.I != nil:
		return fmt.Sprintf("%d", *v.I)
	case v.S != nil:
		return *v.S
	}
	return ""
}

// MarshalJSON writes the bare scalar, so a Values map serializes as the obvious
// object — {"host_inventory_enabled": true, "dedup_ttl_minutes": 60} — rather
// than as this struct. The wire form is read by operators in logs and by the
// device itself; it should look like configuration, not like an encoding.
func (v Value) MarshalJSON() ([]byte, error) {
	switch {
	case v.B != nil:
		return json.Marshal(*v.B)
	case v.I != nil:
		return json.Marshal(*v.I)
	case v.S != nil:
		return json.Marshal(*v.S)
	}
	return []byte("null"), nil
}

// ErrUnsupportedValue is returned for a JSON value that is not a bool, a whole
// number or a string.
var ErrUnsupportedValue = errors.New("agentconfig: value must be a boolean, a whole number or a string")

func (v *Value) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*v = Value{}
		return nil
	}
	var anyv any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&anyv); err != nil {
		return err
	}
	switch t := anyv.(type) {
	case bool:
		*v = Bool(t)
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			// A fractional number is not a rounding problem to paper over:
			// every int setting here is a count of seconds or minutes, and
			// silently truncating 0.5 would store an interval nobody asked
			// for.
			return fmt.Errorf("agentconfig: %q is not a whole number: %w", t.String(), ErrUnsupportedValue)
		}
		*v = Int(i)
	case string:
		*v = Text(t)
	default:
		return ErrUnsupportedValue
	}
	return nil
}

// Values is a set of settings. A key that is absent is not set — it is NOT the
// same as a key set to false or zero, and the two must stay distinguishable all
// the way to the database, or "inherit the fleet default" collapses into
// "explicitly off".
type Values map[Key]Value

// Clone returns a copy, so a caller cannot mutate a stored map through a
// returned reference.
func (v Values) Clone() Values {
	out := make(Values, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out
}

// Keys returns the keys in sorted order.
func (v Values) Keys() []Key {
	out := make([]Key, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ExchangeReport is what a device sends about its own configuration state on
// check-in. Every field is optional: a build older than desired state sends
// none of them, and an empty revision reads as "this device does not report its
// configuration", which is true and is a distinct state from silence.
type ExchangeReport struct {
	ConfigRevision string            `json:"config_revision"`
	ConfigFailures map[string]string `json:"config_failures"`
	PendingRestart []string          `json:"config_pending_restart"`

	// Running is what the device says its managed settings are set to right
	// now — the position it starts from, which for a device that enrolled
	// before the control plane existed is whatever its own file says.
	//
	// ABSENT means "this build does not report what it is running", not "it is
	// running nothing". The distinction decides whether the platform may adopt
	// these values as the device's starting position (see BootstrapValues), so
	// an older device must not be read as reporting an empty configuration —
	// that would bootstrap it to defaults it never chose.
	Running Values `json:"config_running,omitempty"`
}

// ExchangePayload is what the platform sends back: the revision a device should
// be running and the values that make it up.
type ExchangePayload struct {
	Revision string `json:"revision"`
	Values   Values `json:"values"`
	// RestartRequestedAt is when an operator last asked this device to restart,
	// on the PLATFORM's clock, zero when never. It is for display — "requested
	// 5 minutes ago" — and a device must NOT compare it against its own clock.
	//
	// Deliberately outside Values and outside the revision: a restart is not a
	// setting, and hashing it would leave every device that was ever restarted
	// permanently disagreeing with its own desired state.
	RestartRequestedAt time.Time `json:"restart_requested_at,omitempty"`
	// RestartRequestAgeSeconds is how long ago that was, measured entirely on
	// the platform's clock. A device restarts when its own uptime exceeds it.
	//
	// This is the field the DECISION uses, and it exists because the timestamp
	// cannot safely make it: comparing a platform timestamp against a device's
	// start time loops forever on a host whose clock disagrees. Two intervals,
	// each measured on the clock that produced it, cancel the offset out — see
	// ShouldRestart.
	RestartRequestAgeSeconds int64 `json:"restart_request_age_seconds,omitempty"`
}
