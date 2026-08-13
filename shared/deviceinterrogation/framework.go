package deviceinterrogation

import "fmt"

// Registry maps device_type strings to the interrogator that handles them.
// Both runtimes build a Registry via NewRegistry and dispatch through it, so
// the set of supported device types is defined in exactly one place.
type Registry struct {
	interrogators map[string]DeviceInterrogator
}

// NewRegistry returns a Registry pre-populated with every built-in
// interrogator. Callers that need a device-specific construction (e.g. an SSH
// or HTTP prober configured per-target) can still build those directly; the
// vendor REST/CLI clients here are stateless w.r.t. the target until
// Interrogate is called, so a shared registry instance is safe to reuse.
func NewRegistry() *Registry {
	r := &Registry{interrogators: make(map[string]DeviceInterrogator)}
	r.Register(&FortinetInterrogator{})
	r.Register(&CiscoInterrogator{})
	r.Register(&PaloAltoInterrogator{})
	r.Register(&F5Interrogator{})
	r.Register(&UnifiInterrogator{})
	r.Register(&DatabaseInterrogator{})
	r.Register(&SNMPInterrogator{})
	r.Register(&HTTPInterrogator{})
	return r
}

// Register adds an interrogator under each device type it supports.
func (r *Registry) Register(interrogator DeviceInterrogator) {
	for _, deviceType := range interrogator.SupportedDeviceTypes() {
		r.interrogators[deviceType] = interrogator
	}
}

// Get returns the interrogator for a device type, or an error if none is
// registered.
//
// The returned interrogator is wrapped so its result is scrubbed of secret
// material before any caller sees it (see redact.go). Dispatching through the
// Registry is therefore the ONLY supported way to run an interrogation —
// reaching past it to a bare interrogator skips redaction.
func (r *Registry) Get(deviceType string) (DeviceInterrogator, error) {
	interrogator, ok := r.interrogators[deviceType]
	if !ok {
		return nil, fmt.Errorf("no interrogator found for device type: %s", deviceType)
	}
	return sanitizingInterrogator{inner: interrogator}, nil
}

// SupportedDeviceTypes returns every registered device type.
func (r *Registry) SupportedDeviceTypes() []string {
	types := make([]string, 0, len(r.interrogators))
	for deviceType := range r.interrogators {
		types = append(types, deviceType)
	}
	return types
}
