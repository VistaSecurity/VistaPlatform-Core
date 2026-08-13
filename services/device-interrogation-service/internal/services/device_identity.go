package services

import "fmt"

// deviceIdentitySetClauses builds the SQL SET clauses + positional args for
// writing a discovered device identity (vendor/model/firmware/serial) back
// onto a `devices` row, starting the placeholder numbering at startIdx.
//
// Only non-empty fields produce a clause: an interrogator that doesn't
// populate a given field (e.g. a vendor whose API has no firmware endpoint)
// must not blank out a value a prior, more complete run recorded. Shared by
// ResultProcessor.updateDeviceIdentity (the discovery-processor/agent-worker
// path) and DeviceInterrogationService.updateDeviceIdentity (the direct
// device-interrogation-service path, added for L-7 — firmware discovered by
// that path used to never reach the devices table at all) so both apply the
// same rule instead of maintaining it twice.
func deviceIdentitySetClauses(vendor, model, firmware, serial string, startIdx int) (clauses []string, args []interface{}) {
	idx := startIdx
	add := func(column, value string) {
		clauses = append(clauses, fmt.Sprintf("%s = $%d", column, idx))
		args = append(args, value)
		idx++
	}
	if vendor != "" {
		add("vendor", vendor)
	}
	if model != "" {
		add("model", model)
	}
	if firmware != "" {
		add("firmware_version", firmware)
	}
	if serial != "" {
		add("serial_number", serial)
	}
	return clauses, args
}
