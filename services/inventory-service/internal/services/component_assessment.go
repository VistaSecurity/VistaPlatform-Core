package services

// Unmeasured components ( W1.2, principle 2: unknown stays unknown).
//
// A producer that could not measure part of a configuration says so in
// raw_data: unmeasured_components = ["protocol_version"]. Device interrogation
// writes it for a TLS, DTLS or SSH configuration whose version no collector
// read — the collectors used to fill in "TLS 1.2" or "SSH-2.0" instead, and
// that invented version was linked, scored and shown as measured.
//
// An unmeasured protocol version is a partial assessment, held to the same
// rule as a partially resolved cipher string (cipher_assessment.go): a score
// of Medium or worse that the measured components support stands, anything
// lower is stored as unassessed (NULL) rather than claiming "Low" for a
// version nobody looked at; the configuration carries a "Partially assessed"
// risk factor; and the crypto producer records the gap as a limitation.

import (
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

const (
	// unmeasuredComponentsKey is the raw_data list of algorithm roles the
	// producer did not measure.
	unmeasuredComponentsKey = "unmeasured_components"
	// unmeasuredProtocolVersion is the role this file acts on.
	unmeasuredProtocolVersion = "protocol_version"
)

// rawDeclaresUnmeasured reports whether raw_data names role as unmeasured.
// The list arrives as []interface{} from JSON and as []string from Go callers.
func rawDeclaresUnmeasured(raw map[string]interface{}, role string) bool {
	for _, s := range unmeasuredRoles(raw) {
		if s == role {
			return true
		}
	}
	return false
}

// protocolVersionUnmeasured: the observation says its version was not
// measured AND ingest did not derive one either (an SSH banner in raw_data is
// a measurement inventory reads itself).
func protocolVersionUnmeasured(raw map[string]interface{}, version *string) bool {
	return version == nil && rawDeclaresUnmeasured(raw, unmeasuredProtocolVersion)
}

// annotateComponentAssessment returns raw with the unmeasured list made true
// for what is being stored: a protocol_version entry is dropped when ingest
// did derive a version, so the row never claims a gap it does not have. It
// copies rather than mutating the finding's map.
func annotateComponentAssessment(raw models.JSONB, version *string) (models.JSONB, bool) {
	if !rawDeclaresUnmeasured(raw, unmeasuredProtocolVersion) {
		return raw, false
	}
	if protocolVersionUnmeasured(raw, version) {
		return raw, true
	}
	out := make(models.JSONB, len(raw))
	for k, v := range raw {
		out[k] = v
	}
	var rest []string
	for _, role := range unmeasuredRoles(raw) {
		if role != unmeasuredProtocolVersion {
			rest = append(rest, role)
		}
	}
	if len(rest) == 0 {
		delete(out, unmeasuredComponentsKey)
	} else {
		out[unmeasuredComponentsKey] = rest
	}
	return out, false
}

func unmeasuredRoles(raw map[string]interface{}) []string {
	var out []string
	switch v := raw[unmeasuredComponentsKey].(type) {
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}

// unmeasuredVersionFactor is the risk factor shown for a configuration whose
// protocol version was not measured.
const unmeasuredVersionFactor = "Partially assessed: the protocol version was not measured; " +
	"a legacy version cannot be ruled out"
