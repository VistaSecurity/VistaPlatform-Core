package identity

import "strings"

// canonicalSensorIdentity supports retained self-reports and older intake
// services that used agent_id for a sensor installation. Only an authoritative
// measurement of the issuing sensor itself qualifies; a passive observation or
// a device-agent report never changes namespace. Copy before editing so stored
// receipt evidence and concurrent callers keep their original values.
func canonicalSensorIdentity(obs Observation) Observation {
	if !obs.Admission.Authoritative || obs.Source.Kind != SourceMeasured {
		return obs
	}
	for i, id := range obs.Identifiers {
		if id.Kind == KindAgentID && obs.Source.Ref == "sensor:"+strings.TrimSpace(id.Value) {
			obs.Identifiers = append([]Identifier(nil), obs.Identifiers...)
			obs.Identifiers[i].Kind = KindSensorID
			break
		}
	}
	return obs
}
