package cryptoassess

import (
	"slices"
	"testing"
)

// An unmeasured protocol version is a limitation of the judgment (
// W1.2): the finding evidence then says reassessment is required instead of
// reading as a complete assessment.
func TestJudge_UnmeasuredVersionIsALimitation(t *testing.T) {
	j := Configuration{Suite: "ECDHE-RSA-AES256-GCM-SHA384", VersionUnmeasured: true}.Judge()
	if !slices.Contains(j.Limitations, "protocol version was not measured") {
		t.Errorf("limitations %v lack the unmeasured version", j.Limitations)
	}
	e := map[string]any{}
	j.AddEvidence(e)
	if e["reassessment_required"] != true {
		t.Errorf("reassessment_required = %v, want true", e["reassessment_required"])
	}
	measured := Configuration{Version: "TLS 1.2", Suite: "ECDHE-RSA-AES256-GCM-SHA384", VersionUnmeasured: true}.Judge()
	if slices.Contains(measured.Limitations, "protocol version was not measured") {
		t.Errorf("a stated version is reported unmeasured: %v", measured.Limitations)
	}
}
