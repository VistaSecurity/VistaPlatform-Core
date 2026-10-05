package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/jobunits"
)

// The mirror into sensor_discoveries is what carries a discovery job's findings
// to inventory. It used to be gated on probeOpts["result_sink"] ==
// "sensor_discoveries", an option exactly one caller ever set, so every
// wizard-created job's findings reached inventory only if a browser posted them
// back. The work units mirror every finding (shared/jobunits); this pins the
// provenance stamp they write.
func TestMirrorMetadata_StampsProvenanceWithoutGating(t *testing.T) {
	data := map[string]interface{}{"cipher_suite": "TLS_AES_128_GCM_SHA256"}

	job := jobunits.MirrorMetadata(data, false, "00000000-0000-4000-8000-000000000002")
	if job["discovery_source"] != "discovery_job" {
		t.Fatalf("wizard/discovery job stamped %v, want discovery_job", job["discovery_source"])
	}
	if job["cipher_suite"] != "TLS_AES_128_GCM_SHA256" {
		t.Fatal("probe data was not carried into the mirrored metadata")
	}

	scan := jobunits.MirrorMetadata(data, true, "00000000-0000-4000-8000-000000000002")
	if scan["discovery_source"] != "active_scan" {
		t.Fatalf("active scan stamped %v, want active_scan", scan["discovery_source"])
	}

	// The caller's map must not be mutated — findings are also written to
	// discovery_findings from the same struct.
	if _, leaked := data["discovery_source"]; leaked {
		t.Fatal("MirrorMetadata mutated the caller's data map")
	}
}
