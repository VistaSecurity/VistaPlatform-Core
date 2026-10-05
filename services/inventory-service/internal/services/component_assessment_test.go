package services

import (
	"slices"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// Unknown stays unknown ( W1.2), the pure half: the marker is read from
// both JSON and Go shapes, it counts only while the version really is absent,
// and the GET-time risk factors say so.

func TestProtocolVersionUnmeasured(t *testing.T) {
	v := "TLS 1.0"
	for _, c := range []struct {
		name    string
		raw     map[string]interface{}
		version *string
		want    bool
	}{
		{"json marker, no version", map[string]interface{}{"unmeasured_components": []interface{}{"protocol_version"}}, nil, true},
		{"go marker, no version", map[string]interface{}{"unmeasured_components": []string{"protocol_version"}}, nil, true},
		{"marker but a version was derived", map[string]interface{}{"unmeasured_components": []interface{}{"protocol_version"}}, &v, false},
		{"no marker, no version", map[string]interface{}{}, nil, false},
		{"other role only", map[string]interface{}{"unmeasured_components": []interface{}{"cipher_suite"}}, nil, false},
		{"nil raw", nil, nil, false},
	} {
		if got := protocolVersionUnmeasured(c.raw, c.version); got != c.want {
			t.Errorf("%s: protocolVersionUnmeasured = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAnnotateComponentAssessment_DropsAGapIngestFilled(t *testing.T) {
	raw := models.JSONB{"unmeasured_components": []interface{}{"protocol_version", "mac"}, "ssh_banner": "SSH-1.99-x"}
	v := "SSH-1.99"
	out, partial := annotateComponentAssessment(raw, &v)
	if partial {
		t.Error("a derived version is not unmeasured")
	}
	if got := out["unmeasured_components"]; !slices.Equal(got.([]string), []string{"mac"}) {
		t.Errorf("unmeasured_components = %#v, want [mac]", got)
	}
	if _, ok := raw["unmeasured_components"].([]interface{}); !ok {
		t.Error("the finding's own map was mutated")
	}
	if _, partial := annotateComponentAssessment(models.JSONB{"unmeasured_components": []interface{}{"protocol_version"}}, nil); !partial {
		t.Error("an absent version with the marker must be partial")
	}
}

func TestAnalyzeCryptoRisk_NamesAnUnmeasuredVersion(t *testing.T) {
	s := &AssetService{}
	suite := "ECDHE-RSA-AES256-GCM-SHA384"
	unmeasured := &models.CryptoImplementation{Protocol: "TLS", CipherSuite: &suite,
		RawData: models.JSONB{"unmeasured_components": []interface{}{"protocol_version"}}}
	if f := s.AnalyzeCryptoRisk(unmeasured); !slices.Contains(f, unmeasuredVersionFactor) {
		t.Errorf("factors %v lack the unmeasured-version factor", f)
	}
	v := "TLS 1.2"
	measured := &models.CryptoImplementation{Protocol: "TLS", CipherSuite: &suite, ProtocolVersion: &v,
		RawData: models.JSONB{"unmeasured_components": []interface{}{"protocol_version"}}} // stale marker after a merge
	if f := s.AnalyzeCryptoRisk(measured); slices.Contains(f, unmeasuredVersionFactor) {
		t.Errorf("a measured version is reported unmeasured: %v", f)
	}
}

// SSH versions are stored as catalogue codes from the banner; "SSH-1.99"
// must read as outdated (it used to compare "SSH-1.99" < "2.0", false).
func TestAnalyzeCryptoRisk_SSH199IsOutdated(t *testing.T) {
	s := &AssetService{}
	for v, want := range map[string]bool{"SSH-1.99": true, "SSH-1.5": true, "1.99": true, "SSH-2.0": false, "2.0": false} {
		version := v
		got := slices.Contains(s.AnalyzeCryptoRisk(&models.CryptoImplementation{Protocol: "SSH", ProtocolVersion: &version}), "Outdated SSH version")
		if got != want {
			t.Errorf("%s: outdated = %v, want %v", v, got, want)
		}
	}
}
