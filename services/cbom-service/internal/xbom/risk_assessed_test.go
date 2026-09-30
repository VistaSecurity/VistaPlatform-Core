package xbom

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
)

// `assets.risk_score` is NOT NULL DEFAULT 0, so a never-assessed asset and an
// assessed-clean one both read 0. The export must tell them apart: 0 is a
// finding ("somebody looked and found nothing") and cannot be asserted about an
// asset with no assessment behind it. These tests pin both polarities in both
// exports that carry a risk score.

var (
	riskAssessedZero   = uuid.MustParse("b0000000-0000-4000-8000-000000000001")
	riskUnassessedZero = uuid.MustParse("b0000000-0000-4000-8000-000000000002")
	riskAssessed55     = uuid.MustParse("b0000000-0000-4000-8000-000000000003")
)

func riskSnapshot() *Snapshot {
	t := fixtureTime()
	mk := func(id uuid.UUID, name string, score int, assessed bool) Asset {
		return Asset{
			ID: id, ClassKey: "server", ClassPath: "hardware.computer.server",
			DisplayName: name, AssetStatus: "monitoring", AssetOwnership: "internal",
			RiskScore: score, RiskAssessed: assessed,
			FirstSeenAt: t, LastSeenAt: t, Tags: map[string]string{},
		}
	}
	return &Snapshot{Assets: []Asset{
		mk(riskAssessedZero, "assessed-clean", 0, true),
		mk(riskUnassessedZero, "never-assessed", 0, false),
		mk(riskAssessed55, "assessed-55", 55, true),
	}}
}

func riskDocBytes(t *testing.T) []byte {
	t.Helper()
	doc, err := BuildDocument("inventory", riskSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// hasProperty reports the property's value and whether it is present at all.
func hasProperty(props []formatters.CDXProperty, name string) (string, bool) {
	for _, p := range props {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func TestCycloneDX_RiskScoreOnlyForAssessedAssets(t *testing.T) {
	doc, err := BuildDocument("inventory", riskSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	byRef := map[string][]formatters.CDXProperty{}
	for _, c := range doc.Components {
		byRef[c.BOMRef] = c.Properties
	}

	// Assessed clean: an explicit 0 must survive.
	props := byRef[refAsset+riskAssessedZero.String()]
	if v, ok := hasProperty(props, propAssetRisk); !ok || v != "0" {
		t.Errorf("assessed-clean asset risk_score = %q (present=%v), want present \"0\"", v, ok)
	}
	if _, ok := hasProperty(props, propAssetRAsmt); ok {
		t.Errorf("assessed asset must not carry %s", propAssetRAsmt)
	}

	// Never assessed: NO score, and the absence is stated.
	props = byRef[refAsset+riskUnassessedZero.String()]
	if v, ok := hasProperty(props, propAssetRisk); ok {
		t.Errorf("never-assessed asset carries risk_score = %q; nobody assessed it", v)
	}
	if v, ok := hasProperty(props, propAssetRAsmt); !ok || v != "false" {
		t.Errorf("never-assessed asset risk_assessed = %q (present=%v), want present \"false\"", v, ok)
	}

	// Assessed with a real score.
	props = byRef[refAsset+riskAssessed55.String()]
	if v, ok := hasProperty(props, propAssetRisk); !ok || v != "55" {
		t.Errorf("assessed asset risk_score = %q (present=%v), want present \"55\"", v, ok)
	}
}

func TestOCSF_DeviceRiskScoreOnlyForAssessedAssets(t *testing.T) {
	body, _, err := RenderOCSF(riskDocBytes(t))
	if err != nil {
		t.Fatalf("RenderOCSF: %v", err)
	}
	devices := map[string]map[string]any{}
	for _, e := range decodeNDJSON(t, body) {
		if d, _ := e["device"].(map[string]any); d != nil {
			if uid, _ := d["uid"].(string); uid != "" {
				devices[uid] = d
			}
		}
	}

	if d := devices[riskAssessedZero.String()]; d == nil {
		t.Fatal("assessed-clean asset produced no device event")
	} else if v, ok := d["risk_score"]; !ok || v != float64(0) {
		t.Errorf("assessed-clean device risk_score = %v (present=%v), want present 0", v, ok)
	}

	if d := devices[riskUnassessedZero.String()]; d == nil {
		t.Fatal("never-assessed asset produced no device event")
	} else {
		for _, k := range []string{"risk_score", "risk_level", "risk_level_id"} {
			if v, ok := d[k]; ok {
				t.Errorf("never-assessed device carries %s = %v; nobody assessed it", k, v)
			}
		}
	}

	if d := devices[riskAssessed55.String()]; d == nil {
		t.Fatal("assessed asset produced no device event")
	} else if v, ok := d["risk_score"]; !ok || v != float64(55) {
		t.Errorf("assessed device risk_score = %v (present=%v), want present 55", v, ok)
	}
}
