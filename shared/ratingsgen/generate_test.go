package ratingsgen

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/healthbands"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

func TestGeneratedOutputCurrent(t *testing.T) {
	for path, want := range map[string][]byte{
		"../../packages/primitives/src/ratings/definitions.gen.ts": TypeScript(),
		"../../standards/generated/rating-definitions.json":        JSON(),
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generated ratings drift: %s; run go run ./shared/ratingsgen/cmd/gen-ratings from repository root", path)
		}
	}
}

// Execute the generated TypeScript, comparing results with the Go owners at
// every integer and either side of every boundary. This catches algorithm drift
// as well as a changed generated table (a text-only golden cannot do that).
func TestGoTypeScriptParity(t *testing.T) {
	type scoreCase struct {
		Score  float64 `json:"score"`
		Risk   string  `json:"risk"`
		Health any     `json:"health"`
	}
	var scores []scoreCase
	for score := -1; score <= 101; score++ {
		f := float64(score)
		band, ok := healthbands.FromScore(&f)
		var health any
		if ok {
			health = string(band)
		}
		scores = append(scores, scoreCase{f, riskbands.GetRiskLevel(score), health})
	}
	for _, d := range healthbands.Definitions() {
		for _, f := range []float64{d.Min - 0.001, d.Min, d.Min + 0.001} {
			band, ok := healthbands.FromScore(&f)
			var health any
			if ok {
				health = string(band)
			}
			scores = append(scores, scoreCase{f, riskbands.GetRiskLevel(int(f)), health})
		}
	}
	payload, err := json.Marshal(scores)
	if err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Abs("../../packages/primitives/src/ratings/definitions.gen.ts")
	if err != nil {
		t.Fatal(err)
	}
	script := `import assert from 'node:assert/strict';
import * as ratings from ` + fmtJSON("file://"+path) + `;
const cases = ` + string(payload) + `;
for (const row of cases) {
 assert.equal(ratings.riskLevelFromScore(row.score), row.risk, 'risk '+row.score);
 assert.equal(ratings.healthBandFromScore(row.score), row.health, 'health '+row.score);
}
for (const value of [null,undefined,NaN,Infinity,-Infinity]) assert.equal(ratings.healthBandFromScore(value),null);
for (const row of ` + fmtJSON(Values().Severity) + `) {
 assert.equal(ratings.parseSeverity(row.value),row.value);
 assert.equal(ratings.severityRank(row.value),row.rank);
 assert.equal(ratings.severityLabel(row.value),row.label);
 assert.equal(ratings.controlWeight(row.value),row.controlWeight || null);
}
assert.deepEqual(ratings.CONTROL_SEVERITIES, ` + fmtJSON(Values().Severity) + `.filter(row => row.controlWeight > 0).map(row => row.value));
for (const row of ` + fmtJSON(Values().Strength) + `) {
 assert.equal(ratings.strengthRank(row.value),row.rank);
 assert.equal(ratings.strengthLabel(row.value),row.label);
}
for (const value of ['good','unknown','Strong','']) assert.equal(ratings.strengthRank(value),null);
for (const value of ['Med','Medium','INFORMATIONAL','critical ','bogus','']) assert.equal(ratings.parseSeverity(value),null);
`
	cmd := exec.Command("node", "--experimental-strip-types", "--input-type=module")
	cmd.Stdin = bytes.NewBufferString(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Go/TS parity: %v\n%s", err, output)
	}
}
func fmtJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestSeverityDefinitionsValid(t *testing.T) {
	for _, d := range Values().Severity {
		got, err := severity.Parse(string(d.Value))
		if err != nil || got != d.Value {
			t.Fatal(d, err)
		}
	}
}
