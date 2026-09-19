package services

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/redact"
	"strings"
	"testing"
)

func TestMergePreview_SecretProjectionDoesNotChangeSelectedValues(t *testing.T) {
	survivor, source := uuid.New(), uuid.New()
	rows := []map[string]any{}
	for _, id := range []uuid.UUID{survivor, source} {
		rows = append(rows, map[string]any{"id": id.String(), "display_name": "node", "hostname": "node.example.test", "class_key": "server", "asset_status": "monitoring", "identity_status": "legacy", "attributes": map[string]any{"api_token": "private-test-value", "model": "server"}, "tags": map[string]any{}})
	}
	preview, err := buildMergePreview(MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}, uuid.Nil, mergeSnapshot{Assets: rows, Records: map[string][]mergeRecord{}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(preview)
	if strings.Contains(string(encoded), "private-test-value") {
		t.Fatalf("preview leaked secret: %s", encoded)
	}
	if preview.SelectedFields["attributes"].(map[string]any)["api_token"] != redact.Marker {
		t.Fatal("missing redaction")
	}
	if preview.selectedRaw["attributes"].(map[string]any)["api_token"] != "private-test-value" {
		t.Fatal("public projection would overwrite stored value")
	}
}

func TestMergeRecordKey_UsesCompleteCompositePrimaryKey(t *testing.T) {
	key := uuid.NewString()
	one, err := mergeCompositeRecordKey("implementation_keys", map[string]any{"implementation_id": "one", "key_id": key})
	if err != nil {
		t.Fatal(err)
	}
	two, err := mergeCompositeRecordKey("implementation_keys", map[string]any{"implementation_id": "two", "key_id": key})
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("shared key collapsed independent configuration associations")
	}
	if _, err := mergeCompositeRecordKey("implementation_keys", map[string]any{"key_id": key}); err == nil {
		t.Fatal("missing key column silently accepted")
	}
	if _, err := mergeCompositeRecordKey("unregistered_table", map[string]any{}); err == nil {
		t.Fatal("unknown relation guessed a key")
	}
}

func TestMergeNameProvenance_ExplicitHostnameAndLegacyDeclaration(t *testing.T) {
	survivor, source := uuid.New(), uuid.New()
	snap := mergeSnapshot{Assets: []map[string]any{{"id": survivor.String(), "hostname": "", "display_name": ""}, {"id": source.String(), "hostname": "operator.example.test", "display_name": "operator.example.test", "_legacy_name_declared": true}}}
	preview := &AssetMergePreview{MergeSelection: MergeSelection{FieldResolutions: map[string]uuid.UUID{"hostname": source}}}
	if kind, changed := mergeNameProvenance(survivor, preview, snap); kind != "declared" || !changed {
		t.Fatal("explicit hostname decision lost")
	}
	preview.FieldResolutions = nil
	preview.selectedRaw = map[string]any{"hostname": "operator.example.test", "display_name": "operator.example.test"}
	if kind, changed := mergeNameProvenance(survivor, preview, snap); kind != "declared" || !changed {
		t.Fatal("legacy declaration lost during fill")
	}
}

func TestMergeNameProvenance_AllMatchingDonorsPreserveDeclaration(t *testing.T) {
	survivor := uuid.New()
	snap := mergeSnapshot{Assets: []map[string]any{
		{"id": survivor.String(), "hostname": "", "display_name": ""},
		{"id": uuid.NewString(), "hostname": "same.example.test", "display_name": "same.example.test", "metadata": map[string]any{"name_source_kind": "measured-passive"}},
		{"id": uuid.NewString(), "hostname": "same.example.test", "display_name": "same.example.test", "_legacy_name_declared": true},
	}}
	preview := &AssetMergePreview{selectedRaw: map[string]any{"hostname": "same.example.test", "display_name": "same.example.test"}}
	if kind, changed := mergeNameProvenance(survivor, preview, snap); kind != "declared" || !changed {
		t.Fatalf("matching measured donor concealed declaration: %s %v", kind, changed)
	}

	snap.Assets[0]["hostname"] = "same.example.test"
	snap.Assets[0]["display_name"] = "same.example.test"
	snap.Assets[0]["metadata"] = map[string]any{"name_source_kind": "measured-passive"}
	if kind, changed := mergeNameProvenance(survivor, preview, snap); kind != "declared" || !changed {
		t.Fatalf("populated measured survivor concealed declaration: %s %v", kind, changed)
	}
}
