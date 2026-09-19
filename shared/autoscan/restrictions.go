package autoscan

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Restrictions are additional safety decisions shared by both automatic
// scanners. Reading them never enables either scanner or identity admission.
type Restrictions struct {
	Paused            bool
	SensitiveAssetIDs map[uuid.UUID]bool
	Excluded          []netip.Prefix
}

func RestrictionsFromConfig(config map[string]interface{}) (Restrictions, error) {
	out := Restrictions{SensitiveAssetIDs: map[uuid.UUID]bool{}}
	raw, err := json.Marshal(config)
	if err != nil {
		return out, err
	}
	var settings struct {
		Admission struct {
			Mode string `json:"mode"`
		} `json:"identity_admission"`
		Enrichment struct {
			Sensitive []uuid.UUID `json:"sensitive_asset_ids"`
			Excluded  []string    `json:"excluded_cidrs"`
		} `json:"identity_enrichment"`
	}
	if err = json.Unmarshal(raw, &settings); err != nil {
		return out, fmt.Errorf("invalid automatic-scan restrictions: %w", err)
	}
	out.Paused = settings.Admission.Mode == "paused"
	for _, id := range settings.Enrichment.Sensitive {
		out.SensitiveAssetIDs[id] = true
	}
	for _, value := range settings.Enrichment.Excluded {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return out, fmt.Errorf("invalid automatic-scan exclusion")
		}
		out.Excluded = append(out.Excluded, prefix.Masked())
	}
	return out, nil
}

func (r Restrictions) ProtectsAsset(id uuid.UUID, class string) bool {
	return r.SensitiveAssetIDs[id] || strings.Contains(class, "industrial") || strings.Contains(class, "medical") || assetclass.IsAncestor(assetclass.KeyOtDevice, class) || strings.HasPrefix(class, "ot_")
}
