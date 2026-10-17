package services

// The config-context merge rule (NetBox extras/config-context semantics):
//
//   - a context applies to an asset when it is active and, for every
//     assignment dimension it fills, the asset's value is among the ids (OR
//     within a dimension, AND across dimensions); a context that fills none
//     applies to every asset;
//   - applicable contexts merge by weight ascending, ties by name, so the
//     heaviest wins a conflict;
//   - JSON objects merge recursively; any other value -- a scalar, a list,
//     null -- replaces whatever was there (lists are NOT concatenated).

import (
	"encoding/json"
	"sort"
	"strings"
)

// AssetConfigFacts are the asset values a context's assignments are matched against.
type AssetConfigFacts struct {
	// LocationIDs is the asset's location and every ancestor of it.
	LocationIDs    []string
	DeviceTypeID   string
	DeviceRoleID   string
	PlatformID     string
	BusinessUnitID string
	TagIDs         []string
}

// ConfigContextRow is a stored context as the renderer needs it.
type ConfigContextRow struct {
	ID          string
	Name        string
	Weight      int
	IsActive    bool
	Data        map[string]any
	Assignments map[string][]string // column -> ids
}

// ConfigContextRef names a context that contributed to a rendered config.
type ConfigContextRef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Weight int    `json:"weight"`
}

// RenderedConfigContext is an asset's merged config and what produced it.
type RenderedConfigContext struct {
	Data         map[string]any     `json:"data"`
	Contributing []ConfigContextRef `json:"contributing"`
}

func (c ConfigContextRow) appliesTo(f AssetConfigFacts) bool {
	if !c.IsActive {
		return false
	}
	// A filled array on a dimension this tree does not match can never be
	// satisfied; only the live dimensions are read, so it is ignored here and
	// cannot be written through the API.
	for _, d := range configDimensions {
		want := c.Assignments[d.Column]
		if len(want) == 0 {
			continue
		}
		if !intersects(want, d.Values(f)) {
			return false
		}
	}
	return true
}

func intersects(want, have []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}

// deepMerge folds src into dst (both objects) and returns dst.
func deepMerge(dst, src map[string]any) map[string]any {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = deepMerge(dm, sm)
				continue
			}
			dst[k] = deepMerge(map[string]any{}, sm)
			continue
		}
		dst[k] = sv
	}
	return dst
}

// RenderConfigContexts merges the contexts that apply to facts.
func RenderConfigContexts(facts AssetConfigFacts, all []ConfigContextRow) RenderedConfigContext {
	applicable := make([]ConfigContextRow, 0, len(all))
	for _, c := range all {
		if c.appliesTo(facts) {
			applicable = append(applicable, c)
		}
	}
	sort.SliceStable(applicable, func(i, j int) bool {
		if applicable[i].Weight != applicable[j].Weight {
			return applicable[i].Weight < applicable[j].Weight
		}
		return strings.ToLower(applicable[i].Name) < strings.ToLower(applicable[j].Name)
	})
	out := RenderedConfigContext{Data: map[string]any{}, Contributing: []ConfigContextRef{}}
	for _, c := range applicable {
		deepMerge(out.Data, c.Data)
		out.Contributing = append(out.Contributing, ConfigContextRef{ID: c.ID, Name: c.Name, Weight: c.Weight})
	}
	return out
}

// decodeContextData parses the stored data column.
func decodeContextData(raw []byte) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	return m
}
