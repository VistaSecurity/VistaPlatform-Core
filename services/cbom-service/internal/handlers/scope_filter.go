package handlers

// The scope predicate used to be evaluated HERE, in memory, against each asset
// the CBOM assembly had fetched: an AssetPredicate mirroring scopes.Predicate
// field for field, a reflective translator checking the two stayed in step, and
// a per-asset matcher.
//
// All of it is gone. A scope is a query-language string now, it goes to
// inventory-service as `?query=`, and the database answers — so the boundary a
// CBOM attests to is decided by exactly the same code that answers the
// Inventory page, rather than by a second implementation that had to be kept
// in step by a reflection test.
//
// What is left in this file is tag flattening, which the asset CONTEXT still
// needs: a component records the environment, business unit and location of the
// asset it came from, and those are read out of the tags column.

// flattenTags reduces the asset's JSONB tags column to a flat string map. Nested
// objects (the `location` sub-map inventory writes) contribute their leaves, so
// a `{"location":{"region":"us-east-1"}}` asset is matchable by the tag value
// `us-east-1` as well as by location_region.
func flattenTags(raw interface{}) map[string]string {
	out := map[string]string{}
	flattenTagsInto(raw, out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func flattenTagsInto(raw interface{}, out map[string]string) {
	switch v := raw.(type) {
	case map[string]interface{}:
		for key, value := range v {
			switch nested := value.(type) {
			case map[string]interface{}, []interface{}:
				flattenTagsInto(nested, out)
				// Keep the key itself matchable ("tags_any_of": ["location"]).
				if _, exists := out[key]; !exists {
					out[key] = ""
				}
			default:
				out[key] = strVal(value)
			}
		}
	case []interface{}:
		for _, item := range v {
			switch nested := item.(type) {
			case map[string]interface{}, []interface{}:
				flattenTagsInto(nested, out)
			default:
				out[strVal(item)] = ""
			}
		}
	}
}

// tagLocationRegion mirrors inventory-service's location_region filter, which
// reads COALESCE(tags->'location'->>'region', tags->>'region').
func tagLocationRegion(raw interface{}) string {
	tags, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	if location, ok := tags["location"].(map[string]interface{}); ok {
		if region := strVal(location["region"]); region != "" {
			return region
		}
	}
	return strVal(tags["region"])
}
