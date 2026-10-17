package services

import (
	"encoding/json"
	"reflect"
	"testing"
)

func ctxRow(name string, weight int, active bool, data string, assign map[string][]string) ConfigContextRow {
	return ConfigContextRow{ID: "id-" + name, Name: name, Weight: weight, IsActive: active, Data: decodeContextData([]byte(data)), Assignments: assign}
}

func TestRenderConfigContexts_MergeTable(t *testing.T) {
	facts := AssetConfigFacts{
		LocationIDs: []string{"loc-room", "loc-bldg"}, DeviceRoleID: "role-fw", DeviceTypeID: "dt-1",
		BusinessUnitID: "bu-1", TagIDs: []string{"tag-a"},
	}
	cases := []struct {
		name string
		in   []ConfigContextRow
		want string
		by   []string
	}{
		{"weight ascending, heavier wins", []ConfigContextRow{
			ctxRow("heavy", 2000, true, `{"ntp":"b","only_heavy":1}`, nil),
			ctxRow("light", 100, true, `{"ntp":"a","only_light":1}`, nil),
		}, `{"ntp":"b","only_heavy":1,"only_light":1}`, []string{"light", "heavy"}},
		{"equal weight ties by name", []ConfigContextRow{
			ctxRow("b", 10, true, `{"k":"b"}`, nil), ctxRow("a", 10, true, `{"k":"a"}`, nil),
		}, `{"k":"b"}`, []string{"a", "b"}},
		{"deep merge of objects", []ConfigContextRow{
			ctxRow("a", 1, true, `{"dns":{"servers":["1.1.1.1"],"search":"x"},"snmp":{"v":3}}`, nil),
			ctxRow("b", 2, true, `{"dns":{"servers":["9.9.9.9"]},"snmp":{"ctx":"c"}}`, nil),
		}, `{"dns":{"servers":["9.9.9.9"],"search":"x"},"snmp":{"v":3,"ctx":"c"}}`, []string{"a", "b"}},
		{"lists are replaced, not concatenated", []ConfigContextRow{
			ctxRow("a", 1, true, `{"l":[1,2,3]}`, nil), ctxRow("b", 2, true, `{"l":[9]}`, nil),
		}, `{"l":[9]}`, []string{"a", "b"}},
		{"object replaced by scalar and back", []ConfigContextRow{
			ctxRow("a", 1, true, `{"x":{"y":1}}`, nil), ctxRow("b", 2, true, `{"x":5}`, nil), ctxRow("c", 3, true, `{"x":{"z":2}}`, nil),
		}, `{"x":{"z":2}}`, []string{"a", "b", "c"}},
		{"inactive excluded", []ConfigContextRow{
			ctxRow("on", 1, true, `{"a":1}`, nil), ctxRow("off", 2, false, `{"a":2,"b":2}`, nil),
		}, `{"a":1}`, []string{"on"}},
		{"unassigned applies to all", []ConfigContextRow{
			ctxRow("all", 1, true, `{"all":true}`, map[string][]string{"locations": {}}),
		}, `{"all":true}`, []string{"all"}},
		{"role match", []ConfigContextRow{
			ctxRow("fw", 1, true, `{"fw":1}`, map[string][]string{"device_roles": {"role-fw"}}),
			ctxRow("sw", 1, true, `{"sw":1}`, map[string][]string{"device_roles": {"role-sw"}}),
		}, `{"fw":1}`, []string{"fw"}},
		{"business unit match", []ConfigContextRow{
			ctxRow("bu", 1, true, `{"bu":1}`, map[string][]string{"business_units": {"bu-1", "bu-9"}}),
			ctxRow("other", 1, true, `{"o":1}`, map[string][]string{"business_units": {"bu-9"}}),
		}, `{"bu":1}`, []string{"bu"}},
		{"location matches through an ancestor", []ConfigContextRow{
			ctxRow("bldg", 1, true, `{"b":1}`, map[string][]string{"locations": {"loc-bldg"}}),
			ctxRow("elsewhere", 1, true, `{"e":1}`, map[string][]string{"locations": {"loc-x"}}),
		}, `{"b":1}`, []string{"bldg"}},
		{"tag match", []ConfigContextRow{
			ctxRow("t", 1, true, `{"t":1}`, map[string][]string{"tags": {"tag-a"}}),
			ctxRow("u", 1, true, `{"u":1}`, map[string][]string{"tags": {"tag-z"}}),
		}, `{"t":1}`, []string{"t"}},
		{"dimensions are ANDed", []ConfigContextRow{
			ctxRow("both", 1, true, `{"ok":1}`, map[string][]string{"device_roles": {"role-fw"}, "business_units": {"bu-1"}}),
			ctxRow("half", 1, true, `{"bad":1}`, map[string][]string{"device_roles": {"role-fw"}, "business_units": {"bu-9"}}),
		}, `{"ok":1}`, []string{"both"}},
		{"nothing applies", nil, `{}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RenderConfigContexts(facts, c.in)
			var want map[string]any
			if err := json.Unmarshal([]byte(c.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Data, want) {
				gj, _ := json.Marshal(got.Data)
				t.Fatalf("data = %s, want %s", gj, c.want)
			}
			names := []string{}
			for _, r := range got.Contributing {
				names = append(names, r.Name)
			}
			if c.by == nil {
				c.by = []string{}
			}
			if !reflect.DeepEqual(names, c.by) {
				t.Fatalf("contributing = %v, want %v", names, c.by)
			}
		})
	}
}

func TestConfigContextDimensions_AreSpecColumns(t *testing.T) {
	spec := configContextSpecs()[0]
	have := map[string]bool{}
	for _, c := range spec.Cols {
		have[c.Name] = true
	}
	for _, d := range ConfigContextDimensions() {
		if !have[d] {
			t.Errorf("dimension %q is matched but not writable", d)
		}
	}
}
