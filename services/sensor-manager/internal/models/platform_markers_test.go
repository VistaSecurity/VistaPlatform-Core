package models

import (
	"reflect"
	"testing"
)

func TestStripReservedTags(t *testing.T) {
	got := StripReservedTags([]string{"edge", "system", " Platform ", "SYSTEM", "device_interrogation"})
	if !reflect.DeepEqual(got, []string{"edge", "device_interrogation"}) {
		t.Errorf("StripReservedTags = %v", got)
	}
	if StripReservedTags(nil) != nil {
		t.Error("nil (not supplied) became non-nil")
	}
}

// Both polarities: a tenant cannot ADD a platform marker to its sensor, and
// cannot REMOVE one from the platform's own sensor.
func TestReplaceTenantTags(t *testing.T) {
	if got := ReplaceTenantTags([]string{"prod"}, []string{"prod", "system", "platform"}); !reflect.DeepEqual(got, []string{"prod"}) {
		t.Errorf("tenant sensor self-tagging: %v, want [prod]", got)
	}
	got := ReplaceTenantTags([]string{"system", "platform", "device_interrogation"}, []string{"renamed"})
	if !reflect.DeepEqual(got, []string{"renamed", "system", "platform"}) {
		t.Errorf("platform sensor retag: %v, want [renamed system platform]", got)
	}
}

func TestTenantPlatformName(t *testing.T) {
	for in, want := range map[string]string{"platform": "unknown", " Platform ": "unknown", "linux": "linux", "": ""} {
		if got := TenantPlatformName(in); got != want {
			t.Errorf("TenantPlatformName(%q) = %q, want %q", in, got, want)
		}
	}
}
