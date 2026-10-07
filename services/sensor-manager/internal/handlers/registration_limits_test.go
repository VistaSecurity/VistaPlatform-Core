package handlers

import (
	"reflect"
	"testing"
)

// The registration limits are shared by every tenant, so nothing may be able
// to change them at runtime. Guards the shape of the fix for the old
// PUT /admin/settings: no handler exposes a write, and a caller that mutates
// the value it was given cannot affect the next reader.
func TestRegistrationLimitsAreImmutable(t *testing.T) {
	first := currentRegistrationLimits()
	if first.MaxPendingSensors != 50 || first.KeyExpirationMinutes != 60 || first.RequireIPValidation {
		t.Fatalf("unexpected defaults: %+v", first)
	}

	first.MaxPendingSensors = 1
	first.RequireIPValidation = true
	first.KeyExpirationMinutes = 1440

	second := currentRegistrationLimits()
	if second.MaxPendingSensors != 50 || second.KeyExpirationMinutes != 60 || second.RequireIPValidation {
		t.Fatalf("mutating a returned value leaked into shared state: %+v", second)
	}

	typ := reflect.TypeOf(&Handler{})
	for _, name := range []string{"UpdateAdminSettings", "GetAdminSettings"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Errorf("Handler.%s exists again — registration limits must not be tenant-writable", name)
		}
	}
}
