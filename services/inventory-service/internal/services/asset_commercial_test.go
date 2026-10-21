package services

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func d(s string) *time.Time {
	t, err := time.Parse(isoDate, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// The warranty and end-of-support boundaries, one day either side of each
// edge, and the "nothing recorded" answer, which is unknown and never healthy.
func TestComputeAssetLifecycle_Boundaries(t *testing.T) {
	today := time.Date(2026, 10, 20, 15, 4, 5, 0, time.UTC) // time of day is ignored
	cases := []struct {
		name               string
		in                 LifecycleInputs
		warranty, eos, eff string
		source, subject    string
	}{
		{"nothing recorded", LifecycleInputs{}, models.WarrantyUnknown, models.EOSUnknown, "", models.EOSSourceNone, ""},
		{"warranty ended yesterday", LifecycleInputs{WarrantyEnd: d("2026-10-19")}, models.WarrantyExpired, models.EOSUnknown, "", models.EOSSourceNone, ""},
		{"warranty ends today", LifecycleInputs{WarrantyEnd: d("2026-10-20")}, models.WarrantyExpiring90, models.EOSUnknown, "", models.EOSSourceNone, ""},
		{"warranty ends in exactly 90 days", LifecycleInputs{WarrantyEnd: d("2027-01-18")}, models.WarrantyExpiring90, models.EOSUnknown, "", models.EOSSourceNone, ""},
		{"warranty ends in 91 days", LifecycleInputs{WarrantyEnd: d("2027-01-19")}, models.WarrantyActive, models.EOSUnknown, "", models.EOSSourceNone, ""},
		{"eos yesterday (declared)", LifecycleInputs{DeviceType: EOSCandidate{Declared: d("2026-10-19")}}, models.WarrantyUnknown, models.EOSPastEOS, "2026-10-19", models.EOSSourceDecl, models.EOSSubjectDT},
		{"eos today", LifecycleInputs{DeviceType: EOSCandidate{Declared: d("2026-10-20")}}, models.WarrantyUnknown, models.EOSWithin12m, "2026-10-20", models.EOSSourceDecl, models.EOSSubjectDT},
		{"eos in exactly 12 months", LifecycleInputs{DeviceType: EOSCandidate{Declared: d("2027-10-20")}}, models.WarrantyUnknown, models.EOSWithin12m, "2027-10-20", models.EOSSourceDecl, models.EOSSubjectDT},
		{"eos in 12 months and a day", LifecycleInputs{DeviceType: EOSCandidate{Declared: d("2027-10-21")}}, models.WarrantyUnknown, models.EOSSupported, "2027-10-21", models.EOSSourceDecl, models.EOSSubjectDT},
		{"declared wins over catalogue", LifecycleInputs{DeviceType: EOSCandidate{Declared: d("2030-01-01"), Catalogue: d("2020-01-01")}}, models.WarrantyUnknown, models.EOSSupported, "2030-01-01", models.EOSSourceDecl, models.EOSSubjectDT},
		{"catalogue when nothing declared", LifecycleInputs{DeviceType: EOSCandidate{Catalogue: d("2020-01-01")}}, models.WarrantyUnknown, models.EOSPastEOS, "2020-01-01", models.EOSSourceCat, models.EOSSubjectDT},
		{"platform only", LifecycleInputs{Platform: EOSCandidate{Catalogue: d("2027-03-01")}}, models.WarrantyUnknown, models.EOSWithin12m, "2027-03-01", models.EOSSourceCat, models.EOSSubjectPlat},
		{"the earlier of type and platform wins", LifecycleInputs{DeviceType: EOSCandidate{Declared: d("2031-01-01")}, Platform: EOSCandidate{Catalogue: d("2025-06-30")}}, models.WarrantyUnknown, models.EOSPastEOS, "2025-06-30", models.EOSSourceCat, models.EOSSubjectPlat},
		{"a tie names the device type", LifecycleInputs{DeviceType: EOSCandidate{Catalogue: d("2029-01-01")}, Platform: EOSCandidate{Declared: d("2029-01-01")}}, models.WarrantyUnknown, models.EOSSupported, "2029-01-01", models.EOSSourceCat, models.EOSSubjectDT},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeAssetLifecycle(c.in, today)
			if got.WarrantyState != c.warranty || got.EOSState != c.eos || got.Source != c.source {
				t.Fatalf("got warranty=%s eos=%s source=%s, want %s %s %s", got.WarrantyState, got.EOSState, got.Source, c.warranty, c.eos, c.source)
			}
			eff, subj := "", ""
			if got.EffectiveEndOfSupport != nil {
				eff = *got.EffectiveEndOfSupport
			}
			if got.Subject != nil {
				subj = *got.Subject
			}
			if eff != c.eff || subj != c.subject {
				t.Fatalf("effective %q subject %q, want %q %q", eff, subj, c.eff, c.subject)
			}
		})
	}
}

func TestParseHardwareValue(t *testing.T) {
	ok := []struct{ field, in, want string }{
		{"purchase_date", `"2026-01-31"`, "2026-01-31"},
		{"purchase_cost", `4200`, "4200.00"},
		{"purchase_cost", `"4200.5"`, "4200.50"},
		{"purchase_cost", `0.99`, "0.99"},
		{"purchase_currency", `"usd"`, "USD"},
		{"vendor", `"  Acme Resale  "`, "Acme Resale"},
	}
	for _, c := range ok {
		v, err := parseHardwareValue(c.field, hardwareFields[c.field], json.RawMessage(c.in))
		if err != nil || v != c.want {
			t.Errorf("%s %s: got %v, %v; want %s", c.field, c.in, v, err, c.want)
		}
	}
	for _, f := range []string{"purchase_date", "purchase_cost", "vendor", "purchase_currency"} {
		for _, in := range []string{`null`, `""`} {
			if v, err := parseHardwareValue(f, hardwareFields[f], json.RawMessage(in)); err != nil || v != nil {
				t.Errorf("%s %s should clear: got %v, %v", f, in, v, err)
			}
		}
	}
	bad := []struct{ field, in string }{
		{"purchase_date", `"2026-02-30"`}, {"purchase_date", `"31/01/2026"`}, {"purchase_date", `20260131`},
		{"purchase_cost", `-1`}, {"purchase_cost", `"1.234"`}, {"purchase_cost", `1e3`}, {"purchase_cost", `"1234567890123"`}, {"purchase_cost", `true`},
		{"purchase_currency", `"US"`}, {"purchase_currency", `"US1"`}, {"purchase_currency", `"EURO"`},
		{"vendor", `12`},
	}
	for _, c := range bad {
		if _, err := parseHardwareValue(c.field, hardwareFields[c.field], json.RawMessage(c.in)); err == nil {
			t.Errorf("%s %s: accepted, want refused", c.field, c.in)
		}
	}
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'x'
	}
	raw, _ := json.Marshal(string(long))
	if _, err := parseHardwareValue("purchase_order", hardwareFields["purchase_order"], raw); err == nil {
		t.Error("a 201-character purchase order was accepted")
	}
}

func TestCheckCommercialOrder(t *testing.T) {
	pre := assetHardwareRow{values: map[string]any{"warranty_start": "2026-01-01", "warranty_end": nil, "installed_at": nil, "decommissioned_at": "2026-05-01"}}
	if err := checkCommercialOrder(pre, map[string]any{"warranty_end": "2025-12-31"}); err == nil {
		t.Error("a warranty ending before its stored start was accepted")
	}
	if err := checkCommercialOrder(pre, map[string]any{"warranty_end": "2026-01-01"}); err != nil {
		t.Errorf("a one-day warranty was refused: %v", err)
	}
	if err := checkCommercialOrder(pre, map[string]any{"installed_at": "2026-06-01"}); err == nil {
		t.Error("an installation after the stored decommission was accepted")
	}
	if err := checkCommercialOrder(pre, map[string]any{"warranty_start": nil, "warranty_end": "2020-01-01"}); err != nil {
		t.Errorf("clearing the start in the same patch should lift the check: %v", err)
	}
}

func TestApplyAssetLifecycle_DecodesTheSQLObject(t *testing.T) {
	defer func(f func() time.Time) { lifecycleNow = f }(lifecycleNow)
	lifecycleNow = func() time.Time { return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) }
	var a models.Asset
	applyAssetLifecycle(&a, `{"purchase_date":"2024-03-01","warranty_end":"2026-11-01","purchase_cost":4200.5,"purchase_currency":"EUR",
		"vendor":"Acme Resale","dt_end_of_support":null,"dt_catalogue_end_of_support":"2026-01-31","pl_end_of_support":null,"pl_catalogue_end_of_support":null}`)
	if a.PurchaseDate == nil || *a.PurchaseDate != "2024-03-01" || a.PurchaseCost == nil || *a.PurchaseCost != 4200.5 || a.Vendor == nil || *a.Vendor != "Acme Resale" {
		t.Fatalf("commercial fields not decoded: %+v", a.AssetCommercial)
	}
	if a.WarrantyStart != nil {
		t.Fatal("a missing field must stay nil (not recorded)")
	}
	lc := a.Lifecycle
	if lc == nil || lc.WarrantyState != models.WarrantyExpiring90 || lc.EOSState != models.EOSPastEOS || lc.Source != models.EOSSourceCat {
		t.Fatalf("lifecycle %+v", lc)
	}
	var empty models.Asset
	applyAssetLifecycle(&empty, "")
	if empty.Lifecycle == nil || empty.Lifecycle.WarrantyState != models.WarrantyUnknown || empty.Lifecycle.EOSState != models.EOSUnknown {
		t.Fatalf("an empty object must compute unknown, got %+v", empty.Lifecycle)
	}
}
