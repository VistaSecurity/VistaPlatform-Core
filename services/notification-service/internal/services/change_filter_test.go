package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

func ptr(s string) *string { return &s }

func changeMeta(kind, action, source string) map[string]interface{} {
	return map[string]interface{}{"object_kind": kind, "action": action, "source": source}
}

func TestChangeFilter_KindFilter(t *testing.T) {
	f := &models.ChangeFilter{ObjectKinds: []string{"cable", "prefix"}}
	if !changeFilterMatches(f, changeMeta("cable", "update", "ui")) {
		t.Error("a listed kind must match")
	}
	if changeFilterMatches(f, changeMeta("rack", "update", "ui")) {
		t.Error("an unlisted kind must not match")
	}
	if !changeFilterMatches(&models.ChangeFilter{}, changeMeta("rack", "update", "ui")) {
		t.Error("no kinds listed = every kind")
	}
}

func TestChangeFilter_ActionFilter(t *testing.T) {
	f := &models.ChangeFilter{Actions: []string{"delete"}}
	if !changeFilterMatches(f, changeMeta("cable", "delete", "api")) {
		t.Error("a listed action must match")
	}
	if changeFilterMatches(f, changeMeta("cable", "create", "api")) {
		t.Error("an unlisted action must not match")
	}
}

// Intake and sync changes are excluded by default — a nil filter included —
// and routed only when the rule opts in. Mutation: return true for the intake
// arm → the first assertion fails.
func TestChangeFilter_IntakeAndSyncExcludedByDefault(t *testing.T) {
	for _, f := range []*models.ChangeFilter{nil, {}} {
		if changeFilterMatches(f, changeMeta("interface", "create", "intake:lldp")) {
			t.Errorf("filter %+v routed an intake change without opting in", f)
		}
		if changeFilterMatches(f, changeMeta("site", "update", "sync:netbox")) {
			t.Errorf("filter %+v routed a sync change without opting in", f)
		}
		if !changeFilterMatches(f, changeMeta("site", "update", "ui")) {
			t.Errorf("filter %+v dropped a person's change", f)
		}
		if !changeFilterMatches(f, changeMeta("site", "update", "system")) {
			t.Errorf("filter %+v dropped a system change", f)
		}
	}
}

func TestChangeFilter_IntakeAndSyncIncludedWhenOptedIn(t *testing.T) {
	intake := &models.ChangeFilter{IncludeIntake: true}
	if !changeFilterMatches(intake, changeMeta("interface", "create", "intake:lldp")) {
		t.Error("include_intake must route an intake change")
	}
	if changeFilterMatches(intake, changeMeta("site", "update", "sync:netbox")) {
		t.Error("include_intake must not also include sync")
	}
	sync := &models.ChangeFilter{IncludeSync: true, ObjectKinds: []string{"site"}}
	if !changeFilterMatches(sync, changeMeta("site", "update", "sync:netbox")) {
		t.Error("include_sync must route a sync change")
	}
	if changeFilterMatches(sync, changeMeta("rack", "update", "sync:netbox")) {
		t.Error("the kind filter still applies to an included sync change")
	}
}

// Only a rule that names object_changed routes it; a catch-all rule does not,
// and every other alert type is untouched by the change condition.
func TestRuleRoutesAlert_ObjectChangedNeedsANamingRule(t *testing.T) {
	catchAll := models.TenantNotificationRule{AlertSource: "all"}
	named := models.TenantNotificationRule{AlertSource: "inventory-service", AlertType: ptr("object_changed"),
		ChangeFilter: &models.ChangeFilter{ObjectKinds: []string{"cable"}}}
	md := changeMeta("cable", "update", "ui")

	if ruleRoutesAlert(catchAll, "object_changed", md) {
		t.Error("a catch-all rule routed an inventory change")
	}
	if ruleRoutesAlert(models.TenantNotificationRule{AlertType: ptr("")}, "object_changed", md) {
		t.Error("an empty alert_type is a catch-all too")
	}
	if !ruleRoutesAlert(named, "object_changed", md) {
		t.Error("the naming rule did not route a matching change")
	}
	if ruleRoutesAlert(named, "object_changed", changeMeta("prefix", "update", "ui")) {
		t.Error("the naming rule's kind filter was not applied")
	}
	if !ruleRoutesAlert(catchAll, "sensor_offline", nil) {
		t.Error("the change condition must not affect other alert types")
	}
}

func TestChangeFilter_Validate(t *testing.T) {
	var none *models.ChangeFilter
	if err := none.Validate(); err != nil {
		t.Fatalf("nil filter: %v", err)
	}
	if err := (&models.ChangeFilter{ObjectKinds: []string{"cable", "prefix", "asset"}, Actions: []string{"create", "delete"}}).Validate(); err != nil {
		t.Fatalf("valid filter refused: %v", err)
	}
	if err := (&models.ChangeFilter{ObjectKinds: []string{"cables"}}).Validate(); err == nil {
		t.Error("an unknown object kind was accepted")
	}
	if err := (&models.ChangeFilter{Actions: []string{"modify"}}).Validate(); err == nil {
		t.Error("an unknown action was accepted")
	}
}

func TestChangeFilterValue_OnlyForObjectChanged(t *testing.T) {
	if v, f := changeFilterValue(ptr("sensor_offline"), &models.ChangeFilter{IncludeSync: true}); v != nil || f != nil {
		t.Errorf("a non-change rule stored a filter: %v %+v", v, f)
	}
	if v, f := changeFilterValue(nil, nil); v != nil || f != nil {
		t.Errorf("a catch-all rule stored a filter: %v %+v", v, f)
	}
	v, f := changeFilterValue(ptr("object_changed"), nil)
	if v != `{"include_intake":false,"include_sync":false}` || f == nil {
		t.Errorf("an object_changed rule with no filter must store the default one, got %v", v)
	}
}
