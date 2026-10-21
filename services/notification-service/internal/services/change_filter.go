package services

import (
	"encoding/json"
	"strings"

	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

// ruleRoutesAlert is the per-rule condition beyond source/type/severity.
//
// For object_changed (Inventory change notifications) two things hold that do
// not for any other type:
//
//  1. Only a rule that NAMES the type routes it. A catch-all rule (alert_type
//     empty, often alert_source "all") was written for alerts — conditions
//     that need attention — and must not start relaying every edit anybody
//     makes once inventory changes exist. Opting in is choosing "Inventory
//     changes" in the rule editor.
//  2. The rule's change_filter is evaluated against the event's metadata:
//     object kind, action, and the change's source (intake and sync changes
//     only when the rule includes them).
//
// Every other type is unaffected: true.
func ruleRoutesAlert(rule models.TenantNotificationRule, alertType string, metadata map[string]interface{}) bool {
	if alertType != models.ObjectChangedAlertType {
		return true
	}
	if rule.AlertType == nil || *rule.AlertType != models.ObjectChangedAlertType {
		return false
	}
	return changeFilterMatches(rule.ChangeFilter, metadata)
}

// changeFilterMatches evaluates one rule's object_changed condition. A nil
// filter is the default condition: any kind, any action, people's changes
// only. An event that does not say what it is about (no object_kind / action /
// source in its metadata) matches only a filter that does not ask.
func changeFilterMatches(f *models.ChangeFilter, metadata map[string]interface{}) bool {
	if f == nil {
		f = &models.ChangeFilter{}
	}
	kind, _ := metadata["object_kind"].(string)
	action, _ := metadata["action"].(string)
	source, _ := metadata["source"].(string)

	if len(f.ObjectKinds) > 0 && !contains(f.ObjectKinds, kind) {
		return false
	}
	if len(f.Actions) > 0 && !contains(f.Actions, action) {
		return false
	}
	switch {
	case strings.HasPrefix(source, "intake:"):
		return f.IncludeIntake
	case strings.HasPrefix(source, "sync:"):
		return f.IncludeSync
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// scanChangeFilter decodes the change_filter column (NULL → nil).
func scanChangeFilter(raw []byte) *models.ChangeFilter {
	if len(raw) == 0 {
		return nil
	}
	var f models.ChangeFilter
	if json.Unmarshal(raw, &f) != nil {
		return nil
	}
	return &f
}

// changeFilterValue is what to store in change_filter for a rule of alertType:
// the filter for object_changed (an empty one when none was given, so the row
// says what it routes), NULL for every other type.
func changeFilterValue(alertType *string, f *models.ChangeFilter) (any, *models.ChangeFilter) {
	if alertType == nil || *alertType != models.ObjectChangedAlertType {
		return nil, nil
	}
	if f == nil {
		f = &models.ChangeFilter{}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, nil
	}
	return string(b), f
}
