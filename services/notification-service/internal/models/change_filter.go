package models

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// ObjectChangedAlertType is the alert type of an inventory change
// (standards/alert-registry.yaml `object_changed`, raised by inventory-service's
// change notifier). It is the only type a [ChangeFilter] applies to.
const ObjectChangedAlertType = "object_changed"

// ChangeFilter is a routing rule's condition for object_changed — "notify me
// when a cable or a prefix changes" (tenant_notification_rules.change_filter).
//
// Empty ObjectKinds or Actions mean "any". Changes whose source is discovery
// intake (`intake:<producer>`) or a sync connection (`sync:<peer>`) are routed
// only when the rule opts in: those paths write in bursts, and a rule written
// for the changes people make should not page on every collector pass.
type ChangeFilter struct {
	ObjectKinds   []string `json:"object_kinds,omitempty"`
	Actions       []string `json:"actions,omitempty"`
	IncludeIntake bool     `json:"include_intake"`
	IncludeSync   bool     `json:"include_sync"`
}

var changeActions = map[string]bool{"create": true, "update": true, "delete": true}

// Validate refuses a kind that is not an inventory object kind
// (standards/vocabulary.yaml) and an action other than create/update/delete,
// so a typo cannot make a rule that silently matches nothing.
func (f *ChangeFilter) Validate() error {
	if f == nil {
		return nil
	}
	for _, k := range f.ObjectKinds {
		if _, ok := dcim.ParseObjectKind(k); !ok {
			return fmt.Errorf("change_filter.object_kinds: unknown object kind %q", k)
		}
	}
	for _, a := range f.Actions {
		if !changeActions[a] {
			return fmt.Errorf("change_filter.actions: %q is not create, update or delete", a)
		}
	}
	return nil
}
