//go:build !ee

package main

import "testing"

// The Core polarity of the edition seam.
//
// The pair of files edition_core_test.go / edition_ee_test.go is what makes
// "Core does not ship this" an assertion instead of a comment. Deleting the
// `//go:build ee` line from cmd/edition_ee.go — or forgetting to add a new
// hook to it — turns one of the two red.
//
// This matters more than it looks. A hook that is nil when it should not be
// gives a paying customer a 402 on a capability they bought; a hook that is
// non-nil in Core links Enterprise code into the open-source binary, which is
// the one thing the carve exists to prevent.

func TestCoreHasNoEnterpriseHooks(t *testing.T) {
	if hooks.RegisterCMDBSyncRoutes != nil {
		t.Error("Core has a CMDB sync hook; ee/ must not be linked into a Core build")
	}
	if hooks.RegisterNetBoxRoutes != nil {
		t.Error("Core has a NetBox routes hook; ee/ must not be linked into a Core build")
	}
	if hooks.StartNetBoxScheduler != nil {
		t.Error("Core has a NetBox scheduler hook; ee/ must not be linked into a Core build")
	}
	if edition() != "core" {
		t.Errorf("edition() = %q in a build without -tags ee", edition())
	}
}
