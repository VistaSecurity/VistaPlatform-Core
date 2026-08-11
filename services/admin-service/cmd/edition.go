package main

import (
	"github.com/vistasecurity/vistaplatform/admin-service/internal/api"
)

// hooks is the active edition for this binary.
//
// The zero value is the Core edition: every hook nil, meaning the billing
// routes are never mounted, the billing background workers never exist, and
// no Stripe code is linked in. That is a supported product configuration —
// Core's promise is platform administration (tenants, users, roles, settings,
// branding, legal, security, storage, tiers and entitlements), not
// monetization.
//
// The Enterprise/MSP build replaces this from an init() in cmd/edition_ee.go,
// which is guarded by `//go:build ee` and is the ONLY file in this service
// permitted to import services/admin-service/ee/. Neither that file nor the
// ee/ tree exists in the open-source repository, so a Core checkout cannot
// accidentally link Enterprise code — there is nothing to link.
//
// See internal/api/edition.go for the seam's contract and
// docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5 for the
// repo-wide pattern.
var hooks api.EditionHooks

// edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
func edition() string {
	return hooks.Edition()
}
