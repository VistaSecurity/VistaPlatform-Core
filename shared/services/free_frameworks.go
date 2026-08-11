package services

// FreeFrameworkCodes are the zero-cost platform compliance frameworks every
// edition ships, seeded by scripts/database/seed.sql.
//
// They do NOT count against the `compliance_frameworks_max` cap, and the cap
// does not block activating them. Without that carve-out a Core tenant could
// activate exactly one of the six: `compliance_frameworks_max` is 0 on the
// community, free and starter tiers, and the only exemption was
// `is_platform_default` — which a UNIQUE index (idx_platform_frameworks_single_default)
// restricts to a single framework, Best Practices. The other five free
// frameworks are published, advertised, priced at nothing, and were
// unreachable (CMP-6).
//
// The cap stays meaningful for what it was written for: the regulated
// Enterprise catalog (soc2, pci-dss, iso27001, nist-csf, iec-62351-3), which
// ships in the signed content bundle rather than seed.sql and is still counted
// and gated.
//
// This list is the Go half of a partition that is also enforced in
// scripts/audit-edition-boundary.mjs (FREE_FRAMEWORKS / REGULATED_FRAMEWORKS,
// run by `make audit`) and asserted in scripts/database/seed.sql's final
// summary block. free_frameworks_test.go fails if this list and the audit
// script's drift apart, so adding a free framework in one place without the
// other cannot ship quietly.
var FreeFrameworkCodes = []string{
	"best-practices",
	"pqc-readiness",
	"cert-hygiene",
	"cert-expiry-not-expired",
	"cert-expiry-30-day",
	"cert-expiry-90-day",
}
