// Ticket categories — the one list.
//
// A ticket's category says what the ticket is ABOUT. There is one per finding
// producer (`@vistasecurity/primitives/findings`), plus the three that come
// from somewhere other than a finding: `certificate` (cert-lifecycle alerts),
// `operational` (the alert engine) and `general` (a person typing).
//
// Why this file exists at all: the same list is spelled out in four places —
// the `tickets_category_check` constraint in `scripts/database/schema.sql`,
// the Go validator in compliance-engine, the `TicketCategoryFilter` enum in
// `api/openapi/compliance-engine.openapi.yaml`, and here. Three of those are
// write gates and one is the UI. `scripts/audit-ticket-categories.mjs` reads
// all four and fails `make audit` if they disagree, so adding a category is
// four edits and the audit tells you which one you forgot.
//
// `remediation` is NOT here. It was the pre- catch-all and it is a verb,
// not a subject — nearly every ticket is remediation work, which is precisely
// how it came to hold weak crypto, quantum exposure, end-of-life software,
// configuration drift and CMDB hygiene as one undifferentiated bucket. It
// stays legal in the DB CHECK so rows written before the split still read;
// nothing writes it any more. `LEGACY_TICKET_CATEGORIES` carries it for the
// UI's benefit, because a queue that rendered a pre-split row with no label
// would be showing the user a blank.

/** A category something may be FILED under today. */
export type TicketCategory =
  | 'compliance'
  | 'certificate'
  | 'crypto'
  | 'pqc'
  | 'vulnerability'
  | 'lifecycle'
  | 'inventory'
  | 'configuration'
  | 'drift'
  | 'operational'
  | 'general';

/** A category that exists only on rows written before. Never written. */
export type LegacyTicketCategory = 'remediation';

export interface TicketCategoryDef {
  key: TicketCategory;
  /** Sentence-case label for menus, pills and column cells. */
  label: string;
  /** Icon name from the shared `Icon` set. */
  icon: string;
  /** One line, shown as help text under the category picker. */
  description: string;
  /**
   * The finding producer whose findings become tickets of this category, or
   * null when the category has a non-finding origin (an alert, or a person).
   */
  producer: 'compliance' | 'crypto' | 'eol' | 'vulnerability' | 'configuration' | 'hygiene' | 'drift' | null;
}

/** The category list, in the order the picker and the filter bar show it. */
export const TICKET_CATEGORIES: readonly TicketCategoryDef[] = [
  {
    key: 'compliance',
    label: 'Compliance',
    icon: 'shield-check',
    description: 'A framework control the inventory is failing.',
    producer: 'compliance',
  },
  {
    key: 'crypto',
    label: 'Cryptography',
    icon: 'key-round',
    description: 'Weak cipher, protocol version or key size on an observed configuration or certificate.',
    producer: 'crypto',
  },
  {
    key: 'pqc',
    label: 'PQC migration',
    icon: 'layers',
    description: 'Quantum-vulnerable cryptography that needs migrating before it is broken.',
    producer: 'crypto',
  },
  {
    key: 'certificate',
    label: 'Certificate',
    icon: 'file-badge',
    description: 'Certificate lifecycle — expiry, revocation, a broken or untrusted chain.',
    producer: null,
  },
  {
    key: 'vulnerability',
    label: 'Vulnerability',
    icon: 'circle-alert',
    description: 'A known CVE affecting software installed on an asset.',
    producer: 'vulnerability',
  },
  {
    key: 'lifecycle',
    label: 'End of life',
    icon: 'calendar-clock',
    description: 'An operating system, package or device past end-of-life or end-of-support.',
    producer: 'eol',
  },
  {
    key: 'inventory',
    label: 'Inventory hygiene',
    icon: 'list-checks',
    description: 'A gap in the inventory record itself — no owner, no class, no location, stale or a suspected duplicate.',
    producer: 'hygiene',
  },
  {
    key: 'configuration',
    label: 'Configuration',
    icon: 'server-cog',
    description: 'Insecure exposure — plaintext management, default credentials, a service that should not be reachable.',
    producer: 'configuration',
  },
  {
    key: 'drift',
    label: 'Drift',
    icon: 'git-compare',
    description: 'Something changed against its recent baseline — a new issuer, an unexpected protocol, a changed port profile.',
    producer: 'drift',
  },
  {
    key: 'operational',
    label: 'Operational',
    icon: 'activity',
    description: 'The platform itself — a sensor or agent offline, a service not responding.',
    producer: null,
  },
  {
    key: 'general',
    label: 'General',
    icon: 'file-text',
    description: 'Anything else worth tracking.',
    producer: null,
  },
];

/** Categories that may be written, in registry order. */
export const TICKET_CATEGORY_KEYS: readonly TicketCategory[] =
  TICKET_CATEGORIES.map((c) => c.key);

/** Retired categories: readable on old rows, never written. */
export const LEGACY_TICKET_CATEGORIES: readonly LegacyTicketCategory[] = ['remediation'];

const LEGACY_DEFS: Record<LegacyTicketCategory, TicketCategoryDef> = {
  remediation: {
    // Deliberately not in TICKET_CATEGORIES: offering this in the picker is
    // what re-creates the dumping ground.
    key: 'remediation' as unknown as TicketCategory,
    label: 'Remediation',
    icon: 'wrench',
    description: 'Filed before categories were split by subject.',
    producer: null,
  },
};

/**
 * The definition for a category key, including retired ones.
 *
 * Returns undefined for a key from neither list rather than a placeholder —
 * callers decide whether an unknown category is a bug or just something newer
 * than this bundle, and a fabricated label would hide both.
 */
export function ticketCategory(key: string | undefined | null): TicketCategoryDef | undefined {
  if (!key) return undefined;
  return (
    TICKET_CATEGORIES.find((c) => c.key === key) ??
    LEGACY_DEFS[key as LegacyTicketCategory]
  );
}

/** Whether `key` is a category a new ticket may be filed under. */
export function isWritableTicketCategory(key: string | undefined | null): key is TicketCategory {
  return !!key && TICKET_CATEGORIES.some((c) => c.key === key);
}

/**
 * The category a finding of this producer becomes when ticketed.
 *
 * `crypto` is the one producer that splits: its `pqc_vulnerable` kind is
 * quantum-migration work with a different timeline, a different owner and a
 * different remedy from a weak cipher suite, so it gets its own category. Pass
 * the finding's `kind` to get that split; without it the caller gets `crypto`,
 * which is the safe half — mislabelling PQC work as cryptography work is a
 * lesser error than the reverse.
 */
export function categoryForProducer(producer: string | undefined, kind?: string | null): TicketCategory {
  if (producer === 'crypto' && kind === 'pqc_vulnerable') return 'pqc';
  const match = TICKET_CATEGORIES.find((c) => c.producer === producer);
  return match ? match.key : 'general';
}
