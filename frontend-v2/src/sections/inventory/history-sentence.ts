// Readable sentences for the asset timeline's identity-drift entries.
//
// The History tab prints most entries as their raw action plus a dump of the
// changes object — fine for `updated`, unreadable for the four entries the
// identification engine writes when a device's identifying material changes
// under a match (owner Decision 4 of, shared/identity/drift.go). Those
// are the entries a person is most likely to arrive at from a notification
// ("SSH host key changed on db-primary"), so they get a sentence: what
// changed, from what to what, and whether anybody needs to look.
//
// Kept DOM-free so the wording is unit-testable on its own.
import type { AssetHistoryEntry } from './asset-queries';

/** The four drift actions, as asset_history spells them. */
export const DRIFT_ACTIONS = [
  'ssh_host_key_rotated',
  'address_moved',
  'identity_material_rotated',
  'identity_drift_flagged',
] as const;

export type HistorySentence = {
  /** The row's heading. */
  title: string;
  /** One line per material that changed: "SSH host key: A → B (old one retired)". */
  details: string[];
  /** The classifier's explanation — which signals agreed and which changed. */
  explanation?: string;
  /** True for an unconfirmed change a person should review. */
  needsReview: boolean;
};

type MaterialChange = { kind?: unknown; previous?: unknown; current?: unknown; retired?: unknown };

const MATERIAL_LABELS: Record<string, string> = {
  ssh_host_key_fingerprint: 'SSH host key',
  ip_address: 'Address',
  hostname: 'Name',
  tls_certificate: 'TLS certificate',
};

const TITLES: Record<(typeof DRIFT_ACTIONS)[number], string> = {
  ssh_host_key_rotated: 'SSH host key rotated',
  address_moved: 'Moved to a new address',
  identity_material_rotated: 'Reimaged: same hardware, new host key, certificate and name',
  identity_drift_flagged: 'SSH host key changed: needs review',
};

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : [];
}

function listOrNone(vs: string[]): string {
  return vs.length > 0 ? vs.join(', ') : 'none recorded';
}

function detailFor(c: MaterialChange, action: string): string | null {
  const kind = typeof c.kind === 'string' ? c.kind : '';
  const previous = strings(c.previous);
  const current = strings(c.current);
  if (previous.length === 0 && current.length === 0) return null;
  const label = MATERIAL_LABELS[kind] ?? kind.replace(/_/g, ' ');
  let line = `${label}: ${listOrNone(previous)} → ${listOrNone(current)}`;
  if (c.retired === true && previous.length > 0) {
    line += kind === 'ip_address' ? ' (old address released)' : ' (old one retired)';
  } else if (action === 'identity_drift_flagged' && previous.length > 0) {
    line += ' (both kept until reviewed)';
  }
  return line;
}

/**
 * The sentence for a drift entry, or null for any other action — the caller
 * renders those as it always has.
 */
export function historySentence(entry: Pick<AssetHistoryEntry, 'action' | 'changes'>): HistorySentence | null {
  const action = entry.action as (typeof DRIFT_ACTIONS)[number];
  if (!DRIFT_ACTIONS.includes(action)) return null;
  const changes = (entry.changes && typeof entry.changes === 'object' ? entry.changes : {}) as Record<string, unknown>;
  const materials = Array.isArray(changes.changes) ? (changes.changes as MaterialChange[]) : [];
  const details = materials.map((c) => detailFor(c, action)).filter((d): d is string => d !== null);
  const explanation = typeof changes.explanation === 'string' && changes.explanation !== '' ? changes.explanation : undefined;
  return {
    title: TITLES[action],
    details,
    explanation,
    needsReview: action === 'identity_drift_flagged' || changes.needs_review === true,
  };
}
