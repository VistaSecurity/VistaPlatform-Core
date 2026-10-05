// The Observations review table's decisions, out of the components so
// they can be tested without rendering: what each "needs" value and
// explanation code says in plain words, which bulk actions a selection allows,
// the reason a decision is proposed with, and what each per-row bulk failure
// tells the person.
//
// The SERVER decides what a row needs (`needs`, `suggested_action`,
// `explanation_code`, `suggested_reason`); nothing here re-derives that rule.
// A second copy of "is this ready to confirm" in TypeScript is exactly how the
// bulk bar would come to offer Confirm on a row the server then refuses.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type Observation = inventoryComponents['schemas']['IdentityObservation'];
export type ObservationNeeds = inventoryComponents['schemas']['ObservationNeeds'];
export type ObservationCounts = inventoryComponents['schemas']['ObservationNeedsCounts'];
export type ExplanationCode = Observation['explanation_code'];
export type BulkResult = inventoryComponents['schemas']['BulkObservationDecisionResult']['results'][number];
export type BulkFailureCode = NonNullable<BulkResult['code']>;
export type ObservationState = Observation['state'];

/** The bulk endpoint's ceiling on ids per request. */
export const MAX_BULK = 200;

// ---- chips -----------------------------------------------------------------

export type ChipKey = Exclude<ObservationNeeds, 'none'> | 'all';

/** In the order the table shows them. Ready to confirm is the default view (D3). */
export const CHIPS: { key: ChipKey; label: string }[] = [
  { key: 'ready_to_confirm', label: 'Ready to confirm' },
  { key: 'link_existing', label: 'Matches an asset' },
  { key: 'needs_review', label: 'Several match' },
  { key: 'needs_network', label: 'Needs a network' },
  { key: 'needs_sensor', label: 'Needs a sensor' },
  { key: 'likely_noise', label: 'Likely noise' },
  { key: 'all', label: 'All' },
];
export const DEFAULT_CHIP: ChipKey = 'ready_to_confirm';

export function isChipKey(v: unknown): v is ChipKey {
  return CHIPS.some((c) => c.key === v);
}

export function chipLabel(key: ChipKey): string {
  return CHIPS.find((c) => c.key === key)?.label ?? key;
}

/**
 * The chip an empty view suggests instead: the first OTHER needs chip with
 * something in it. Counts cover the unresolved window regardless of the
 * current filter, so this never sends a person to another empty view.
 */
export function nextNonEmptyChip(current: ChipKey, counts: ObservationCounts | undefined): ChipKey | null {
  if (!counts) return null;
  for (const c of CHIPS) {
    if (c.key === current || c.key === 'all') continue;
    if (counts[c.key] > 0) return c.key;
  }
  return current !== 'all' && counts.all > 0 ? 'all' : null;
}

// ---- plain words ------------------------------------------------------------

/** The collapsed row's "Needs" label. */
export const NEEDS_LABEL: Record<ObservationNeeds, string> = {
  ready_to_confirm: 'Ready to confirm',
  link_existing: 'Matches an asset',
  needs_review: 'Several match',
  needs_network: 'Needs a network',
  needs_sensor: 'Needs a sensor',
  likely_noise: 'Likely noise',
  none: 'Needs review',
};

const STATE_LABEL: Record<ObservationState, string> = {
  unresolved: 'Unresolved',
  linked: 'Linked',
  conflict: 'Identity conflict',
  dismissed: 'Dismissed',
  expired: 'Expired',
};

/** A decided row says what happened to it; an unresolved one says what it needs. */
export function needsLabel(o: Pick<Observation, 'needs' | 'state'>): string {
  return o.state === 'unresolved' ? NEEDS_LABEL[o.needs] : STATE_LABEL[o.state];
}

/** The collapsed row's primary-action label for a link suggestion: "Link to dream-router". */
export function linkLabel(o: Pick<Observation, 'link_asset'>): string {
  const name = o.link_asset?.name?.trim();
  return name ? `Link to ${name}` : 'Link to the existing asset';
}

export interface Explanation {
  /** Why the platform did not create an asset itself. */
  why: string;
  /** What will fix it. Empty when nothing is asked of the person. */
  fix: string;
}

/**
 * One sentence pair per explanation code. Typed as a total Record so a code the
 * server adds fails typecheck here instead of rendering a bare token.
 */
export const EXPLANATIONS: Record<ExplanationCode, Explanation> = {
  dynamic_address_answered: {
    why: 'A real device answered at this address, but this network uses DHCP, so an address alone cannot identify it.',
    fix: 'Confirming says you recognise it. The asset is created and then follows its network’s approval rules.',
  },
  owned_by_asset: {
    why: 'An asset you already have owns this address, so confirming it would create a second record of the same device.',
    fix: 'Link this observation to that asset. Its approval and history are kept.',
  },
  owned_by_several_assets: {
    why: 'More than one existing asset owns identifiers of this observation, so the platform cannot tell which one it belongs to.',
    fix: 'Compare those assets — merge them if they are the same device — or link this observation to the right one yourself, or dismiss it.',
  },
  network_not_configured: {
    why: 'This address is not inside any network you have set up.',
    fix: 'Add a network segment that covers it, and the platform can place this host — and others in the same range — itself.',
  },
  relayed_advertisement: {
    why: 'Another device advertised this name; nothing here saw the device itself.',
    fix: 'A sensor on that network lets the platform confirm it without you.',
  },
  no_collector_in_network: {
    why: 'No sensor can reach the network this was seen on, so the platform cannot check it.',
    fix: 'A sensor on that network lets the platform confirm it without you.',
  },
  name_only: {
    why: 'Only a name was seen — nothing to create an asset from.',
    fix: 'Dismiss it. If the device is real, it is picked up when something sees its address.',
  },
  no_address_or_service: {
    why: 'No address or service was seen — nothing to create an asset from.',
    fix: 'Dismiss it. If the device is real, it is picked up when something sees its address.',
  },
  not_seen_recently: {
    why: 'Nothing has seen this for more than 30 days.',
    fix: 'Dismiss it. If it is seen again, it is kept for review again.',
  },
  no_suggestion: {
    why: 'The platform kept this evidence but has no specific suggestion for it.',
    fix: 'Review the evidence, then confirm it, link it to an asset or dismiss it.',
  },
  not_awaiting_review: {
    why: 'This observation is not waiting for a decision.',
    fix: '',
  },
};

/** Identifier kinds that recognise the same device again on a DHCP network. */
const STABLE_KINDS = new Set(['ssh_host_key_fingerprint', 'mac_address', 'serial_number']);

/** "Its SSH host key will recognise it next time." — or null when it has none. */
export function stableIdentifierNote(o: Pick<Observation, 'summary'>): string | null {
  const stable = o.summary.find((s) => STABLE_KINDS.has(s.kind));
  return stable ? `Its ${stable.label.toLowerCase()} (${stable.value}) will recognise it next time.` : null;
}

// ---- failures --------------------------------------------------------------

/**
 * A failed bulk row, in its own words. Typed as a total Record over the
 * contract's failure codes for the same reason as EXPLANATIONS.
 */
export const BULK_FAILURE_COPY: Record<BulkFailureCode, string> = {
  asset_allowance_reached: 'The asset allowance has been reached. This observation is still saved; you can link it to an existing asset.',
  observation_changed: 'This changed since you looked — review it.',
  // The single-row form's wording for the same 409, so one situation reads the
  // same wherever it is met ( D6).
  provisional_item_requires_merge_review: 'This observation already backs a provisional inventory item. To combine it with another asset, use merge review from Inventory.',
  not_ready_to_confirm: 'This one is not ready for that in bulk — review it on its own.',
  not_found: 'This observation is gone — it was removed or decided elsewhere.',
  cancelled: 'The request ended before this one was reached. Try again.',
  internal_error: 'The decision could not be saved. Try again.',
};

export function bulkFailureMessage(r: Pick<BulkResult, 'code' | 'status'>): string {
  if (r.code && r.code in BULK_FAILURE_COPY) return BULK_FAILURE_COPY[r.code];
  return 'The decision could not be saved. Try again.';
}

// ---- bulk rules (D4) -------------------------------------------------------

/**
 * Bulk Confirm is homogeneous: every selected row must be ready to confirm.
 * Takes the CURRENT rows, never a remembered snapshot — a row that stopped
 * being ready after a refetch must turn Confirm off.
 */
export function canBulkConfirm(rows: Pick<Observation, 'needs' | 'suggested_action' | 'state'>[]): boolean {
  return rows.length > 0 && rows.length <= MAX_BULK
    && rows.every((r) => r.state === 'unresolved' && r.needs === 'ready_to_confirm' && r.suggested_action === 'confirm');
}

/**
 * Bulk Link is homogeneous too: every selected row must be a link suggestion
 * carrying its owner. The server links each to the owner it finds on the locked
 * row; the UI never names an asset.
 */
export function canBulkLink(rows: Pick<Observation, 'needs' | 'suggested_action' | 'state' | 'link_asset'>[]): boolean {
  return rows.length > 0 && rows.length <= MAX_BULK
    && rows.every((r) => r.state === 'unresolved' && r.needs === 'link_existing' && r.suggested_action === 'link' && !!r.link_asset);
}

/** Bulk Dismiss takes any non-empty selection within the ceiling. */
export function canBulkDismiss(rows: unknown[]): boolean {
  return rows.length > 0 && rows.length <= MAX_BULK;
}

/** Which rows can be ticked at all: the ones a decision still applies to. */
export function isSelectable(o: Pick<Observation, 'state'>): boolean {
  return o.state === 'unresolved' || o.state === 'expired';
}

// ---- reasons (D1) ----------------------------------------------------------

export type DecisionAction = 'confirm' | 'link' | 'dismiss';
const VERB: Record<DecisionAction, string> = { confirm: 'Confirmed', link: 'Linked', dismiss: 'Dismissed' };
// The server's sentences open with one of these two (the API contract says so).
const PREFIX = /^(Confirmed|Linked|Dismissed) from Observations: /;
/** A reason the decision endpoints accept. */
export const MAX_REASON = 2000;

/**
 * The reason a single-row decision is proposed with. The server proposes ONE
 * sentence, for the decision its suggestion leads to; when the person picks a
 * different decision the sentence keeps what was seen and changes the verb, and
 * a dismissal's "— why" clause is dropped because it only argues for dismissing.
 */
export function proposedReason(o: Pick<Observation, 'suggested_reason'>, action: DecisionAction): string {
  const s = o.suggested_reason.trim();
  const m = PREFIX.exec(s);
  if (!m) return s;
  if (m[1] === VERB[action]) return s;
  let body = s.slice(m[0].length);
  // The "— why" clause of a dismissal or a link only argues for that decision.
  if (m[1] === 'Dismissed' || m[1] === 'Linked') body = body.replace(/ — [^—]*\.$/, '.');
  return `${VERB[action]} from Observations: ${body}`;
}

/**
 * The one reason a batch carries. The bulk call takes a single reason, so a
 * batch gets a summary: the first row's own sentence and how many more it
 * stands for ("like it" only when every row shares one explanation).
 */
export function batchReason(rows: Pick<Observation, 'suggested_reason' | 'explanation_code'>[], action: DecisionAction): string {
  if (rows.length === 0) return '';
  const first = proposedReason(rows[0], action);
  if (rows.length === 1) return first.slice(0, MAX_REASON);
  const more = rows.length - 1;
  const alike = rows.every((r) => r.explanation_code === rows[0].explanation_code);
  const tail = `, and ${more} more${alike ? ' like it' : ''}.`;
  let head = (first || `${VERB[action]} from Observations: ${rows.length} observations`).replace(/\.$/, '');
  // "— already belongs to <asset>" names ONE row's owner; it does not stand for the batch.
  if (action === 'link') head = head.replace(/ — [^—]*$/, '');
  return (head.slice(0, MAX_REASON - tail.length) + tail);
}

// ---- reading the evidence --------------------------------------------------

export interface EvidenceEndpoint {
  address: string;
  fqdn: string;
  port: number;
  transport: string;
  protocol: string;
  service: string;
}

const str = (v: unknown) => (typeof v === 'string' ? v.trim() : '');

/** The evidence's endpoints, tolerating whatever a collector stored. */
export function evidenceEndpoints(o: Pick<Observation, 'evidence'>): EvidenceEndpoint[] {
  const raw = o.evidence.endpoints;
  if (!Array.isArray(raw)) return [];
  return raw.filter((e): e is Record<string, unknown> => typeof e === 'object' && e !== null).map((e) => ({
    address: str(e.address),
    fqdn: str(e.fqdn),
    port: typeof e.port === 'number' ? e.port : 0,
    transport: str(e.transport),
    protocol: str(e.protocol),
    service: str(e.service_name),
  }));
}

/** "SSH 22", "TLS 8443", "Port 161" — the same words the server's reason uses. */
export function serviceLabel(e: EvidenceEndpoint): string {
  let label = e.protocol.toUpperCase() || e.service || e.transport.toUpperCase();
  if (!label || label === 'NONE') label = 'Port';
  return e.port > 0 ? `${label} ${e.port}` : label;
}

export function serviceChips(o: Pick<Observation, 'evidence'>): string[] {
  return [...new Set(evidenceEndpoints(o).map(serviceLabel))];
}

/** The evidence's raw identifiers — the full values `summary` shortens. */
function evidenceIdentifier(o: Pick<Observation, 'evidence'>, kinds: string[]): string {
  const raw = o.evidence.identifiers;
  if (!Array.isArray(raw)) return '';
  for (const i of raw) {
    if (typeof i !== 'object' || i === null) continue;
    const { kind, value } = i as Record<string, unknown>;
    if (typeof kind === 'string' && kinds.includes(kind) && str(value)) return str(value);
  }
  return '';
}

/** The first value that is not empty — `??` would keep an empty string. */
const firstFilled = (...values: (string | undefined)[]) => values.find((v) => !!v?.trim())?.trim() ?? '';

/** The address the observation was seen at: its IP identifier, else the first endpoint's. */
export function observationAddress(o: Pick<Observation, 'evidence' | 'summary'>): string {
  return firstFilled(
    o.summary.find((s) => s.kind === 'ip_address')?.value,
    evidenceIdentifier(o, ['ip_address']),
    evidenceEndpoints(o).find((e) => e.address)?.address,
  );
}

/** What the row is called: its name, else its address. */
export function hostLabel(o: Pick<Observation, 'evidence' | 'summary'>): { primary: string; secondary: string } {
  const name = firstFilled(
    str(o.evidence.hostname),
    o.summary.find((s) => s.kind === 'hostname' || s.kind === 'fqdn')?.value,
    evidenceIdentifier(o, ['hostname', 'fqdn']),
  );
  const address = observationAddress(o);
  if (name) return { primary: name, secondary: address };
  return { primary: firstFilled(address, 'Unnamed device'), secondary: '' };
}

/**
 * The network column. `network_name` is null for the tenant default or a scope
 * that names no segment — the raw scope is an id, so it is never shown.
 */
export function networkLabel(o: Pick<Observation, 'network_name'>): string {
  return firstFilled(o.network_name ?? undefined, 'No configured network');
}

// ---- remembered view (per browser, a convenience only) ----------------------

const VIEW_KEY = 'vista.observations.view';
export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 50;

export interface RememberedView { chip: ChipKey; pageSize: number }

export function loadView(): RememberedView {
  const fallback = { chip: DEFAULT_CHIP, pageSize: DEFAULT_PAGE_SIZE };
  try {
    const raw = window.localStorage.getItem(VIEW_KEY);
    if (!raw) return fallback;
    const v = JSON.parse(raw) as { chip?: unknown; pageSize?: unknown };
    return {
      chip: isChipKey(v.chip) ? v.chip : DEFAULT_CHIP,
      pageSize: PAGE_SIZES.includes(v.pageSize as 25) ? (v.pageSize as number) : DEFAULT_PAGE_SIZE,
    };
  } catch {
    return fallback;
  }
}

export function saveView(v: RememberedView): void {
  try {
    window.localStorage.setItem(VIEW_KEY, JSON.stringify(v));
  } catch {
    // Storage blocked or full: the view just isn't remembered.
  }
}
