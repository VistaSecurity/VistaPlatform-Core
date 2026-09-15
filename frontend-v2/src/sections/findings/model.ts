// Findings domain model — the vocabulary bridge between the two live streams
// (inventory-service crypto risks + compliance-engine framework evaluation)
// and the mock's presentation vocabulary (Findings.jsx CAT / ISSUE maps).
import type { inventoryComponents, complianceEngineComponents } from '@vistasecurity/api-contract';

export type CryptoRisk = inventoryComponents['schemas']['CryptoRisk'];
export type BatchResult = complianceEngineComponents['schemas']['BatchEvaluateResult'];
export type BatchFinding = complianceEngineComponents['schemas']['BatchFindingSummary'];
export type BatchControl = complianceEngineComponents['schemas']['BatchControlStatus'];
export type ComplianceFinding = complianceEngineComponents['schemas']['ComplianceFinding'];

/**
 * The subset of BatchControl the UI actually renders (just the name, in the
 * inspector drawer and workflow actions). Findings against a published-but-
 * unlicensed framework (#H-4b) resolve their control via GET
 * /frameworks/published/{id} instead of batch-evaluate (which skips unlicensed
 * frameworks), and that path has no status/severity/findings-count — only id +
 * title. BatchControl satisfies this type structurally, so either source works
 * wherever a ControlRef is expected.
 */
export type ControlRef = Pick<BatchControl, 'id' | 'name'>;

/**
 * The joined asset object GET /findings rides on each finding.
 *
 * Taken from the contract rather than restated here. This used to be a
 * hand-written interface, because the spec left `asset` an open object; phase 1
 * pinned it (FindingAsset in compliance-engine.openapi.yaml), and a second
 * hand-maintained copy of a type the generator emits is a drift source with no
 * upside. Read the field semantics there — in particular, `port` and
 * `ip_address` are null when no single endpoint answers for the finding, which
 * means "this asset has several faces", not "no port".
 *
 * `Partial` because `assetOf` substitutes `{}` for a finding whose target has
 * no joined object (a certificate resolves to `display_name` alone), so every
 * field has to be optional at the point of use.
 */
export type FindingAsset = Partial<complianceEngineComponents['schemas']['FindingAsset']>;
export const assetOf = (f: ComplianceFinding): FindingAsset => f.asset ?? {};

/**
 * The best available human label for a finding's target object.
 *
 * The joined `asset` object is usually the SUBJECT's own display object — a
 * certificate resolves to its common name there, an asset to its hostname — so
 * preferring it is right almost everywhere.
 *
 * `software_install` is the exception, and it produced a real defect. The
 * server resolves that subject to the HOST the package is installed on
 * (findings_service.go: "a row that named only the package would have no host
 * to show, no asset link and no environment"), so every end-of-life and
 * vulnerability finding on one machine rendered with the same label — the
 * machine's — and a host with nine end-of-life packages showed nine identical
 * rows. The package's own name is in `subject_label`, written by the producer
 * as product + version, and for this subject type that is the target. The host
 * is not lost: it is the CONTEXT line, see [subjectContext].
 */
export function targetLabel(f: ComplianceFinding): string {
  const a = assetOf(f);
  if (f.subject_type === 'software_install' && f.subject_label) return f.subject_label;
  return firstNonBlank(a.display_name, a.hostname, a.ip_address, f.subject_label)
    ?? f.subject_id.slice(0, 8);
}

/**
 * The first of these that is actually SOMETHING.
 *
 * Both fallback chains below need "non-blank", not "non-null": a joined asset
 * can carry `hostname: ''`, and an empty label has to fall through to the next
 * candidate rather than be rendered as a blank cell. So `a || b` is right here
 * and `a ?? b` is wrong — which means the lint rule that prefers `??` cannot be
 * satisfied by swapping the operator, and saying the rule once, by name, is the
 * honest way to satisfy it.
 */
function firstNonBlank(...vals: (string | null | undefined)[]): string | undefined {
  for (const v of vals) {
    if (v) return v;
  }
  return undefined;
}

/**
 * Where the subject LIVES, for a subject that is not itself the asset — the
 * second half of the software_install fix.
 *
 * Returns null when the asset would be repeating what [targetLabel] already
 * shows (a subject that IS the asset, or one with no joined host), because a
 * context line that echoes the title is noise the reader has to re-read before
 * discovering it says nothing.
 */
export function subjectContext(f: ComplianceFinding): string | null {
  if (f.subject_type !== 'software_install') return null;
  const a = assetOf(f);
  return firstNonBlank(a.display_name, a.hostname, a.ip_address) ?? null;
}

// `matchesFindingSearch` was here and is deliberately GONE (seeds part 3). The
// page's search box now goes to the server as `?q=`, because this function ran
// over a page-capped stream: a term matching only the 1,200th finding answered
// "no findings match". Re-adding it as a second belt would not be harmless —
// the server also matches the finding's KIND, so a narrower local pass would
// drop rows the server matched.

// Finding workflow vocabulary (backend: findings_service.go) with the mock's
// status colors (Findings.jsx FSTATUS).
export const WF_STATUSES = ['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'] as const;
export const WF_LABEL: Record<string, string> = { NEW: 'New', NOTIFIED: 'Notified', RESOLVED: 'Resolved', SUPPRESSED: 'Suppressed' };
export const WF_COLOR: Record<string, string> = { NEW: 'var(--info)', NOTIFIED: 'var(--warn)', RESOLVED: 'var(--ok)', SUPPRESSED: 'var(--neutral)' };
export const wfOf = (f: ComplianceFinding) => (f.workflow_status || 'NEW').toUpperCase();
export const isOpenWf = (f: ComplianceFinding) => { const w = wfOf(f); return w !== 'RESOLVED' && w !== 'SUPPRESSED'; };

// what KIND of thing failed — backend `category` values from the weak-crypto
// detector (protocol / algorithm / key_size / certificate).
export const CAT: Record<string, { label: string; icon: string }> = {
  protocol: { label: 'Protocol', icon: 'route' },
  algorithm: { label: 'Algorithm', icon: 'binary' },
  key_size: { label: 'Key size', icon: 'ruler' },
  certificate: { label: 'Certificate', icon: 'file-badge' },
  compliance: { label: 'Compliance', icon: 'scale' },
};
export const CAT_OPTS = ['All', 'Protocol', 'Algorithm', 'Key size', 'Certificate', 'Compliance'];

export const catOf = (risk: CryptoRisk) => CAT[risk.category] ?? { label: 'Other', icon: 'circle-alert' };

// human description of the failure, keyed by backend issue_type
const ISSUE: Record<string, string> = {
  weak_protocol: 'Weak protocol version in use',
  deprecated_protocol: 'Legacy protocol version in use',
  weak_cipher: 'Weak cipher negotiated',
  deprecated_cipher: 'Legacy cipher negotiated',
  weak_hash: 'Weak hash / MAC algorithm',
  deprecated_hash: 'Deprecated hash algorithm',
  weak_key_size: 'Inadequate key length',
  critically_weak_key_size: 'Critically weak key length',
};
export function issueLabel(risk: CryptoRisk): string {
  if (ISSUE[risk.issue_type]) return ISSUE[risk.issue_type];
  const t = risk.issue_type.replace(/_/g, ' ');
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : risk.description;
}

/**
 * Backend severities are the findings registry's lowercase ladder
 * (critical/high/medium/low/info).
 *
 * `med` is still accepted because a CONTROL's baseline_severity is authored in
 * the old vocabulary and reaches some surfaces unnormalized; the findings table
 * itself no longer stores it.
 */
export function sevLevel(s: string | undefined): string {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'medium': return 'Medium';
    case 'med': return 'Medium';
    case 'low': return 'Low';
    default: return 'Informational';
  }
}

/**
 * The severity rungs a `?severity=` URL filter may name, in the lowercase
 * spelling the endpoint's `severity` parameter takes.
 *
 * The Dashboard's "Critical findings" tile links through this
 * (DASHBOARD_CRITICAL_FINDINGS_ROUTE), because a tile that counts a subset must
 * link to that subset — the rule dashboard-metrics.ts already states for the
 * High-risk assets tile and could not honour here until the page had a severity
 * parameter to carry.
 *
 * `info` is omitted deliberately: nothing links to it and the ladder's bottom
 * rung is not a thing anyone narrows to on purpose.
 */
export const SEVERITY_FILTER_VALUES = ['critical', 'high', 'medium', 'low'] as const;
export type SeverityFilterValue = (typeof SEVERITY_FILTER_VALUES)[number];

/**
 * Read a `?severity=` value, or null when it names no rung.
 *
 * Validated rather than forwarded, because an unrecognized value would reach the
 * server, match nothing and render an empty page that reads exactly like "this
 * organization has no findings". An unparseable filter is treated as absent —
 * the page shows everything and shows NO filter banner, so what is on screen and
 * what the page claims to be showing still agree.
 *
 * Accepts `med` for Medium for the same reason sevLevel does.
 */
export function parseSeverityFilter(raw: string | null | undefined): SeverityFilterValue | null {
  const v = (raw ?? '').trim().toLowerCase();
  const canonical = v === 'med' ? 'medium' : v;
  return (SEVERITY_FILTER_VALUES as readonly string[]).includes(canonical)
    ? (canonical as SeverityFilterValue)
    : null;
}

/**
 * Does this toolbar chip control the SEVERITY axis?
 *
 * The Findings page has two severity controls — the `?severity=` URL filter the
 * Dashboard's Critical tile links through, and the local "Critical + High" chip
 * — and they are one axis, so picking the chip drops the URL filter rather than
 * intersecting with it. Left to intersect, arriving from the tile and then
 * clicking a chip labelled "Critical + High" shows Criticals only: a control
 * that reads as applied and is not.
 *
 * A function rather than an inline `k === 'crit'` so the rule is testable on its
 * own. The other chips are workflow/assignee controls and leave severity alone.
 */
export const SEVERITY_AXIS_SEGS = ['crit'] as const;
export function segOwnsSeverityAxis(seg: string): boolean {
  return (SEVERITY_AXIS_SEGS as readonly string[]).includes(seg);
}

const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
export const sevRank = (lvl: string) => SEV_RANK[lvl] ?? 4;

/**
 * The citation a finding carries, if it has one.
 *
 * A judgement made against a catalogue has to say which catalogue row it read,
 * and where a person can go and check it — ADR-0008 D4.4's "cite or refuse"
 * applies to a lookup exactly as it applies to a model. The `eol` producer puts
 * the endoflife.date page in `evidence.catalogue_source_url`; the
 * `vulnerability` producer puts each CVE's NVD page on its entry in
 * `evidence.cves`, worst-first, so the first one is the citation for the
 * headline severity.
 *
 * Returns null when nothing cited — which is the honest answer for the
 * `compliance` producer, whose findings cite a control rather than a URL, and
 * for a catalogue row an operator hand-entered without a source. A "Source"
 * link that went nowhere useful would be worse than none.
 *
 * Only http(s) is returned. `evidence` is JSONB written by a producer reading a
 * mirrored feed, which is one step removed from data we wrote ourselves; `href`
 * is a URL context where escaping does nothing, so a `javascript:` value has to
 * be refused rather than escaped.
 */
export function findingCitation(f: ComplianceFinding): { href: string; label: string } | null {
  const ev = (f.evidence ?? {}) as Record<string, unknown>;

  const direct = ev.catalogue_source_url;
  if (typeof direct === 'string' && isHttpURL(direct)) {
    return { href: direct, label: 'Catalogue entry' };
  }

  const cves = ev.cves;
  if (Array.isArray(cves) && cves.length > 0) {
    const first = cves[0] as Record<string, unknown> | undefined;
    const href = first?.source_url;
    const id = typeof first?.cve_id === 'string' ? first.cve_id : 'Advisory';
    if (typeof href === 'string' && isHttpURL(href)) return { href, label: id };
  }
  return null;
}

function isHttpURL(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}
