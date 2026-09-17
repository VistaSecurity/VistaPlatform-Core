// What a finding's evidence means, per producer.
//
// `evidence` is a free-shaped JSONB document — the one place the findings table
// does not pin a schema, deliberately, because every producer puts something
// different in it. That freedom stops at the UI: a drawer that rendered a raw
// object dump would make the citation, the CVSS score and the end-of-life date
// equally invisible. So each producer's shape is READ here, once, defensively,
// and the inspector renders the result.
//
// Everything below tolerates a malformed document and returns null / an empty
// list rather than throwing. The rows are written by a producer reading a
// mirrored feed — one step removed from data we wrote ourselves — and a drawer
// that throws takes the whole page with it.
import { FINDING_KINDS, FINDING_PRODUCERS } from '@vistasecurity/primitives/findings';
import type { ComplianceFinding } from './model';

/** The registry's display name for a producer key, or the key itself. */
export function producerLabel(key: string | undefined): string {
  return FINDING_PRODUCERS.find((p) => p.key === key)?.label ?? key ?? 'Unknown';
}

/**
 * A human label for a finding kind.
 *
 * Derived from the kind KEY rather than from a hand-kept map: the registry has
 * twenty-one kinds and six producers still to ship, and a map here would go
 * stale silently — a missing entry renders as a blank, not as an error. The
 * registry's `titleTemplate` is the per-finding headline and already lives on
 * the row's `summary`; this is the grouping label beside it.
 */
export function kindLabel(kind: string | undefined): string {
  if (!kind) return '—';
  const known = FINDING_KINDS.find((k) => k.key === kind);
  const raw = known?.key ?? kind;
  const words = raw.replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Whether the registry says this kind's score feeds the per-asset risk rollup. */
export function kindFeedsRisk(kind: string | undefined): boolean {
  return FINDING_KINDS.find((k) => k.key === kind)?.feedsRisk ?? false;
}

function ev(f: ComplianceFinding | undefined): Record<string, unknown> {
  return f?.evidence ?? {};
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

/** http(s) only. `href` is a URL context where escaping does nothing. */
export function isHttpURL(raw: unknown): raw is string {
  if (typeof raw !== 'string') return false;
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

/** The end-of-life detail behind an `eol` finding. */
export interface EOLEvidence {
  product: string | null;
  cycle: string | null;
  /** ISO date, as the catalogue row published it. */
  eolDate: string | null;
  extendedSupportDate: string | null;
  /** Negative once the date has passed. Null when the producer wrote none. */
  daysRemaining: number | null;
  observedVersion: string | null;
  /** The catalogue row id — the citation that survives a row with no URL. */
  catalogueId: string | null;
  sourceUrl: string | null;
}

/**
 * Reads an `eol` finding's evidence.
 *
 * Returns null when nothing end-of-life-shaped is there, so the caller renders
 * the generic block rather than a panel of dashes.
 */
export function eolEvidence(f: ComplianceFinding): EOLEvidence | null {
  const e = ev(f);
  const eolDate = str(e.eol_date);
  const catalogueId = str(e.catalogue_id);
  if (!eolDate && !catalogueId) return null;
  const days = e.days_remaining;
  return {
    product: str(e.catalogue_product),
    cycle: str(e.catalogue_cycle),
    eolDate,
    extendedSupportDate: str(e.extended_support_date),
    daysRemaining: typeof days === 'number' && Number.isFinite(days) ? days : null,
    observedVersion: str(e.observed_version),
    catalogueId,
    sourceUrl: isHttpURL(e.catalogue_source_url) ? e.catalogue_source_url : null,
  };
}

/** One CVE on a `vulnerability` finding. */
export interface CVEEntry {
  id: string;
  /** null when the catalogue has no CVSS for it — NOT the same as 0.0. */
  cvss: number | null;
  /** false only when the producer said so explicitly. */
  scored: boolean;
  vector: string | null;
  href: string | null;
  matchedBy: string | null;
}

/**
 * The CVE list a `vulnerability` finding carries, worst-first as the producer
 * sorted it.
 *
 * One finding per software INSTALL carries every CVE that matched it — the
 * identity index leaves no column for a CVE id, and the unit of remediation is
 * "upgrade this package" anyway. So this list is the whole content of the
 * finding, and the inspector has to render all of it: a drawer that showed only
 * the headline CVE would hide eleven of twelve.
 *
 * An entry with no score keeps `cvss: null` and `scored: false`. "We could not
 * grade this" is not "there is nothing here", and rendering it as 0.0 would be
 * the three-valued-logic collapse this codebase keeps paying for.
 */
export function cveList(f: ComplianceFinding): CVEEntry[] {
  const raw = ev(f).cves;
  if (!Array.isArray(raw)) return [];
  const out: CVEEntry[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as Record<string, unknown>;
    const id = str(rec.cve_id);
    if (!id) continue;
    const score = rec.cvss_score;
    const scored = rec.cvss_scored !== false && typeof score === 'number' && Number.isFinite(score);
    out.push({
      id,
      cvss: scored ? score : null,
      // Absent `cvss_scored` with a numeric score means scored; the producer
      // writes the key only when it is false.
      scored,
      vector: str(rec.cvss_vector),
      href: isHttpURL(rec.source_url) ? rec.source_url : null,
      matchedBy: str(rec.matched_by),
    });
  }
  return out;
}

/** A limitation that can be proved from the evidence already on findings. */
export interface AssessmentLimitations {
  unscoredCves: number;
  totalCves: number;
  unscoredSummaries: number;
  crypto: string[];
}

/**
 * Derives the visible assessment limit from every CVE entry, not from the
 * headline/worst CVE. A scored worst CVE can coexist with an unscored entry.
 *
 * Crypto completeness is intentionally absent here: current crypto evidence
 * contains resolved catalogue components only, so its length cannot establish
 * whether an observed component failed to resolve.
 */
export function assessmentLimitations(findings: ComplianceFinding[]): AssessmentLimitations | null {
  const cves = findings
    .filter((f) => f.producer === 'vulnerability')
    .flatMap(cveList);
  const unscoredCves = cves.filter((cve) => !cve.scored).length;
  // Older evidence can disclose an unscored headline without listing each CVE.
  // That proves a limitation, but supplies no denominator for a CVE count.
  const unscoredSummaries = findings.filter((f) => f.producer === 'vulnerability'
    && cveList(f).length === 0 && ev(f).worst_cvss_scored === false).length;
  const crypto = [...new Set(findings
    .filter((f) => f.producer === 'crypto')
    .flatMap((f) => cryptoEvidence(f)?.assessmentLimitations ?? []))];
  return unscoredCves > 0 || unscoredSummaries > 0 || crypto.length > 0
    ? { unscoredCves, totalCves: cves.length, unscoredSummaries, crypto }
    : null;
}

export function assessmentLimitText(limit: AssessmentLimitations): string {
  if (limit.unscoredSummaries > 0) return 'Assessment incomplete: matching vulnerability evidence includes an unscored CVE; the full CVE list is unavailable.';
  if (limit.unscoredCves === 0) return 'Assessment incomplete.';
  return `Assessment incomplete: ${limit.unscoredCves} of ${limit.totalCves} matching CVE${limit.totalCves === 1 ? '' : 's'} ${limit.unscoredCves === 1 ? 'has' : 'have'} no CVSS score.`;
}

/** How many CVEs the finding claims, for a header count. */
export function cveCount(f: ComplianceFinding): number {
  const n = ev(f).cve_count;
  if (typeof n === 'number' && Number.isFinite(n)) return n;
  return cveList(f).length;
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** The detail behind a `configuration` finding. */
export interface ConfigurationEvidence {
  /** The rule table's human name for the service, e.g. "Redis", "Telnet". */
  service: string | null;
  /** The rule id — the citation, so a disputed finding leads to the exact rule. */
  ruleId: string | null;
  /**
   * Which signal fired: `service_name` (something measured what is listening),
   * `port` (nothing did, and the port is all there was), or `fact` (the
   * interrogation's own `mgmt.plaintext`). They are NOT equally strong and the
   * drawer says which one it was.
   */
  matchedBy: 'service_name' | 'port' | 'fact' | null;
  /** The needle or the port that matched. */
  matched: string | null;
  /** One clause on why the service is unsafe to expose. */
  why: string | null;
  observedService: string | null;
  port: number | null;
  transport: string | null;
  /**
   * THREE-VALUED. `true` = loopback only, `false` = measured exposed to the
   * network, `null` = nobody established it (every endpoint a scan found).
   * Collapsing null into false would claim a measurement nobody took.
   */
  boundLocal: boolean | null;
  /** The management protocol, for a fact-derived finding. */
  mgmtProtocol: string | null;
  factSourceRef: string | null;
}

/**
 * Reads a `configuration` finding's evidence.
 *
 * Returns null when nothing configuration-shaped is there, so the caller falls
 * back to the generic block rather than rendering a panel of dashes.
 */
export function configurationEvidence(f: ComplianceFinding): ConfigurationEvidence | null {
  const e = ev(f);
  const matchedByRaw = str(e.matched_by);
  const ruleId = str(e.rule_id);
  if (!matchedByRaw && !ruleId) return null;
  const matchedBy =
    matchedByRaw === 'service_name' || matchedByRaw === 'port' || matchedByRaw === 'fact'
      ? matchedByRaw
      : null;
  return {
    service: str(e.service),
    ruleId,
    matchedBy,
    matched: str(e.matched),
    why: str(e.why),
    observedService: str(e.observed_service),
    port: num(e.port),
    transport: str(e.transport),
    boundLocal: typeof e.bound_local === 'boolean' ? e.bound_local : null,
    mgmtProtocol: str(e.mgmt_protocol),
    factSourceRef: str(e.fact_source_ref),
  };
}

/** The detail behind a `hygiene` finding. Every field is kind-specific. */
export interface HygieneEvidence {
  /** stale: how long since anything observed the subject, and when that was. */
  daysUnseen: number | null;
  lastSeenAt: string | null;
  /** no_class: the placeholder class the asset is stuck on. */
  classKey: string | null;
  /** duplicate_suspected: the Approvals proposal and the other record(s). */
  proposalId: string | null;
  otherAssetIds: string[];
  proposalReason: string | null;
  /** orphan_relationship: the edge, the end that is gone, and the survivor. */
  relationshipType: string | null;
  missingAssetLabel: string | null;
  missingReason: string | null;
  survivingAssetLabel: string | null;
}

/** Reads a `hygiene` finding's evidence. Null when nothing of it is there. */
export function hygieneEvidence(f: ComplianceFinding): HygieneEvidence | null {
  const e = ev(f);
  const out: HygieneEvidence = {
    daysUnseen: num(e.days_unseen),
    lastSeenAt: str(e.last_seen_at),
    classKey: str(e.class_key),
    proposalId: str(e.proposal_id),
    otherAssetIds: Array.isArray(e.other_asset_ids)
      ? e.other_asset_ids.filter((x): x is string => typeof x === 'string' && x !== '')
      : [],
    proposalReason: str(e.reason),
    relationshipType: str(e.relationship_type),
    missingAssetLabel: str(e.missing_asset_label),
    missingReason: str(e.missing_reason),
    survivingAssetLabel: str(e.surviving_asset_label),
  };
  const anything =
    out.daysUnseen !== null ||
    out.lastSeenAt !== null ||
    out.classKey !== null ||
    out.proposalId !== null ||
    out.relationshipType !== null ||
    out.missingAssetLabel !== null ||
    out.otherAssetIds.length > 0;
  return anything ? out : null;
}

/**
 * The asset a finding's subject belongs to, when the subject is not itself the
 * asset.
 *
 * The `eol` and `vulnerability` producers both write `evidence.asset_id` beside
 * a `software_install` subject, because a package has no page of its own and
 * "where is this installed?" is the first question a person asks. The joined
 * `asset` object on the row is the display path; this is the ID path, for a
 * ticket link and for a drill-through.
 */
export function subjectAssetID(f: ComplianceFinding): string | null {
  if (f.subject_type === 'asset') return f.subject_id;
  const id = str(ev(f).asset_id);
  return id;
}

/** What a `drift` finding compared, and what it saw. */
export interface DriftEvidence {
  /** The window in days, as the tenant had it set when the pass ran. */
  windowDays: number | null;
  /** ISO instants bounding the window. */
  windowStart: string | null;
  windowEnd: string | null;
  /**
   * The baseline, as the lines a person reads: "Protocols: TLS, SSH".
   *
   * Built from whatever the producer wrote rather than from a per-kind map,
   * because the four drift kinds each name their baseline differently
   * (`protocols`, `ports`, `issuers`, `classes_in_segment`) and a map here would
   * render a blank for the fifth.
   */
  baseline: { label: string; value: string }[];
  /** The observation, same treatment. */
  observed: { label: string; value: string }[];
  /** When the new thing was first seen, if the producer said. */
  firstObservedAt: string | null;
}

/** Evidence keys the drift panel must not render: bookkeeping, not evidence. */
const DRIFT_SKIP = new Set(['detail', 'observation_key', 'first_observed_at']);

/** `snake_case` → `Sentence case`, for a key the producer chose. */
function humanise(key: string): string {
  const words = key.replace(/_/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * Renders one baseline/observed sub-object into label/value lines.
 *
 * Arrays of strings and numbers join; scalars stringify; an array of objects is
 * skipped, because its per-entry detail is what would turn the drawer into a
 * JSON dump.
 */
function driftLines(raw: unknown): { label: string; value: string }[] {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [];
  const out: { label: string; value: string }[] = [];
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (DRIFT_SKIP.has(key)) continue;
    if (Array.isArray(value)) {
      const flat = value.filter((v): v is string | number => typeof v === 'string' || typeof v === 'number');
      if (flat.length === value.length) {
        // An EMPTY list is a real answer here — "nothing closed" is half of what
        // a port-profile finding says — so it renders as "none" rather than
        // vanishing into a row that was never there.
        out.push({ label: humanise(key), value: flat.length > 0 ? flat.join(', ') : 'none' });
      }
      continue;
    }
    if (typeof value === 'string' || typeof value === 'number') {
      out.push({ label: humanise(key), value: String(value) });
    }
  }
  return out;
}

/**
 * Reads a `drift` finding's evidence.
 *
 * Returns null when nothing drift-shaped is there, so the caller renders the
 * generic block rather than a panel of dashes.
 */
export function driftEvidence(f: ComplianceFinding): DriftEvidence | null {
  const e = ev(f);
  const baseline = driftLines(e.baseline);
  const observed = driftLines(e.observed);
  const days = e.window_days;
  const windowDays = typeof days === 'number' && Number.isFinite(days) ? days : null;
  if (baseline.length === 0 && observed.length === 0 && windowDays === null) return null;

  const obs = (e.observed ?? {}) as Record<string, unknown>;
  return {
    windowDays,
    windowStart: str(e.window_start),
    windowEnd: str(e.window_end),
    baseline,
    observed,
    firstObservedAt: str(obs.first_observed_at),
  };
}

/**
 * What a `crypto` finding measured, and where its number came from.
 *
 * The `crypto` producer (workstream 3.2) was the one producer with no evidence
 * panel: its findings reached the Findings page's inspector and fell through to
 * the generic "raised by the Crypto producer" card, while the producer had
 * written the whole derivation — the two scores it took the worse of, and the
 * catalogue components that produced them. The drawer therefore answered
 * "why this score?" for end-of-life, vulnerability, configuration, hygiene and
 * drift, and not for the producer whose entire output IS a score.
 *
 * One reader for all three kinds, because the kinds share a subject vocabulary
 * and differ only in which fields are present: `weak_configuration` carries the
 * protocol and its components, `weak_certificate` the key and signature
 * algorithms with the catalogue rows they matched, `pqc_vulnerable` the
 * Shor-breakable algorithm codes and the standard that says so.
 */
export interface CryptoEvidence {
  /** The score the finding carries — the WORSE of the two below. */
  score: number | null;
  /**
   * The two opinions, kept apart on purpose.
   *
   * `catalogueScore` is recomputed from the `algorithms` rows at pass time, so
   * a catalogue row corrected since ingest takes effect without re-observing
   * the service; `storedScore` is the verdict ingest persisted, which is where
   * key SIZE enters (no per-algorithm row can express an RSA-2048 floor).
   * Showing only the total would hide which of the two is driving it, and that
   * is the first thing a person disputing the score needs to know.
   */
  catalogueScore: number | null;
  storedScore: number | null;
  protocol: string | null;
  protocolVersion: string | null;
  cipherSuite: string | null;
  /** Worst first, straight from the catalogue rows. Never key material. */
  components: CryptoComponent[];
  /** weak_certificate: the algorithms judged, and what was wrong with them. */
  publicKeyAlgorithm: string | null;
  publicKeySize: number | null;
  signatureAlgorithm: string | null;
  riskFactors: string[];
  /** pqc_vulnerable: the Shor-breakable codes, and the standard behind them. */
  vulnerableAlgorithms: string[];
  authority: string | null;
  /** Exact gaps proved by the producer; absence does not prove completeness. */
  assessmentLimitations: string[];
  reassessmentRequired: boolean;
}

/** One catalogue component behind a configuration's score. */
export interface CryptoComponent {
  code: string;
  role: string | null;
  riskScore: number | null;
  strength: string | null;
  deprecationStatus: string | null;
}

/** Reads the `components` array the producer writes, dropping anything malformed. */
function cryptoComponents(raw: unknown): CryptoComponent[] {
  if (!Array.isArray(raw)) return [];
  const out: CryptoComponent[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const e = entry as Record<string, unknown>;
    const code = str(e.code);
    // A component with no code is not nameable, and a row reading "— (85)" is
    // worse than no row.
    if (!code) continue;
    out.push({
      code,
      role: str(e.role),
      riskScore: num(e.risk_score),
      strength: str(e.strength),
      deprecationStatus: str(e.deprecation_status),
    });
  }
  return out;
}

/** A list of non-empty strings, or []. */
function strList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((v): v is string => typeof v === 'string' && v !== '');
}

/**
 * Reads a `crypto` finding's evidence.
 *
 * Returns null when nothing crypto-shaped is there, so the caller falls back to
 * the generic block rather than rendering a panel of dashes.
 */
export function cryptoEvidence(f: ComplianceFinding): CryptoEvidence | null {
  const e = ev(f);
  const out: CryptoEvidence = {
    score: num(e.score),
    catalogueScore: num(e.catalogue_score),
    storedScore: num(e.stored_score),
    protocol: str(e.protocol),
    protocolVersion: str(e.protocol_version),
    cipherSuite: str(e.cipher_suite),
    components: cryptoComponents(e.components),
    publicKeyAlgorithm: str(e.public_key_algorithm) ?? str(e.key_algorithm),
    publicKeySize: num(e.public_key_size),
    signatureAlgorithm: str(e.signature_algorithm),
    riskFactors: strList(e.risk_factors),
    vulnerableAlgorithms: strList(e.vulnerable_algorithms),
    authority: str(e.authority),
    assessmentLimitations: strList(e.assessment_limitations),
    reassessmentRequired: e.reassessment_required === true,
  };
  const anything =
    out.score !== null ||
    out.protocol !== null ||
    out.components.length > 0 ||
    out.publicKeyAlgorithm !== null ||
    out.signatureAlgorithm !== null ||
    out.riskFactors.length > 0 ||
    out.vulnerableAlgorithms.length > 0 ||
    out.assessmentLimitations.length > 0 ||
    out.reassessmentRequired;
  return anything ? out : null;
}
