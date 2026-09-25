// Pure display-derivation for the crypto-configuration drawer's "Why this
// score" panel. No React, no network — plain data in, plain data out, so the
// honesty rules below are unit-testable directly (mirrors lens-helpers.ts).
//
// The rules this module exists to enforce:
//
//  1. **Score 0 / no components means NOT ASSESSED, not safe.** An empty
//     component list must never render as "no risk factors found". Nothing here
//     is allowed to produce a reassuring phrase from an absence of data.
//  2. **Observed and offered-only are different findings.** `is_inferred`
//     separates "this server negotiated it" from "this server would accept it
//     if asked". Both raise the score; they must not read identically.
//  3. **Banding is the backend's job.** `risk_level` arrives pre-banded from
//     models.RiskBands. Nothing here re-derives a ladder from a number.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type CryptoComponent = inventoryComponents['schemas']['CryptoComponentAssessment'];

/** How a component was established. `observed` = the handshake demonstrably
 *  used it. `offered` = the server exposes it but this session did not
 *  negotiate it (SSH), or it was derived from the suite name (TLS). */
export type Provenance = 'observed' | 'offered';

export function provenanceOf(c: CryptoComponent): Provenance {
  return c.is_inferred ? 'offered' : 'observed';
}

/** Short label for the provenance marker. Deliberately different WORDS, not
 *  just different colours — a colour-only distinction disappears for a
 *  colour-blind reader and in a screenshot. */
export const PROVENANCE_LABEL: Record<Provenance, string> = {
  observed: 'observed in use',
  offered: 'offered, not observed',
};

/** The long form, used as the marker's tooltip. States plainly that an offered
 *  algorithm still counts, so the reader doesn't conclude we scored a
 *  hypothetical. */
export const PROVENANCE_TITLE: Record<Provenance, string> = {
  observed: 'Observed in use — this was negotiated in the session we measured.',
  offered:
    'Offered but not observed — this server accepts it, but the session we measured did not use it. ' +
    'It still counts toward the score: any client that asks for it can have it.',
};

/** Human label for the junction role. The API returns storage vocabulary
 *  (`protocol_version`); the drawer speaks product vocabulary. */
export const COMPONENT_TYPE_LABEL: Record<string, string> = {
  protocol_version: 'Protocol version',
  cipher_suite: 'Cipher suite',
  key_exchange: 'Key exchange',
  signature: 'Signature',
  symmetric: 'Symmetric',
  hash: 'Hash',
};

export function componentTypeLabel(t: string | undefined): string {
  if (!t) return 'Component';
  return COMPONENT_TYPE_LABEL[t] ?? t.replace(/_/g, ' ');
}

/** One-phrase catalogue verdict, e.g. "weak · obsolete". Empty when the
 *  catalogue row records neither — an absent assessment is left absent rather
 *  than filled in with a guess. */
export function verdictOf(c: CryptoComponent): string {
  return [c.strength, c.deprecation_status]
    .map((s) => (s ?? '').trim())
    .filter((s) => s && s !== 'current')
    .join(' · ');
}

/** The "supports hybrid, negotiated classical" remediation hint ( W1.9).
 *
 *  The backend sets `hybrid_kex_available` on a classical key-exchange
 *  component only when a handshake proved the server ALSO accepts a hybrid
 *  post-quantum group — it decides "classical" from the catalogue and treats
 *  unknown support as no support, so nothing here second-guesses it beyond
 *  refusing to show the hint on a component that is not a classical key
 *  exchange.
 *
 *  The hint is guidance, not a verdict: the configuration still needs PQC
 *  migration because what it negotiated is classical, and the copy says so, so
 *  a reader does not take "your server supports hybrid" for "you are safe". */
export interface HybridKexHint {
  /** The sentence to show: what the server can do, what it did, what to change. */
  text: string;
  /** Why the risk score and PQC category have not moved. */
  note: string;
}

export function hybridKexHint(c: CryptoComponent): HybridKexHint | null {
  const avail = c.hybrid_kex_available;
  if (!avail || c.algorithm_type !== 'key_exchange' || c.is_pqc) return null;
  const groups = Array.isArray(avail.groups) ? avail.groups.filter((g) => typeof g === 'string' && g.trim() !== '') : [];
  const which = groups.length > 0 ? ` (${groups.join(', ')})` : '';
  return {
    text:
      `This server supports hybrid post-quantum key exchange${which}, but negotiated ${c.code}. ` +
      "Prefer the hybrid group in the server's configuration, or update the clients that connect to it.",
    note: 'Until a hybrid group is negotiated this configuration still counts as needing PQC migration, and its risk score is unchanged.',
  };
}

/** The catalogue's curated "how to fix this" for one component, shaped for
 *  display. Read from `remediation_guidance`, which the backend omits when the
 *  catalogue row records none — so a null here means "no guidance recorded",
 *  never "nothing to fix".
 *
 *  It is guidance only. Severity stays with the component's `risk_level`; the
 *  catalogue `timeline` is shown as the catalogue's suggestion, not re-derived
 *  into a band. */
export interface RemediationGuidanceView {
  summary: string | null;
  impact: string | null;
  /** Ordered steps with any leading "1." / "2)" the catalogue text carries
   *  stripped, because the drawer renders them in a numbered list. */
  steps: string[];
  timeline: string | null;
  cves: string[];
  /** `href` is set only for an http(s) URL. The catalogue is admin-edited free
   *  text, so anything else (a `javascript:` URL included) renders as text. */
  resources: { text: string; href: string | null }[];
}

const STEP_NUMBER = /^\s*\d+\s*[.)]\s+/;

function cleanList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map((x) => x.trim()) : [];
}

function cleanText(v: unknown): string | null {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

export function safeHref(v: string): string | null {
  try {
    const u = new URL(v);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}

export function remediationGuidanceOf(c: CryptoComponent): RemediationGuidanceView | null {
  const g = c.remediation_guidance;
  if (!g) return null;
  const view: RemediationGuidanceView = {
    summary: cleanText(g.summary),
    impact: cleanText(g.impact),
    steps: cleanList(g.steps).map((s) => s.replace(STEP_NUMBER, '')).filter((s) => s !== ''),
    timeline: cleanText(g.timeline),
    cves: cleanList(g.cve_references),
    resources: cleanList(g.resources).map((text) => ({ text, href: safeHref(text) })),
  };
  const empty = !view.summary && !view.impact && !view.timeline && view.steps.length === 0 && view.cves.length === 0 && view.resources.length === 0;
  return empty ? null : view;
}

export interface RiskExplanation {
  /** True only when at least one component resolved against the catalogue. */
  assessed: boolean;
  /** Components, worst first, exactly as the API ordered them. */
  components: CryptoComponent[];
  /** The component the backend marked as setting the score, if any. */
  worst: CryptoComponent | null;
  /** How many components are offered-only rather than observed. */
  offeredCount: number;
  /** Headline for the panel. Never reassuring when `assessed` is false. */
  headline: string;
  /** Sub-caption. Explains what unassessed means, or names the score-setter. */
  caption: string;
  /** Set when the configuration's stored score is HIGHER than any catalogue
   *  component can explain — i.e. part of the score came from the size /
   *  lifecycle detector, which is not attributable to a single catalogue row.
   *  Saying so beats implying the component list is the whole story. */
  unexplainedRemainder: number | null;
}

/** Build everything the panel renders from the API response plus the stored
 *  score, without ever converting an absence of data into a verdict.
 *
 *  `score` is the configuration's persisted `risk_score`, or null when the
 *  read-side evidence projection cannot establish a numeric assessment. */
export function explainRisk(components: CryptoComponent[] | undefined, score: number | null | undefined): RiskExplanation {
  const list = Array.isArray(components) ? components : [];
  const assessed = list.length > 0;
  const worst = list.find((c) => c.sets_score) ?? list.find((c) => typeof c.risk_score === 'number') ?? null;
  const offeredCount = list.filter((c) => c.is_inferred).length;
  const s = typeof score === 'number' && Number.isFinite(score) ? score : 0;

  if (!assessed) {
    const hasStoredScore = typeof score === 'number' && Number.isFinite(score);
    return {
      assessed: false,
      components: [],
      worst: null,
      offeredCount: 0,
      headline: 'No catalogue evidence',
      // A detector can supply a stored score even when no catalogue component
      // resolves. State only the evidence gap; do not turn it into a claim that
      // nobody assessed the configuration.
      caption: hasStoredScore
        ? `No catalogue components resolved; the existing risk score ${score} is not explained by this catalogue evidence.`
        : 'No catalogue components resolved, so this panel cannot explain a numeric risk score.',
      unexplainedRemainder: null,
    };
  }

  const worstScore = worst?.risk_score;
  // Only report a remainder when the stored score genuinely exceeds what the
  // catalogue explains. A stored score BELOW the catalogue's worst just means
  // the catalogue moved since ingest — the panel shows live catalogue values
  // and does not need to editorialize about that.
  const remainder = typeof worstScore === 'number' && s > worstScore ? s - worstScore : null;

  return {
    assessed: true,
    components: list,
    worst: worst ?? null,
    offeredCount,
    headline: worst ? `${componentTypeLabel(worst.algorithm_type)}: ${worst.code}` : 'Catalogue components resolved',
    caption: worst
      ? `Worst component — catalogue risk ${worst.risk_score} (${worst.risk_level}), ${PROVENANCE_LABEL[provenanceOf(worst)]}.`
      : 'The catalogue records qualitative judgments for these components, but no numeric risk score.',
    unexplainedRemainder: remainder,
  };
}
