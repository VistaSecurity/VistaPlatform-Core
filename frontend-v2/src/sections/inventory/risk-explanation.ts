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
 *  `score` is the configuration's persisted `risk_score` (0 when unset). */
export function explainRisk(components: CryptoComponent[] | undefined, score: number | null | undefined): RiskExplanation {
  const list = Array.isArray(components) ? components : [];
  const assessed = list.length > 0;
  const worst = list.find((c) => c.sets_score) ?? (assessed ? list[0] : null);
  const offeredCount = list.filter((c) => c.is_inferred).length;
  const s = typeof score === 'number' && Number.isFinite(score) ? score : 0;

  if (!assessed) {
    return {
      assessed: false,
      components: [],
      worst: null,
      offeredCount: 0,
      headline: 'Not assessed',
      // Deliberately says what we DON'T know. "No risk factors found" would be
      // a clean bill of health we have not earned.
      caption:
        'Nothing on this configuration resolved against the algorithm catalogue, so it has not been assessed. ' +
        'This is not the same as being safe.',
      unexplainedRemainder: null,
    };
  }

  const worstScore = worst?.risk_score ?? 0;
  // Only report a remainder when the stored score genuinely exceeds what the
  // catalogue explains. A stored score BELOW the catalogue's worst just means
  // the catalogue moved since ingest — the panel shows live catalogue values
  // and does not need to editorialize about that.
  const remainder = s > worstScore ? s - worstScore : null;

  return {
    assessed: true,
    components: list,
    worst: worst ?? null,
    offeredCount,
    headline: worst ? `${componentTypeLabel(worst.algorithm_type)}: ${worst.code}` : 'Contributing components',
    caption: worst
      ? `Worst component — catalogue risk ${worst.risk_score} (${worst.risk_level}), ${PROVENANCE_LABEL[provenanceOf(worst)]}.`
      : '',
    unexplainedRemainder: remainder,
  };
}
