// Certificate trust status → what a person reads.
//
// `trust_status` is decided CENTRALLY by inventory-service for this tenant —
// not by whichever sensor happened to observe the certificate — so the label
// says where the chain ends from the organisation's point of view. Absent means
// the platform has not evaluated the certificate yet, and that is rendered as
// exactly that: never as "trusted" by default (spec §9).
//
// Pure and React-free on purpose: the certificate drawer chip uses it now, and
// slice 3's Trust facet and saved view will reuse the same labels, so the words
// a person filters by are the words the chip shows.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type TrustStatus = inventoryComponents['schemas']['TrustStatus'];

/** Semantic tone; map to a colour with TRUST_TONE_COLOR at the render site. */
export type TrustTone = 'ok' | 'warn' | 'danger' | 'muted';

export interface TrustPresentation {
  label: string;
  tone: TrustTone;
  /** One sentence for the drawer's Trust row. */
  explanation: string;
}

export const TRUST_STATUSES: readonly TrustStatus[] = [
  'public', 'private_trusted', 'self_signed', 'untrusted', 'distrusted', 'incomplete',
] as const;

const PRESENTATION: Record<TrustStatus, TrustPresentation> = {
  public: {
    label: 'Public CA',
    tone: 'ok',
    explanation: 'The chain ends at a public root that the platform trusts by default.',
  },
  private_trusted: {
    label: 'Trusted (your CA)',
    tone: 'ok',
    explanation: 'The chain ends at a certificate authority your organisation has trusted.',
  },
  self_signed: {
    label: 'Self-signed',
    tone: 'warn',
    explanation: 'The certificate signs itself, so no certificate authority vouches for it.',
  },
  untrusted: {
    label: 'Untrusted CA',
    tone: 'danger',
    explanation: 'The chain ends at a certificate authority nobody in your organisation has trusted.',
  },
  distrusted: {
    label: 'Distrusted CA',
    tone: 'danger',
    explanation: 'The chain ends at a certificate authority your organisation has explicitly distrusted.',
  },
  incomplete: {
    label: 'Chain incomplete',
    tone: 'warn',
    explanation: 'An issuer in the chain is not in inventory, so no trust decision can be made yet.',
  },
};

const NOT_EVALUATED: TrustPresentation = {
  label: 'Not yet evaluated',
  tone: 'muted',
  explanation: 'The platform has not evaluated this certificate’s trust yet.',
};

/**
 * Presentation for a certificate's trust status. Anything that is not one of
 * the contract's values — absent, null, or a value from a newer server — reads
 * as not evaluated rather than borrowing another status's meaning.
 */
export function trustPresentation(status: string | null | undefined): TrustPresentation {
  if (status && Object.prototype.hasOwnProperty.call(PRESENTATION, status)) {
    return PRESENTATION[status as TrustStatus];
  }
  return NOT_EVALUATED;
}

export const TRUST_TONE_COLOR: Record<TrustTone, string> = {
  ok: 'var(--ok)',
  warn: 'var(--warn-strong)',
  danger: 'var(--danger)',
  muted: 'var(--app-t3)',
};

// ------------------------------------------------------------------ filter --
//
// Slice 3: the same labels as a FILTER. `GET /certificates?trust_status=` takes
// a comma-separated list of the contract's values plus `unevaluated`, the
// contract's spelling for "trust has not been computed yet" (NULL). The filter
// offers that as its own choice because a freshly ingested certificate is
// neither trusted nor untrusted, and folding it into either would be a guess.

/** The filter value that selects certificates whose trust is not computed yet. */
export const TRUST_UNEVALUATED = 'unevaluated';

export type TrustFilterValue = TrustStatus | typeof TRUST_UNEVALUATED;

/** Every value the Trust filter offers, in the order it shows them. */
export const TRUST_FILTER_VALUES: readonly TrustFilterValue[] = [...TRUST_STATUSES, TRUST_UNEVALUATED];

/** The statuses "Untrusted certificates" means: nobody trusted the CA, or the
 *  organisation explicitly distrusted it. */
export const UNTRUSTED_TRUST_FILTER: readonly TrustFilterValue[] = ['untrusted', 'distrusted'];

/** Label + tone for a filter value. `unevaluated` reads exactly as the chip
 *  does for a certificate that has no status yet. */
export function trustFilterPresentation(value: TrustFilterValue): TrustPresentation {
  return value === TRUST_UNEVALUATED ? NOT_EVALUATED : trustPresentation(value);
}

function isTrustFilterValue(v: string): v is TrustFilterValue {
  return (TRUST_FILTER_VALUES as readonly string[]).includes(v);
}

/**
 * Reads a `trust_status`-style list (`untrusted,distrusted`) into filter values:
 * unknown words dropped, duplicates dropped, and in the filter's own order so
 * two spellings of one selection compare equal.
 */
export function parseTrustFilter(raw: string | null | undefined): TrustFilterValue[] {
  if (!raw) return [];
  const wanted = new Set(raw.split(',').map((s) => s.trim()).filter(isTrustFilterValue));
  return TRUST_FILTER_VALUES.filter((v) => wanted.has(v));
}

/** The query-parameter value for a selection, or undefined for "any". */
export function trustFilterParam(values: readonly string[]): string | undefined {
  const canonical = parseTrustFilter(values.join(','));
  return canonical.length > 0 ? canonical.join(',') : undefined;
}
