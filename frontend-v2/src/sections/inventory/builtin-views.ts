// Views every tenant has, beside the ones people save (ADR-0006 D2: a view is
// exactly its query text).
//
// "Never scanned" is what Discovery → Active Scan listed before it was folded
// into Inventory: every asset no active or automatic scan has reached.
// It is the query the API's `unscanned_only` parameter translates to
// (inventory-service legacyFilterTerms), so the view and that parameter can
// never disagree about which assets are unscanned.
import { UNTRUSTED_TRUST_FILTER, trustFilterParam, type TrustFilterValue } from './trust-status';

export const NEVER_SCANNED_QUERY = 'not endpoint:(exists(last_scanned)) and not exists(last_scanned)';

export interface BuiltinView {
  name: string;
  query: string;
  description: string;
}

export const BUILTIN_VIEWS: readonly BuiltinView[] = [
  {
    name: 'Never scanned',
    query: NEVER_SCANNED_QUERY,
    description: 'Assets no active or automatic scan has reached yet. Tick them and choose Scan.',
  },
];

/** All assets with a query, as a link. */
export function assetsLensHref(query: string): string {
  return `/inventory?lens=assets&query=${encodeURIComponent(query)}`;
}

/** Where Discovery → Active Scan, and every link to it, goes now. */
export const NEVER_SCANNED_HREF = assetsLensHref(NEVER_SCANNED_QUERY);

// ------------------------------------------------------- certificates lens --
//
// The Certificates lens is not query-language driven: it filters through
// `GET /certificates` parameters, so its built-in views are a parameter
// selection rather than query text. The selection lives in the URL
// (`?lens=certificate&trust=…`) for the same reason a query does — a view you
// cannot link to is a view you cannot hand to someone.

export interface CertificateBuiltinView {
  name: string;
  /** `trust_status` values, as the lens's Trust filter writes them. */
  trust: readonly TrustFilterValue[];
  description: string;
}

/** "Untrusted certificates" ( slice 3): the chain ends at a CA nobody in
 *  the organisation trusted, or at one it explicitly distrusted. */
export const UNTRUSTED_CERTIFICATES_VIEW: CertificateBuiltinView = {
  name: 'Untrusted certificates',
  trust: UNTRUSTED_TRUST_FILTER,
  description: 'Certificates whose chain ends at a CA your organisation has not trusted, or has distrusted.',
};

export const CERTIFICATE_BUILTIN_VIEWS: readonly CertificateBuiltinView[] = [UNTRUSTED_CERTIFICATES_VIEW];

/** The Certificates lens with a Trust selection, as a link. */
export function certificatesLensHref(trust: readonly string[]): string {
  const param = trustFilterParam(trust);
  return param ? `/inventory?lens=certificate&trust=${param}` : '/inventory?lens=certificate';
}

/** Where the dashboard's "Untrusted certificates" tile goes. */
export const UNTRUSTED_CERTIFICATES_HREF = certificatesLensHref(UNTRUSTED_CERTIFICATES_VIEW.trust);
