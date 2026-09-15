/**
 * Where an alert's subject leads.
 *
 * Every alert carries a typed subject — `subject_type` plus `subject_id` — and
 * the Alerts page rendered it as plain grey text. "Certificate expiring:
 * *.example.com" told you which certificate and then left you to go and find
 * it, which on a page whose whole job is triage is a dead end at exactly the
 * moment somebody wants to act.
 *
 * Two rules, and the second matters more than the first:
 *
 *  1. A destination must resolve by the ID THE ALERT CARRIES. A link to a list
 *     page that ignores the id is not a drill-through; it just moves the
 *     "go and find it" one click later.
 *  2. A subject type with no such destination gets NO link. A link that lands
 *     on an empty page reads as "nothing wrong with this object", which is the
 *     one thing it must never say. Plain text is honest; a false negative is
 *     not.
 *
 * `subjectHrefGaps` below records the types that fail rule 1 today, so the gap
 * is written down rather than rediscovered.
 */

import { FINDINGS_SUBJECT_LENS } from '../findings/lenses';

/** One alert's subject, as the API returns it. */
export type AlertSubject = {
  subject_type?: string;
  subject_id?: string;
  subject_label?: string;
};

/**
 * Alert subject types with no id-addressable destination today.
 *
 * - `sensor` / `agent` — Discovery → Sensors & Agents has no `?sensor=<id>`
 *   deep link; the page selects from its own list.
 * - `job` — same for Discovery → Discovery Jobs.
 * - `framework` — Risk & Compliance → Posture is not addressable by framework id.
 * - `user`, `tenant`, `service`, `channel` — platform-track and account
 *   subjects with no tenant-facing page keyed on the id.
 *
 * Adding a deep link to one of those pages is what unblocks each of these; the
 * mapping below is where it would then be wired.
 */
export const subjectHrefGaps = ['sensor', 'agent', 'job', 'framework', 'user', 'tenant', 'service', 'channel'];

/**
 * The href for an alert's subject, or null when there is no honest destination.
 *
 * - `asset` → the asset page, which is the object itself.
 * - `software_install` / `crypto_configuration` → Findings narrowed to that
 *   subject. The install has no page of its own, and the findings list takes
 *   `subject_type` + `subject_id` as a SERVER-side filter (the same pair the
 *   software surfaces already link with), so the destination is about exactly
 *   this subject and nothing else.
 * - `control` → Findings on the control lens, expanded to that control.
 * - `certificate` → the certificate lens, seeded with the subject's label,
 *   which is how the command palette already deep-links a certificate. It
 *   needs the LABEL: there is no `?cert=<id>` route, and a certificate alert
 *   whose label is missing therefore gets no link rather than a search for
 *   nothing.
 */
export function alertSubjectHref(a: AlertSubject): string | null {
  const id = a.subject_id;
  if (!a.subject_type || !id) return null;
  switch (a.subject_type) {
    case 'asset':
      return `/inventory/assets/${encodeURIComponent(id)}`;
    case 'software_install':
    case 'crypto_configuration':
      // FINDINGS_SUBJECT_LENS is not decoration. The Findings page's DEFAULT lens is
      // `severity`, which reads the CRYPTO-RISK stream — a different data set
      // that knows nothing about `subject_type`/`subject_id`. A link without a
      // lens therefore lands on an unfiltered crypto list under a banner
      // reading "Showing findings on one software install only": a page that
      // says it is filtered and is not. `producer` is the one findings-scoped
      // lens that shows every producer's rows, so the subject filter the link
      // carries is the filter the reader sees applied.
      return `/risk-compliance/findings?lens=${FINDINGS_SUBJECT_LENS}&subject_type=${encodeURIComponent(a.subject_type)}&subject_id=${encodeURIComponent(id)}`;
    case 'control':
      return `/risk-compliance/findings?lens=control&control=${encodeURIComponent(id)}`;
    case 'certificate': {
      const label = a.subject_label?.trim();
      return label ? `/inventory?lens=certificate&q=${encodeURIComponent(label)}` : null;
    }
    default:
      return null;
  }
}

/** What to show for the subject when there is nothing to link to. */
export function alertSubjectText(a: AlertSubject): string {
  // Written out rather than as a `||` chain because `??` is not a substitute
  // here — an EMPTY label has to fall through to the id, and the eslint rule
  // that prefers `??` would quietly change that.
  const label = a.subject_label?.trim();
  if (label) return label;
  const id = a.subject_id?.trim();
  if (id) return id;
  return '—';
}
