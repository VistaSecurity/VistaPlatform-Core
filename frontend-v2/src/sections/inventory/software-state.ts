// How the software EOL and vulnerability columns read (workstream 3.8).
//
// The two columns exist because a software inventory that does not say whether
// a package is supported or exploitable is a list of names. They are fed by the
// per-install rollup the list endpoints carry, which is a READ of what the
// `eol` and `vulnerability` producers wrote — nothing here re-decides either.
//
// # The whole point is the last value
//
// Both axes are many-valued, and flattening either one is the failure this
// file is written against:
//
//   - `none_known` says the vulnerability producer HAD a machine identifier to
//     match on (a PURL or a CPE) and nothing matched. That is a reassuring
//     answer and it is earned.
//   - `not_assessed` says it had neither, skipped the install, and counted it
//     as unidentifiable. Rendering that as "0" claims a check that never ran.
//
// End of life reads the producer's own per-install record of what the
// lifecycle catalogue resolved, so a supported package can say so, a package
// the catalogue has never heard of says that, and a version whose entry
// publishes no date says that too. What is left in `not_assessed` is exactly
// "no completed pass has recorded an answer": the check has not run since the
// install was seen, the install is no longer present and was skipped, or its
// finding was closed by a person. It is deliberately not "Supported".
import type { inventoryComponents } from '@vistasecurity/api-contract';

import { FINDINGS_SUBJECT_LENS } from '../findings/lenses';

export type SoftwareEOLState = NonNullable<inventoryComponents['schemas']['SoftwareInstall']['eol_state']>;
export type SoftwareVulnState = NonNullable<inventoryComponents['schemas']['SoftwareInstall']['vulnerability_state']>;

/** What a cell shows: the words, the colour and the hover explanation. */
export interface StateCell {
  label: string;
  tone: string;
  title: string;
  /** True when there is something to link at. */
  actionable: boolean;
}

/**
 * Has this end-of-life date already passed?
 *
 * `days_remaining` is the producer's own arithmetic and is preferred whenever
 * it is there. It is NOT always there: the per-install rollup carries it, the
 * catalogue-row rollup does not (a product is installed on N assets and there
 * is no one countdown to state), so every row on the Inventory Software lens
 * arrives with the date and without the days. Reading the tense off
 * `days === undefined` therefore printed "Ends" for a version that
 * went out of support seven years ago — a wrong-tense claim about a date the
 * row is showing the reader at the same time.
 *
 * The date alone answers it, so the date alone is used when the days are
 * missing. `eol_date` is `YYYY-MM-DD` from the catalogue, which compares
 * lexicographically against today's ISO date; equal is NOT past, matching the
 * producer's ladder ("a product goes out of support at the END of its
 * end-of-life date").
 *
 * `now` is injectable so the boundary is testable without waiting for midnight.
 */
function eolDateHasPassed(date: string | null | undefined, now: Date): boolean {
  if (!date) return false;
  return date < now.toISOString().slice(0, 10);
}

/**
 * "Catalogue checked." — appended to the tooltip of every state the
 * producer actually recorded, so a reassuring answer carries its date. The
 * record's timestamp is an ISO date-time; the day is enough here.
 */
function checkedOn(assessedAt: string | null | undefined): string {
  return assessedAt ? ` Catalogue checked ${assessedAt.slice(0, 10)}.` : '';
}

/** The end-of-life cell. */
export function eolCell(row: {
  eol_state?: string | null;
  eol_date?: string | null;
  eol_days_remaining?: number | null;
  eol_severity?: string | null;
  eol_assessed_at?: string | null;
  /** The install's own status, when the row is an install rather than a catalogue product. */
  status?: string | null;
}, now: Date = new Date()): StateCell {
  switch (row.eol_state) {
    case 'end_of_life': {
      const days = row.eol_days_remaining;
      const past = typeof days === 'number' ? days < 0 : eolDateHasPassed(row.eol_date, now);
      const label = past
        ? `Ended ${row.eol_date ?? ''}`.trim()
        : `Ends ${row.eol_date ?? ''}`.trim();
      const detail = typeof days === 'number'
        ? past
          ? ` ${Math.abs(days).toLocaleString()} days ago.`
          : ` In ${days.toLocaleString()} days.`
        : '';
      return {
        label: label || 'End of life',
        // High severity is "past by more than a year" — the rung the producer's
        // own ladder escalates to — so it gets the strongest colour the table
        // uses.
        tone: row.eol_severity === 'high' ? 'var(--danger-text)' : past ? 'var(--warn-strong)' : 'var(--warn)',
        title: `The lifecycle catalogue's end-of-life date for this version.${detail} `
          + 'Click for the finding and its citation.',
        actionable: true,
      };
    }
    case 'supported':
      // The earned answer: the catalogue resolved this version and its date
      // is beyond the warning window. Said with the date, so the reader can
      // plan against it rather than take "supported" on trust.
      return {
        label: row.eol_date ? `Supported until ${row.eol_date}` : 'Supported',
        tone: 'var(--ok)',
        title: 'The lifecycle catalogue resolves this version to a support cycle whose end-of-life '
          + `date is further out than the warning window.${checkedOn(row.eol_assessed_at)}`,
        actionable: false,
      };
    case 'no_date':
      return {
        label: 'No date published',
        tone: 'var(--app-t3)',
        title: 'The lifecycle catalogue has an entry for this version but publishes no end-of-life '
          + 'date: the vendor has not announced one, or support ended on a date nobody recorded. '
          + `Neither "supported" nor "end of life" can be claimed.${checkedOn(row.eol_assessed_at)}`,
        actionable: false,
      };
    case 'not_in_catalogue':
      return {
        label: 'Not in catalogue',
        tone: 'var(--app-t3)',
        title: 'The lifecycle catalogue has no entry for this product, so its support status is '
          + `unknown. The gap is recorded for the catalogue's curators.${checkedOn(row.eol_assessed_at)}`,
        actionable: false,
      };
    default: {
      // `not_assessed`, an absent state, or a value this build does not know.
      // Defaulting to anything reassuring would invent an answer out of
      // missing data — the jq `//` mistake in a table cell.
      const inactive = typeof row.status === 'string' && row.status !== '' && row.status !== 'active';
      return {
        label: 'Not assessed',
        tone: 'var(--app-t3)',
        // Said out loud, because a dash here would read as "supported".
        title: inactive
          ? 'This install is no longer listed as present, so the lifecycle check does not run '
            + 'for it. That is not the same as "supported".'
          : 'No lifecycle answer has been recorded for this install: the check has not run since '
            + 'it was seen, or its end-of-life finding was closed. That is not the same as '
            + '"supported".',
        actionable: false,
      };
    }
  }
}

/** The vulnerability cell. */
export function vulnerabilityCell(row: {
  vulnerability_state?: string | null;
  vulnerability_count?: number | null;
  worst_cvss?: number | null;
}): StateCell {
  switch (row.vulnerability_state) {
    case 'vulnerable': {
      const n = row.vulnerability_count ?? 0;
      const cvss = row.worst_cvss;
      // A CVE nobody graded shows the COUNT and says the score is missing,
      // rather than printing 0.0 — which reads as harmless for exactly the
      // thing nobody has been able to grade.
      const score = typeof cvss === 'number' ? ` · CVSS ${cvss.toFixed(1)}` : ' · not scored';
      return {
        label: `${n.toLocaleString()}${score}`,
        tone: typeof cvss === 'number' && cvss >= 9 ? 'var(--danger-text)'
          : typeof cvss === 'number' && cvss >= 7 ? 'var(--warn-strong)'
            : 'var(--warn)',
        title: typeof cvss === 'number'
          ? `${n} advisory match${n === 1 ? '' : 'es'}, worst CVSS ${cvss.toFixed(1)}. Click for the CVE list.`
          : `${n} advisory match${n === 1 ? '' : 'es'}. The catalogue published no CVSS for any of them — `
            + 'that is "we could not grade this", not "harmless". Click for the CVE list.',
        actionable: true,
      };
    }
    case 'none_known':
      return {
        label: 'None known',
        tone: 'var(--ok)',
        title: 'This product carries a Package URL or a CPE, so the advisory catalogue could be '
          + 'searched for it, and nothing matched this version.',
        actionable: false,
      };
    default:
      return {
        label: 'Not assessed',
        tone: 'var(--app-t3)',
        title: 'This product carries neither a Package URL nor a CPE, so there is nothing to match '
          + 'against the advisory catalogue. "Could not be checked" is not "no known vulnerabilities".',
        actionable: false,
      };
  }
}

/**
 * The Findings page, filtered to ONE software install.
 *
 * `subject_type` and `subject_id` together — the endpoint refuses either alone,
 * because a lone id can collide across subject vocabularies and a lone type is
 * the producer filter under a worse name. Both are in the URL so the page is a
 * link somebody can paste.
 *
 * The producer is carried too, so clicking an end-of-life cell opens the
 * end-of-life finding rather than a page where it is one row among a package's
 * twelve CVEs.
 *
 * `lens` is not decoration. The Findings page's DEFAULT lens is `severity`,
 * which reads the CRYPTO-RISK stream — a different data set that knows nothing
 * about `subject_type`/`subject_id`/`producer`. A link without a lens therefore
 * landed on an unfiltered crypto list under a banner reading "Showing findings
 * on one software install only": a page that says it is filtered and is not.
 * FINDINGS_SUBJECT_LENS is the one findings-scoped lens that shows every
 * producer's rows, so the filters the link carries are the filters the reader
 * sees applied.
 */
export function installFindingsHref(installID: string, producer?: 'eol' | 'vulnerability'): string {
  const p = new URLSearchParams({
    lens: FINDINGS_SUBJECT_LENS,
    subject_type: 'software_install',
    subject_id: installID,
  });
  if (producer) p.set('producer', producer);
  return `/risk-compliance/findings?${p.toString()}`;
}

/**
 * The Findings page, filtered to every install of one catalogue PRODUCT.
 *
 * There is no single subject to name — a product may be installed on forty
 * assets, and the producers write one finding per INSTALL. So the catalogue
 * row links by producer and by a search for the product instead, which is the
 * closest honest thing: the count came from N installs, and the page shows the
 * findings on all of them.
 *
 * Same lens reason as installFindingsHref: `producer` and `q` are read only by
 * the findings-scoped lenses, so without one this landed on the crypto-risk
 * stream, which ignores both.
 */
export function productFindingsHref(name: string, producer: 'eol' | 'vulnerability'): string {
  return `/risk-compliance/findings?${new URLSearchParams({
    lens: FINDINGS_SUBJECT_LENS, producer, q: name,
  }).toString()}`;
}


/**
 * The "Last checked" cell: when the lifecycle catalogue last had an answer for
 * this row.
 *
 * It existed only inside the end-of-life tooltip, which made the freshness
 * question unanswerable at any scale — a tenant with two thousand products
 * could not find the stale corner of its catalogue without hovering every row
 * in it.
 *
 * "Never" is not a blank. A row no completed pass has ever recorded an answer
 * for is in a WEAKER state than one checked a year ago, and a dash there would
 * read as "nothing to report" — the same "not evaluated rendered as clean"
 * this file's other cells refuse. It is the state the sort puts FIRST.
 *
 * `now` is injectable so the boundaries are testable without waiting.
 */
export function lastCheckedCell(
  row: { eol_assessed_at?: string | null },
  now: Date = new Date(),
): StateCell {
  if (!row.eol_assessed_at) {
    return {
      label: 'Never',
      tone: 'var(--app-t3)',
      title: 'No completed lifecycle pass has recorded an answer for this row. That is not '
        + '"supported" and it is not "no news" — nobody has looked.',
      actionable: false,
    };
  }
  const day = row.eol_assessed_at.slice(0, 10);
  const days = Math.floor((now.getTime() - new Date(row.eol_assessed_at).getTime()) / 86_400_000);
  // A date the reader cannot place is not much better than none, so the age is
  // said in words alongside it. Negative ages (a clock skew, a record written
  // just now) read as "today" rather than "in -1 days".
  const age = days <= 0 ? 'today'
    : days === 1 ? 'yesterday'
      : days < 30 ? `${days} days ago`
        : days < 365 ? `${Math.floor(days / 30)} months ago`
          : `${Math.floor(days / 365)} year${days < 730 ? '' : 's'} ago`;
  return {
    label: day,
    // Amber past a quarter: the catalogue moves, so an answer older than that
    // is a claim about a world that has changed underneath it.
    tone: days >= 90 ? 'var(--warn)' : 'var(--app-t3)',
    title: `The lifecycle catalogue was last consulted for this row on ${day} (${age}).`,
    actionable: false,
  };
}
