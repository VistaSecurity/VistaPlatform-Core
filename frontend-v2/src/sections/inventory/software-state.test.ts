// The software EOL / vulnerability columns (workstream 3.8).
//
// Every test here is a polarity test on the SAME thing: the third value must
// survive. `none_known` and `not_assessed` are the pair the vulnerability
// column exists to keep apart — one says the advisory catalogue was searched
// and nothing matched, the other says there was nothing to search with — and a
// cell that renders both as "0" undoes the distinction the producer refuses to
// make.
import { describe, expect, it } from 'vitest';
import { isFindingsLens } from '../findings/lenses';
import { eolCell, installFindingsHref, lastCheckedCell, productFindingsHref, vulnerabilityCell } from './software-state';

const INSTALL = '9c0e2a44-0000-4000-8000-0000000000aa';

describe('the vulnerability cell', () => {
  it('counts the CVEs and names the worst CVSS', () => {
    const c = vulnerabilityCell({ vulnerability_state: 'vulnerable', vulnerability_count: 12, worst_cvss: 9.8 });
    expect(c.label).toBe('12 · CVSS 9.8');
    expect(c.actionable).toBe(true);
  });

  it('says "not scored" rather than printing 0.0 for an ungraded CVE', () => {
    // The producer writes `worst_cvss_scored: false` beside a score of 0
    // precisely because "we could not grade this" is not "harmless". 0.0 on
    // screen would undo that one layer up — the jq `//` mistake in CSS.
    const c = vulnerabilityCell({ vulnerability_state: 'vulnerable', vulnerability_count: 1, worst_cvss: null });
    expect(c.label).toBe('1 · not scored');
    expect(c.label).not.toContain('0.0');
    expect(c.title).toContain('not "harmless"');
    expect(c.actionable).toBe(true);
  });

  it('distinguishes "nothing matched" from "nothing to match on"', () => {
    const checked = vulnerabilityCell({ vulnerability_state: 'none_known' });
    const unchecked = vulnerabilityCell({ vulnerability_state: 'not_assessed' });
    expect(checked.label).toBe('None known');
    expect(unchecked.label).toBe('Not assessed');
    expect(checked.label).not.toBe(unchecked.label);
    // And neither is a link: there is nothing behind them, and a link that
    // opens an empty page is how a reader learns to stop trusting the column.
    expect(checked.actionable).toBe(false);
    expect(unchecked.actionable).toBe(false);
  });

  it('never renders an unassessed install as a zero', () => {
    // The whole point, stated as its own assertion so deleting the branch
    // above cannot quietly lose it.
    const c = vulnerabilityCell({ vulnerability_state: 'not_assessed', vulnerability_count: 0 });
    expect(c.label).not.toMatch(/^0/);
    expect(c.title).toContain('not "no known vulnerabilities"');
  });

  it('treats an absent state as unassessed, not as clean', () => {
    // A row from an older server, or a shape change nobody noticed. Defaulting
    // to `none_known` would invent a reassuring answer out of missing data.
    expect(vulnerabilityCell({}).label).toBe('Not assessed');
  });
});

describe('the end-of-life cell', () => {
  it('reads a passed date as ENDED, with the date', () => {
    const c = eolCell({ eol_state: 'end_of_life', eol_date: '2023-09-11', eol_days_remaining: -731, eol_severity: 'high' });
    expect(c.label).toBe('Ended 2023-09-11');
    expect(c.title).toContain('731 days ago');
    expect(c.actionable).toBe(true);
  });

  it('reads an approaching date as ENDS', () => {
    const c = eolCell({ eol_state: 'end_of_life', eol_date: '2027-01-31', eol_days_remaining: 40, eol_severity: 'low' });
    expect(c.label).toBe('Ends 2027-01-31');
    expect(c.title).toContain('In 40 days');
  });

  it('says "Not assessed", never "Supported", when no answer was recorded', () => {
    // This is the honest half and it is easy to get wrong in the reassuring
    // direction. `not_assessed` now means exactly "no completed pass has
    // recorded an answer" — the check has not run since the install was seen,
    // the install is gone and was skipped, or its finding was closed — and
    // none of those means "supported".
    const c = eolCell({ eol_state: 'not_assessed' });
    expect(c.label).toBe('Not assessed');
    expect(c.label).not.toMatch(/supported/i);
    expect(c.title).toContain('not the same as "supported"');
    expect(c.actionable).toBe(false);
  });

  it('gives a SUPPORTED package its credit, with the date it is supported until', () => {
    // The producer recorded that the catalogue resolved this version to a
    // cycle whose date is beyond the warning window. That answer is earned —
    // the catalogue was asked and answered with a date — and it used to be
    // rendered identically to "never heard of it".
    const c = eolCell({ eol_state: 'supported', eol_date: '2028-04-01', eol_assessed_at: '2026-09-12T02:00:00Z' });
    expect(c.label).toBe('Supported until 2028-04-01');
    expect(c.tone).toBe('var(--ok)');
    expect(c.title).toContain('Catalogue checked 2026-09-12');
    // Nothing to link at: there is no finding behind a supported package.
    expect(c.actionable).toBe(false);
  });

  it('distinguishes "not in the catalogue" from "in it, with no date"', () => {
    // Two different problems with two different fixes — one belongs on the
    // catalogue's gap list, the other is with the vendor — and both used to
    // be one silence. Neither is "supported" and neither is "end of life".
    const miss = eolCell({ eol_state: 'not_in_catalogue' });
    const noDate = eolCell({ eol_state: 'no_date' });
    expect(miss.label).toBe('Not in catalogue');
    expect(noDate.label).toBe('No date published');
    expect(miss.label).not.toBe(noDate.label);
    for (const c of [miss, noDate]) {
      expect(c.label).not.toMatch(/supported/i);
      expect(c.actionable).toBe(false);
    }
    expect(noDate.title).toContain('Neither "supported" nor "end of life"');
  });

  it('never renders any recorded non-finding state as a link', () => {
    // A link that opens an empty Findings page is how a reader learns to stop
    // trusting the column. Only an open finding is clickable.
    for (const state of ['supported', 'no_date', 'not_in_catalogue', 'not_assessed']) {
      expect(eolCell({ eol_state: state, eol_date: '2028-04-01' }).actionable).toBe(false);
    }
    expect(eolCell({ eol_state: 'end_of_life', eol_date: '2028-04-01' }).actionable).toBe(true);
  });

  it('explains an install that is no longer present rather than a generic "not assessed"', () => {
    // The producer skips non-active installs and the sweep removes their
    // record. The row knows its own status, so the tooltip can say why the
    // check did not run instead of listing every possibility.
    const gone = eolCell({ eol_state: 'not_assessed', status: 'removed' });
    expect(gone.label).toBe('Not assessed');
    expect(gone.title).toContain('no longer listed as present');
    expect(gone.title).toContain('not the same as "supported"');
    // An ACTIVE install with no answer gets the other explanation.
    const fresh = eolCell({ eol_state: 'not_assessed', status: 'active' });
    expect(fresh.title).not.toContain('no longer listed');
    expect(fresh.title).toContain('has not run since');
  });

  it('treats an absent or unknown state as not assessed, never as supported', () => {
    // A row from an older server, or a value this build has never heard of.
    // Defaulting to `supported` would invent a reassuring answer out of
    // missing data.
    expect(eolCell({}).label).toBe('Not assessed');
    expect(eolCell({ eol_state: 'something_new' }).label).toBe('Not assessed');
    expect(eolCell({ eol_state: 'something_new', eol_date: '2028-04-01' }).label).not.toMatch(/supported/i);
  });

  it('survives a finding with no date recorded', () => {
    const c = eolCell({ eol_state: 'end_of_life' });
    expect(c.label).toBe('Ends');
    expect(c.actionable).toBe(true);
  });

  // The catalogue-row rollup carries the DATE and not the countdown — a product
  // is installed on N assets and there is no one number of days to state — so
  // every row on the Inventory Software lens arrives here without
  // `eol_days_remaining`. Reading the tense off the countdown's absence printed
  // "Ends" for a version that went out of support seven years ago,
  // beside the date that says otherwise.
  const NOW = new Date('2026-09-12T00:00:00Z');

  it('reads a PAST date as ENDED even with no days remaining — the Software lens row', () => {
    const c = eolCell({ eol_state: 'end_of_life', eol_date: '2019-01-14', eol_severity: 'high' }, NOW);
    expect(c.label).toBe('Ended 2019-01-14');
    expect(c.label).not.toContain('Ends');
    // No countdown to quote, so the tooltip states none rather than inventing
    // one. It must not claim "0 days ago".
    expect(c.title).not.toMatch(/days ago/);
  });

  it('still reads a FUTURE date as ENDS with no days remaining', () => {
    // The other polarity. Dating everything "Ended" would be the same wrong
    // claim pointed the other way.
    const c = eolCell({ eol_state: 'end_of_life', eol_date: '2027-01-31', eol_severity: 'low' }, NOW);
    expect(c.label).toBe('Ends 2027-01-31');
  });

  it('treats the end-of-life date ITSELF as not yet past', () => {
    // The producer's ladder: "a product goes out of support at the END of its
    // end-of-life date, not at the start of it."
    expect(eolCell({ eol_state: 'end_of_life', eol_date: '2026-09-12' }, NOW).label).toBe('Ends 2026-09-12');
  });

  it('prefers the producer own countdown when it is there', () => {
    // A per-install row carries `days_remaining`; the date comparison is the
    // fallback, not a second opinion that can override it.
    const c = eolCell({ eol_state: 'end_of_life', eol_date: '2027-01-31', eol_days_remaining: -3 }, NOW);
    expect(c.label).toBe('Ended 2027-01-31');
    expect(c.title).toContain('3 days ago');
  });
});

describe('the last-checked cell', () => {
  const now = new Date('2026-09-14T12:00:00Z');

  it('says "Never" when no pass has recorded an answer', () => {
    // Not a dash. A dash reads as "nothing to report", and nobody having
    // looked is a WEAKER state than an old answer — the same distinction the
    // eol and vulnerability cells refuse to flatten.
    const c = lastCheckedCell({}, now);
    expect(c.label).toBe('Never');
    expect(c.title).toContain('nobody has looked');
  });

  it('treats an explicit null the same as an absent field', () => {
    expect(lastCheckedCell({ eol_assessed_at: null }, now).label).toBe('Never');
  });

  it('shows the day, and says how long ago in words', () => {
    const c = lastCheckedCell({ eol_assessed_at: '2026-09-12T03:11:00Z' }, now);
    expect(c.label).toBe('2026-09-12');
    expect(c.title).toContain('2 days ago');
  });

  it('warns once an answer is older than a quarter', () => {
    // The catalogue moves. An answer older than that is a claim about a world
    // that has changed underneath it, and the colour is the only thing that
    // says so on a table of fifty rows.
    const fresh = lastCheckedCell({ eol_assessed_at: '2026-08-01T00:00:00Z' }, now);
    const stale = lastCheckedCell({ eol_assessed_at: '2025-08-01T00:00:00Z' }, now);
    expect(fresh.tone).not.toBe('var(--warn)');
    expect(stale.tone).toBe('var(--warn)');
  });

  it('does not print a negative age for a record written just now', () => {
    // Clock skew between the database and the browser is ordinary, and
    // "in -1 days" is the kind of detail that makes a reader distrust the
    // whole column.
    expect(lastCheckedCell({ eol_assessed_at: '2026-09-14T13:00:00Z' }, now).title).toContain('today');
  });

  it('is never a link — there is nothing on the other side of a timestamp', () => {
    expect(lastCheckedCell({ eol_assessed_at: '2026-09-12T03:11:00Z' }, now).actionable).toBe(false);
    expect(lastCheckedCell({}, now).actionable).toBe(false);
  });
});

describe('the links out', () => {
  it('sends BOTH halves of the subject filter, because the endpoint refuses either alone', () => {
    const href = installFindingsHref(INSTALL, 'vulnerability');
    const p = new URL(href, 'https://x').searchParams;
    expect(p.get('subject_type')).toBe('software_install');
    expect(p.get('subject_id')).toBe(INSTALL);
    expect(p.get('producer')).toBe('vulnerability');
  });

  it('carries the producer, so an end-of-life cell does not open a page of CVEs', () => {
    expect(new URL(installFindingsHref(INSTALL, 'eol'), 'https://x').searchParams.get('producer')).toBe('eol');
  });

  it('omits the producer when none is asked for', () => {
    expect(new URL(installFindingsHref(INSTALL), 'https://x').searchParams.has('producer')).toBe(false);
  });

  it('lands on the Findings page', () => {
    expect(installFindingsHref(INSTALL).startsWith('/risk-compliance/findings?')).toBe(true);
    expect(productFindingsHref('log4j', 'eol').startsWith('/risk-compliance/findings?')).toBe(true);
  });

  // The lens a software link lands on has to be one that reads the FINDINGS
  // table. The Findings page's default lens is `severity`, which reads the
  // crypto-risk stream and ignores subject_type/subject_id/producer/q entirely
  // — so a link without a lens rendered an unfiltered crypto list under a
  // banner reading "Showing findings on one software install only": a page that
  // says it is filtered and is not. Asserted against the page's own lens
  // registry rather than the literal string, so a lens rename cannot leave this
  // passing while the link breaks.
  //
  // Mutation-proven: drop `lens` from either builder and both cases go red.
  it.each([
    ['an install link', () => installFindingsHref(INSTALL, 'vulnerability')],
    ['an install link with no producer', () => installFindingsHref(INSTALL)],
    ['a product link', () => productFindingsHref('openssl 3.0', 'eol')],
  ] as const)('%s lands on a lens that can honour its filters', (_name, build) => {
    const lens = new URL(build(), 'https://x').searchParams.get('lens');
    expect(lens).toBeTruthy();
    expect(isFindingsLens(lens!)).toBe(true);
  });

  it('a catalogue row links by producer and product name, having no single subject', () => {
    // A product is installed on N assets and the producers write one finding
    // per INSTALL, so there is no one subject id to name. Searching by name is
    // the closest honest target.
    const p = new URL(productFindingsHref('openssl 3.0', 'vulnerability'), 'https://x').searchParams;
    expect(p.get('producer')).toBe('vulnerability');
    expect(p.get('q')).toBe('openssl 3.0');
    expect(p.has('subject_id')).toBe(false);
  });
});
