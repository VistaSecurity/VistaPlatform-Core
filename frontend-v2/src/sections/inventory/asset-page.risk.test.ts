import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  topRiskFinding, assessedBySentence, findingAnchor, findingLinkTo, selectedFindingID,
} from './asset-page';
import type { ComplianceFinding } from '../findings/model';

/**
 * The two sentences the Overview tab says about risk, and both of them are
 * three-valued.
 *
 * `assets.risk_score` is MAX over the asset's OPEN risk-feeding findings
 * (ADR-0005 D4), so the gauge has exactly one reason and the page owes the user
 * that reason rather than a bare number. And `risk_assessed_by` is the only
 * thing separating "assessed, nothing found" from "nobody looked" — a score of
 * 0 is both, and the array decides which.
 */

function f(over: Partial<ComplianceFinding>): ComplianceFinding {
  return {
    id: over.id ?? 'id',
    summary: over.summary ?? 'summary',
    severity: over.severity ?? 'medium',
    score: over.score ?? 0,
    producer: over.producer ?? 'crypto',
    workflow_status: over.workflow_status ?? 'NEW',
    detection_state: over.detection_state ?? 'ACTIVE',
  } as ComplianceFinding;
}

describe('topRiskFinding', () => {
  it('names the finding the MAX came from', () => {
    const top = topRiskFinding([
      f({ id: 'a', score: 40, summary: 'pqc' }),
      f({ id: 'b', score: 90, summary: 'tls 1.0', severity: 'critical' }),
      f({ id: 'c', score: 70, summary: 'weak cert', severity: 'high' }),
    ]);
    expect(top?.id).toBe('b');
  });

  it('ignores findings that feed no risk', () => {
    // A hygiene or compliance finding scores 0 by registry rule, so it never
    // moved the gauge and must never be offered as the explanation for it.
    const top = topRiskFinding([
      f({ id: 'hygiene', score: 0, producer: 'hygiene', summary: 'no owner', severity: 'low' }),
    ]);
    expect(top).toBeNull();
  });

  it('ignores findings nobody would count as open', () => {
    // The same open predicate the server rolls up with: a suppressed finding is
    // a standing decision and a resolved one has been dealt with. Either one
    // showing up as "why your score is 90" would point at work already done.
    expect(topRiskFinding([f({ score: 90, workflow_status: 'SUPPRESSED' })])).toBeNull();
    expect(topRiskFinding([f({ score: 90, workflow_status: 'RESOLVED' })])).toBeNull();
  });

  it('breaks ties deterministically', () => {
    // Same score: the worse severity wins, then the summary. A "why" that
    // changed between reloads would read as the asset changing.
    const bySeverity = topRiskFinding([
      f({ id: 'low', score: 70, severity: 'medium', summary: 'b' }),
      f({ id: 'high', score: 70, severity: 'high', summary: 'a' }),
    ]);
    expect(bySeverity?.id).toBe('high');

    const bySummary = topRiskFinding([
      f({ id: 'second', score: 70, severity: 'high', summary: 'zebra' }),
      f({ id: 'first', score: 70, severity: 'high', summary: 'aardvark' }),
    ]);
    expect(bySummary?.id).toBe('first');
  });

  it('answers null for an asset with nothing open', () => {
    expect(topRiskFinding([])).toBeNull();
  });
});

describe('the "why" link lands on the finding it names', () => {
  it('points at the Findings tab, at that finding', () => {
    expect(findingLinkTo('asset-1', 'f-9')).toBe('/inventory/assets/asset-1/findings#finding-f-9');
  });

  it('reads back the id the row is anchored with', () => {
    // The round trip is the whole point: the link, the row's id and the reader
    // are one helper, so a link into the list cannot stop matching the row it
    // meant — a mismatch shows up as nothing happening, which nobody reports.
    const link = findingLinkTo('asset-1', 'f-9');
    expect(selectedFindingID(link.slice(link.indexOf('#')))).toBe('f-9');
    expect(findingAnchor('f-9')).toBe('finding-f-9');
  });

  it('selects nothing for any other hash', () => {
    expect(selectedFindingID('')).toBe('');
    expect(selectedFindingID('#something-else')).toBe('');
  });

  // The WIRING, not the helper. Both halves above pass with the Overview link
  // still pointing at the bare tab and the rows carrying no id at all — the
  // link would land on the list and scroll nowhere, which is exactly the state
  // this change set out to fix and exactly the state nobody files a bug about.
  it('is actually used at both ends of the page', () => {
    const src = readFileSync(fileURLToPath(new URL('./asset-page.tsx', import.meta.url)), 'utf8');
    expect(src).toContain('to={findingLinkTo(asset.id, why.id)}');
    expect(src).toContain('id={findingAnchor(f.id)}');
    expect(src).toContain('selectedFindingID(useLocation().hash)');
  });
});

describe('assessedBySentence', () => {
  it('names every producer that has evaluated the asset', () => {
    expect(assessedBySentence(['crypto', 'eol', 'vulnerability']))
      .toBe('Assessed by crypto, eol, vulnerability');
  });

  it('says NOT ASSESSED for an empty coverage array, never a blank', () => {
    // The load-bearing case. An empty array with a score of 0 is "nobody has
    // looked", and rendering it as "Assessed by " with nothing after it — or as
    // nothing at all — is the sentence this field exists to prevent.
    expect(assessedBySentence([])).toBe('Not assessed');
  });
});
