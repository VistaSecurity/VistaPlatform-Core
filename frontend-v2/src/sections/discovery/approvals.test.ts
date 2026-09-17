// Approvals as the single proposal queue (ADR-0006 D6).
//
// The source facet and the merge row are the two new things, and both are backed
// by pure functions so the rules are tested rather than eyeballed. What is being
// pinned is mostly negative: a filter that hides work, a count that omits a row
// kind, and a highlight that misses half the evidence are all failures that look
// like a working page.
import { describe, expect, it } from 'vitest';
import {
  APPROVAL_SOURCES, SOURCE_LABEL, countBySource, matchesSourceFilter,
  sourceOfAsset, sourceOfProposal,
} from './approval-sources';
import {
  candidateName, defaultSurvivor, readIdentifier, scoreLabel,
} from './merge-proposal-row';
import type { MergeCandidate } from '../inventory/asset-queries';

/** A candidate with the contract's required fields filled in, so a test can
 *  state only the part it is about. */
function candidate(over: Partial<MergeCandidate> = {}): MergeCandidate {
  return { asset_id: 'a1', deleted: false, matched_identifiers: [], score: 0, ...over };
}

describe('sourceOfAsset', () => {
  it('reads the producer out of class_source_ref', () => {
    // `class_source_ref` names who decided the class (`classifier:<model>`,
    // `cmdb:<profile>`, `user:<id>`), which is enough to place a row without a
    // seventh column on the API.
    expect(sourceOfAsset({ class_source_kind: 'inferred', class_source_ref: 'classifier:v2' })).toBe('classifier');
    expect(sourceOfAsset({ class_source_kind: 'inferred', class_source_ref: 'assistant:gpt' })).toBe('assistant');
    expect(sourceOfAsset({ class_source_kind: 'imported', class_source_ref: 'cmdb:servicenow-prod' })).toBe('cmdb');
    // An SBOM-created application is DECLARED, which would otherwise fall
    // through to `discovered` and tell a reviewer a sensor saw it on the
    // network. The `sbom:` producer prefix is what says otherwise.
    expect(sourceOfAsset({ class_source_kind: 'declared', class_source_ref: 'sbom:8c2f0e4a-1d3b-4a5c-9e6f-0b1c2d3e4f50' })).toBe('sbom');
    expect(sourceOfAsset({ class_source_kind: 'DECLARED', class_source_ref: 'SBOM:abc' })).toBe('sbom');
  });

  it('separates a spreadsheet import from a CMDB pull', () => {
    expect(sourceOfAsset({ class_source_kind: 'imported' })).toBe('imported');
    expect(sourceOfAsset({ class_source_kind: 'imported', discovery_method: 'cmdb_sync' })).toBe('cmdb');
  });

  it('treats a measured class as discovered', () => {
    expect(sourceOfAsset({ class_source_kind: 'measured' })).toBe('discovered');
  });

  it('falls back to "discovered" for anything it cannot place', () => {
    // The truthful default: the queue existed for network discoveries before
    // anything else could write to it.
    expect(sourceOfAsset({})).toBe('discovered');
    expect(sourceOfAsset({ class_source_kind: 'something_new' })).toBe('discovered');
  });

  it('is case-insensitive about what the backend sends', () => {
    expect(sourceOfAsset({ class_source_ref: 'CLASSIFIER:v2' })).toBe('classifier');
    expect(sourceOfAsset({ class_source_kind: 'IMPORTED' })).toBe('imported');
  });
});

describe('sourceOfProposal', () => {
  it('groups by the PRODUCER that raised it, not by how the thing was seen', () => {
    expect(sourceOfProposal({})).toBe('matcher');
    expect(sourceOfProposal({ source: 'matcher:v1' })).toBe('matcher');
    expect(sourceOfProposal({ source: 'assistant:gpt' })).toBe('assistant');
    expect(sourceOfProposal({ source: 'classifier:v2' })).toBe('classifier');
    // `source_kind` is how the observation was MADE (measured, imported); it is
    // deliberately not what the facet groups by — the question the facet answers
    // is "who is asking me this".
    expect(sourceOfProposal({ source: 'matcher', source_kind: 'imported' })).toBe('matcher');
  });
});

describe('countBySource', () => {
  it('counts BOTH row kinds — the queue is one queue', () => {
    // A count that included only the assets would send a user to a page with
    // more work on it than the count admitted.
    const counts = countBySource(
      [{ class_source_kind: 'measured' }, { class_source_kind: 'imported' }],
      [{ source: 'matcher:v1' }],
    );
    expect(counts.discovered).toBe(1);
    expect(counts.imported).toBe(1);
    expect(counts.matcher).toBe(1);
  });

  it('seeds EVERY source at zero, so the facet does not jump as rows arrive', () => {
    const counts = countBySource([], []);
    for (const s of APPROVAL_SOURCES) expect(counts[s]).toBe(0);
    expect(Object.keys(counts).sort()).toEqual([...APPROVAL_SOURCES].sort());
  });

  it('has a label for every source it can count', () => {
    for (const s of APPROVAL_SOURCES) expect(SOURCE_LABEL[s]).toBeTruthy();
  });
});

describe('matchesSourceFilter', () => {
  it('treats an EMPTY selection as "all", never as "none"', () => {
    // The difference between an unfiltered queue and an empty one. Reading no
    // selection as "none" would render a full queue as if the work were done.
    expect(matchesSourceFilter('discovered', [])).toBe(true);
    expect(matchesSourceFilter('matcher', [])).toBe(true);
  });

  it('keeps only the selected sources', () => {
    expect(matchesSourceFilter('discovered', ['discovered', 'imported'])).toBe(true);
    expect(matchesSourceFilter('matcher', ['discovered', 'imported'])).toBe(false);
  });
});

describe('the merge row\u2019s pure helpers', () => {
  it('reads an identifier out of the contract\u2019s open object', () => {
    // `matched_identifiers` is typed as an open map, so the row narrows it
    // rather than asserting a shape the schema does not promise.
    expect(readIdentifier({ kind: 'mac_address', value: 'aa:bb', scope: 'tenant' }))
      .toEqual({ kind: 'mac_address', value: 'aa:bb', scope: 'tenant' });
  });

  it('returns an empty identifier for junk rather than throwing', () => {
    expect(readIdentifier(null)).toEqual({});
    expect(readIdentifier('nope')).toEqual({});
    expect(readIdentifier({ kind: 7 })).toEqual({ kind: undefined, value: undefined, scope: undefined });
  });

  it('renders matcher scores from the declared 0..1 unit only', () => {
    expect(scoreLabel(0.86)).toBe('86%');
    expect(scoreLabel(86)).toBeNull();
  });

  it('renders an UNSCORED candidate as no score, never as 0%', () => {
    // "ZERO means unscored, not certainly wrong" — a 0% bar would read as a
    // confident rejection of a candidate nothing has weighed.
    expect(scoreLabel(0)).toBeNull();
    expect(scoreLabel(NaN)).toBeNull();
  });

  it('names a candidate by display name, then hostname, then a short id', () => {
    expect(candidateName(candidate({ display_name: 'Payroll', hostname: 'web-01' }))).toBe('Payroll');
    expect(candidateName(candidate({ hostname: 'web-01' }))).toBe('web-01');
    expect(candidateName(candidate({ asset_id: 'abcdef0123456789' }))).toBe('abcdef01');
  });
});

describe('defaultSurvivor', () => {
  it('preselects the highest-scoring available candidate', () => {
    const chosen = defaultSurvivor([
      candidate({ asset_id: 'a', score: 0.4 }),
      candidate({ asset_id: 'b', score: 0.9 }),
    ]);
    expect(chosen).toBe('b');
  });

  it('never preselects a candidate that can no longer be merged into', () => {
    // A deleted candidate is SHOWN (dropping it would make the proposal read as
    // if it only ever had one) but it cannot be the survivor.
    const chosen = defaultSurvivor([
      candidate({ asset_id: 'gone', score: 0.99, deleted: true }),
      candidate({ asset_id: 'alive', score: 0.2 }),
    ]);
    expect(chosen).toBe('alive');
  });

  it('picks the first when nothing is scored', () => {
    expect(defaultSurvivor([candidate({ asset_id: 'a' }), candidate({ asset_id: 'b' })])).toBe('a');
  });

  it('picks nothing when every candidate is gone', () => {
    // The Merge button is then disabled: there is nothing to merge into, and
    // guessing a survivor is exactly what the server refuses to do.
    expect(defaultSurvivor([candidate({ asset_id: 'a', deleted: true })])).toBeUndefined();
    expect(defaultSurvivor([])).toBeUndefined();
  });
});
