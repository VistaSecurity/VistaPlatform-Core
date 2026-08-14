import { describe, expect, it } from 'vitest';
import {
  PROVENANCE_LABEL,
  PROVENANCE_TITLE,
  componentTypeLabel,
  explainRisk,
  provenanceOf,
  verdictOf,
  type CryptoComponent,
} from './risk-explanation';

function comp(over: Partial<CryptoComponent> = {}): CryptoComponent {
  return {
    algorithm_type: 'symmetric',
    is_inferred: false,
    algorithm_id: '00000000-0000-0000-0000-000000000001',
    code: 'AES256',
    name: 'AES-256',
    category: 'symmetric',
    strength: 'strong',
    deprecation_status: 'current',
    risk_score: 15,
    risk_level: 'Low',
    recommended_alternatives: [],
    is_pqc: false,
    sets_score: false,
    ...over,
  } as CryptoComponent;
}

// The single most important behaviour in this module. An implementation with
// nothing linked to the catalogue has NOT been assessed; rendering that as
// "no risk factors found" would be a clean bill of health we have not earned.
describe('not assessed is never a clean bill of health', () => {
  it('reports assessed=false for an empty component list', () => {
    const x = explainRisk([], 0);
    expect(x.assessed).toBe(false);
    expect(x.worst).toBeNull();
    expect(x.headline).toMatch(/not assessed/i);
  });

  it('reports assessed=false when the field is missing entirely', () => {
    expect(explainRisk(undefined, 0).assessed).toBe(false);
  });

  it('says what we do not know, and never that there is no risk', () => {
    const { caption, headline } = explainRisk([], 0);
    const text = `${headline} ${caption}`.toLowerCase();
    expect(caption).toMatch(/has not been assessed/i);
    expect(caption).toMatch(/not the same as being safe/i);
    // Reassuring phrasings that would misread an absence of data as a verdict.
    for (const forbidden of ['no risk', 'no issues', 'looks good', 'secure', 'clean', 'safe configuration']) {
      expect(text).not.toContain(forbidden);
    }
  });

  it('stays not-assessed even if a score somehow arrives without components', () => {
    // Defensive: the panel must follow the COMPONENTS, not the number. A score
    // with no explanation is still an unexplained score.
    expect(explainRisk([], 82).assessed).toBe(false);
  });
});

describe('observed vs offered', () => {
  it('maps is_inferred to the two provenances', () => {
    expect(provenanceOf(comp({ is_inferred: false }))).toBe('observed');
    expect(provenanceOf(comp({ is_inferred: true }))).toBe('offered');
  });

  it('labels them with different WORDS, not just different styling', () => {
    // A colour-only distinction disappears in greyscale and for a colour-blind
    // reader; the whole point of this feature is that the two are unmistakable.
    expect(PROVENANCE_LABEL.observed).not.toBe(PROVENANCE_LABEL.offered);
    expect(PROVENANCE_LABEL.observed).toMatch(/observed/i);
    expect(PROVENANCE_LABEL.offered).toMatch(/not observed/i);
  });

  it('explains that an offered algorithm still counts toward the score', () => {
    expect(PROVENANCE_TITLE.offered).toMatch(/still counts/i);
  });

  it('counts the offered-only components', () => {
    const x = explainRisk(
      [comp({ sets_score: true, is_inferred: true }), comp({ code: 'SHA256', is_inferred: false })],
      15,
    );
    expect(x.offeredCount).toBe(1);
  });

  it('names the provenance of the score-setter in the caption', () => {
    const offered = explainRisk([comp({ sets_score: true, is_inferred: true, code: '3des-cbc', risk_score: 72, risk_level: 'High' })], 72);
    expect(offered.caption).toContain(PROVENANCE_LABEL.offered);
    const observed = explainRisk([comp({ sets_score: true, is_inferred: false, code: '3des-cbc', risk_score: 72, risk_level: 'High' })], 72);
    expect(observed.caption).toContain(PROVENANCE_LABEL.observed);
    // Asserted on the CAPTIONS, not on the constants, so collapsing the two
    // labels into one string cannot slip past by being self-consistent.
    expect(offered.caption).not.toBe(observed.caption);
    expect(observed.caption).not.toMatch(/not observed/i);
  });
});

describe('worst-component selection', () => {
  it('uses the backend sets_score marker', () => {
    const x = explainRisk([comp({ code: 'A' }), comp({ code: 'B', sets_score: true })], 15);
    expect(x.worst?.code).toBe('B');
  });

  it('falls back to the first (worst-first ordered) component when unmarked', () => {
    const x = explainRisk([comp({ code: 'A' }), comp({ code: 'B' })], 15);
    expect(x.worst?.code).toBe('A');
  });

  it('headlines with the component type and code', () => {
    const x = explainRisk([comp({ algorithm_type: 'key_exchange', code: 'diffie-hellman-group1-sha1', sets_score: true })], 82);
    expect(x.headline).toBe('Key exchange: diffie-hellman-group1-sha1');
  });

  it('quotes the API-supplied band rather than deriving one', () => {
    // If this module ever re-banded, an intentionally "wrong" pairing here
    // would be silently corrected — which is exactly the drift that once made
    // badges band High at >=60 while the summary used >=70.
    const x = explainRisk([comp({ sets_score: true, risk_score: 65, risk_level: 'Critical' })], 65);
    expect(x.caption).toContain('Critical');
  });
});

describe('unexplained remainder', () => {
  it('is null when the components fully explain the score', () => {
    expect(explainRisk([comp({ sets_score: true, risk_score: 82 })], 82).unexplainedRemainder).toBeNull();
  });

  it('is null when the catalogue has moved ABOVE the stored score', () => {
    expect(explainRisk([comp({ sets_score: true, risk_score: 90 })], 82).unexplainedRemainder).toBeNull();
  });

  it('reports the gap when the stored score exceeds every component', () => {
    // e.g. a 1024-bit RSA key: the size rule fires, and no per-algorithm
    // catalogue row can express it.
    expect(explainRisk([comp({ sets_score: true, risk_score: 20 })], 95).unexplainedRemainder).toBe(75);
  });
});

describe('presentation helpers', () => {
  it('translates storage vocabulary to product vocabulary', () => {
    expect(componentTypeLabel('protocol_version')).toBe('Protocol version');
    expect(componentTypeLabel('key_exchange')).toBe('Key exchange');
  });

  it('degrades gracefully on an unknown role instead of dropping it', () => {
    expect(componentTypeLabel('some_new_role')).toBe('some new role');
    expect(componentTypeLabel(undefined)).toBe('Component');
  });

  it('renders a verdict only from what the catalogue actually says', () => {
    expect(verdictOf(comp({ strength: 'weak', deprecation_status: 'obsolete' }))).toBe('weak · obsolete');
    // "current" is the unremarkable default — showing it would imply a finding.
    expect(verdictOf(comp({ strength: 'strong', deprecation_status: 'current' }))).toBe('strong');
    // Nothing recorded stays nothing. No invented assessment.
    expect(verdictOf(comp({ strength: '', deprecation_status: '' }))).toBe('');
  });
});
