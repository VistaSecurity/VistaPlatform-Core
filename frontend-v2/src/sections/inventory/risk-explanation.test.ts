import { describe, expect, it } from 'vitest';
import {
  PROVENANCE_LABEL,
  PROVENANCE_TITLE,
  componentTypeLabel,
  explainRisk,
  provenanceOf,
  remediationGuidanceOf,
  safeHref,
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
    expect(x.headline).toMatch(/no catalogue evidence/i);
  });

  it('reports assessed=false when the field is missing entirely', () => {
    expect(explainRisk(undefined, 0).assessed).toBe(false);
  });

  it('says what we do not know, and never that there is no risk', () => {
    const { caption, headline } = explainRisk([], 0);
    const text = `${headline} ${caption}`.toLowerCase();
    expect(caption).toMatch(/no catalogue components resolved/i);
    expect(caption).toMatch(/not explained by this catalogue evidence/i);
    // Reassuring phrasings that would misread an absence of data as a verdict.
    for (const forbidden of ['no risk', 'no issues', 'looks good', 'secure', 'clean', 'safe configuration']) {
      expect(text).not.toContain(forbidden);
    }
  });

  it('keeps a positive stored score present while naming its missing catalogue evidence', () => {
    const x = explainRisk([], 82);
    expect(x.assessed).toBe(false);
    expect(x.caption).toContain('existing risk score 82');
    expect(x.caption).toContain('not explained by this catalogue evidence');
    expect(x.caption).not.toMatch(/has not been assessed/i);
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

  it('preserves a resolved qualitative judgment without inventing a numeric score', () => {
    const x = explainRisk([comp({ strength: 'weak', risk_score: null, risk_level: null, sets_score: false })], null);
    expect(x.assessed).toBe(true);
    expect(x.worst).toBeNull();
    expect(x.caption).toMatch(/qualitative judgments/i);
    expect(x.caption).toMatch(/no numeric risk score/i);
    expect(x.unexplainedRemainder).toBeNull();
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

// The catalogue's curated "how to fix" (algorithms.remediation_guidance), which
// used to be reachable only through an endpoint no screen called.
describe('remediation guidance', () => {
  const seeded = {
    summary: 'RC4 is broken.',
    impact: 'Keystream biases allow plaintext recovery.',
    steps: ['1. Remove RC4 from the cipher list', '2) Prefer AES-GCM', '10. Re-test'],
    timeline: 'Immediate - within 7 days',
    cve_references: ['CVE-2013-2566'],
    resources: ['https://www.rfc-editor.org/rfc/rfc7465'],
  };

  it('is null when the catalogue records none — never an empty "how to fix"', () => {
    expect(remediationGuidanceOf(comp())).toBeNull();
    expect(remediationGuidanceOf(comp({ remediation_guidance: { steps: [], cve_references: [], resources: [] } }))).toBeNull();
    expect(remediationGuidanceOf(comp({ remediation_guidance: { summary: '  ', steps: [' '], cve_references: [], resources: [] } }))).toBeNull();
  });

  it('keeps the catalogue text and strips only the step numbering the list supplies', () => {
    const g = remediationGuidanceOf(comp({ remediation_guidance: seeded }))!;
    expect(g.summary).toBe('RC4 is broken.');
    expect(g.impact).toBe('Keystream biases allow plaintext recovery.');
    expect(g.steps).toEqual(['Remove RC4 from the cipher list', 'Prefer AES-GCM', 'Re-test']);
    expect(g.timeline).toBe('Immediate - within 7 days');
    expect(g.cves).toEqual(['CVE-2013-2566']);
    expect(g.resources).toEqual([{ text: 'https://www.rfc-editor.org/rfc/rfc7465', href: 'https://www.rfc-editor.org/rfc/rfc7465' }]);
  });

  it('does not strip a number that is part of the step itself', () => {
    const g = remediationGuidanceOf(comp({ remediation_guidance: { steps: ['2048-bit keys are the minimum'], cve_references: [], resources: [] } }))!;
    expect(g.steps).toEqual(['2048-bit keys are the minimum']);
  });

  it('links only http(s) resources — the catalogue is admin-edited free text', () => {
    expect(safeHref('https://weakdh.org/')).toBe('https://weakdh.org/');
    expect(safeHref('http://example.com/x')).toBe('http://example.com/x');
    expect(safeHref('javascript:alert(1)')).toBeNull();
    expect(safeHref('JaVaScRiPt:alert(1)')).toBeNull();
    expect(safeHref('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(safeHref('NIST SP 800-52r2')).toBeNull();
    const g = remediationGuidanceOf(comp({ remediation_guidance: { steps: [], cve_references: [], resources: ['javascript:alert(1)', 'NIST SP 800-52r2'] } }))!;
    expect(g.resources.every((r) => r.href === null)).toBe(true);
  });
});
