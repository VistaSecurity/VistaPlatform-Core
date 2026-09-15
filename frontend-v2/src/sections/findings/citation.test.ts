import { describe, expect, it } from 'vitest';
import { findingCitation, type ComplianceFinding } from './model';

// A finding derived from a catalogue has to say where the claim came from, or
// the user can neither check it nor dispute it. Both polarities matter: a
// helper that returned null for everything would satisfy every "is the bad URL
// refused?" case below and quietly remove the citation from the UI.

function finding(evidence: Record<string, unknown>): ComplianceFinding {
  return { evidence } as unknown as ComplianceFinding;
}

describe('findingCitation', () => {
  it('cites the catalogue page an end-of-life finding read', () => {
    const cite = findingCitation(finding({
      catalogue_id: '1111',
      catalogue_source_url: 'https://endoflife.date/ubuntu',
    }));
    expect(cite).toEqual({ href: 'https://endoflife.date/ubuntu', label: 'Catalogue entry' });
  });

  it('cites the worst CVE of a vulnerability finding, by id', () => {
    // `cves` is sorted worst-first by the producer, so the first entry is the
    // advisory the headline severity came from.
    const cite = findingCitation(finding({
      cves: [
        { cve_id: 'CVE-2026-1000', cvss_score: 9.8, source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1000' },
        { cve_id: 'CVE-2026-1001', cvss_score: 4.3, source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1001' },
      ],
    }));
    expect(cite).toEqual({
      href: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1000',
      label: 'CVE-2026-1000',
    });
  });

  it('returns null for a finding that cites a control rather than a URL', () => {
    // The compliance producer's findings name a control_id. There is no page to
    // link to, and a "Source" link that went nowhere useful is worse than none.
    expect(findingCitation(finding({ crypto_implementation_ids: ['abc'] }))).toBeNull();
    expect(findingCitation(finding({}))).toBeNull();
  });

  it('refuses a non-http scheme', () => {
    // `evidence` is JSONB written by a producer reading a mirrored feed, and
    // `href` is a URL context where escaping does nothing — so the scheme has to
    // be checked rather than the value escaped.
    for (const href of ['javascript:alert(1)', 'data:text/html,<script>', 'file:///etc/passwd', 'not a url']) {
      expect(findingCitation(finding({ catalogue_source_url: href }))).toBeNull();
      expect(findingCitation(finding({ cves: [{ cve_id: 'CVE-1', source_url: href }] }))).toBeNull();
    }
  });

  it('tolerates a malformed evidence shape without throwing', () => {
    expect(findingCitation(finding({ cves: 'not-a-list' }))).toBeNull();
    expect(findingCitation(finding({ cves: [] }))).toBeNull();
    expect(findingCitation(finding({ cves: [null] }))).toBeNull();
    expect(findingCitation({} as ComplianceFinding)).toBeNull();
  });
});
