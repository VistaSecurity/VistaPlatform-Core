// The findings domain model, after workstream 3.1 moved the compliance producer
// onto the one `findings` table.
//
// Several of these are about the SUBJECT. A finding names the object the
// judgement is about, and on live data three in four of those objects are a
// certificate or a crypto configuration rather than a host — so every place
// that reads the subject as "the asset" is a place that renders the wrong
// thing, or links a ticket to a row that does not exist.
import { describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { RiskChip } from '../../components/ui';
import { assetOf, categoriesOf, hasCategoryLabel, isOpenWf, sevLevel, sevRank, subjectContext, targetLabel, wfOf, type ComplianceFinding, type CryptoRisk } from './model';

function finding(over: Partial<ComplianceFinding> = {}): ComplianceFinding {
  return {
    id: 'f-1',
    tenant_id: 't-1',
    producer: 'compliance',
    kind: 'control_noncompliant',
    control_id: 'c-1',
    subject_id: '0198fb2c-1111-2222-3333-444455556666',
    subject_type: 'certificate',
    severity: 'high',
    score: 0,
    summary: 'Certificate uses a SHA-1 signature',
    evidence: null,
    first_seen: '2026-09-01T00:00:00Z',
    last_seen: '2026-09-10T00:00:00Z',
    detection_state: 'ACTIVE',
    workflow_status: 'NEW',
    occurrence_count: 1,
    is_stale: false,
    evaluation_version: 1,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-10T00:00:00Z',
    ...over,
  } as ComplianceFinding;
}

describe('targetLabel', () => {
  it('prefers the joined display name — a certificate names itself, not its host', () => {
    const f = finding({ asset: { display_name: 'api.example.com', id: 'x', tenant_id: 't-1' } as never });
    expect(targetLabel(f)).toBe('api.example.com');
  });

  it('falls back to the hostname when the subject IS an asset', () => {
    const f = finding({
      subject_type: 'asset',
      asset: { hostname: 'web-01.internal', id: 'x', tenant_id: 't-1' } as never,
    });
    expect(targetLabel(f)).toBe('web-01.internal');
  });

  it('falls back to the stored subject label before the raw id', () => {
    // The label is captured at write time, so a subject whose row has since gone
    // still reads as a name. The raw UUID is the last resort, and showing it
    // unnecessarily is the H-9b defect this ordering exists to prevent.
    const f = finding({ subject_label: 'TLS 1.0 on :443' });
    expect(targetLabel(f)).toBe('TLS 1.0 on :443');
  });

  it('shows a short id only when nothing else names the subject', () => {
    expect(targetLabel(finding())).toBe('0198fb2c');
  });

  //. The server resolves a software_install subject to the HOST the
  // package is on, because the row needs an asset link and an environment. The
  // list then rendered the host as the target, so a machine with nine
  // end-of-life packages showed nine rows with the same label — and the same
  // label as the machine's own findings.
  it('names the PACKAGE for a software_install, not the host it resolved to', () => {
    const f = finding({
      subject_type: 'software_install',
      subject_label: 'nginx 1.20.0',
      asset: { hostname: 'web-01.internal', id: 'a-1', tenant_id: 't-1' } as never,
    });
    expect(targetLabel(f)).toBe('nginx 1.20.0');
    // The host is not lost — it becomes the context line.
    expect(subjectContext(f)).toBe('web-01.internal');
  });

  it('falls back to the host when a software_install carries no label', () => {
    const f = finding({
      subject_type: 'software_install',
      subject_label: null as never,
      asset: { hostname: 'web-01.internal', id: 'a-1', tenant_id: 't-1' } as never,
    });
    expect(targetLabel(f)).toBe('web-01.internal');
  });

  // The over-strict polarity: a context line that echoes the title is noise.
  it('has no context line for a subject that IS the asset', () => {
    const f = finding({
      subject_type: 'asset',
      asset: { hostname: 'web-01.internal', id: 'a-1', tenant_id: 't-1' } as never,
    });
    expect(subjectContext(f)).toBeNull();
    expect(targetLabel(f)).toBe('web-01.internal');
  });

  it('has no context line for a certificate, whose joined object is itself', () => {
    const f = finding({ asset: { display_name: 'api.example.com', id: 'x', tenant_id: 't-1' } as never });
    expect(subjectContext(f)).toBeNull();
  });

  // Search must still find the finding by the host it is on, now that the row
  // no longer shows the host in its title — and that assertion moved to the
  // SERVER when the search did (seeds part 3). `matchesFindingSearch` ran over
  // a page-capped stream, so it could only answer for the first thousand
  // findings; the predicate is now one WHERE shared by the rows, the total and
  // the producer counts, and
  // `findings_search_integration_test.go:…SearchMatchesTheHost` is where both
  // halves of this case (the package name AND the host) are pinned.

  it('never throws on a finding with no joined object', () => {
    expect(assetOf(finding())).toEqual({});
  });
});

describe('sevLevel', () => {
  it('reads the registry ladder the findings table now stores', () => {
    expect(sevLevel('critical')).toBe('Critical');
    expect(sevLevel('high')).toBe('High');
    expect(sevLevel('medium')).toBe('Medium');
    expect(sevLevel('low')).toBe('Low');
    expect(sevLevel('info')).toBe('Informational');
    expect(sevLevel('informational')).toBe('Informational');
  });

  it('still reads a control author’s `Med`, which reaches some surfaces unnormalized', () => {
    expect(sevLevel('Med')).toBe('Medium');
    expect(sevLevel('High')).toBe('High');
  });

  it('keeps unknown or missing severity separate from measured Informational', () => {
    // A missing grade is not an informational finding.
    expect(sevLevel(null)).toBe('Unknown');
    expect(sevLevel(undefined)).toBe('Unknown');
    expect(sevLevel('')).toBe('Unknown');
    expect(sevLevel('catastrophic')).toBe('Unknown');
  });

  it('renders an unscored crypto risk as a neutral unknown marker', () => {
    const html = renderToStaticMarkup(createElement(RiskChip, { level: sevLevel(null) }));
    expect(html).toContain('aria-label="Unknown"');
    expect(html).toContain('>?</span>');
  });

  it('ranks worst-first, so a sort puts Critical at the top', () => {
    expect(sevRank('Critical')).toBeLessThan(sevRank('High'));
    expect(sevRank('High')).toBeLessThan(sevRank('Medium'));
    expect(sevRank('Informational')).toBeGreaterThan(sevRank('Low'));
  });
});

describe('crypto risk categories', () => {
  const risk = { category: 'key_size' } as CryptoRisk;

  it('uses every applicable category for filtering while retaining the primary category', () => {
    const mixed = { ...risk, categories: ['key_size', 'algorithm'] } as CryptoRisk;
    expect(categoriesOf(mixed)).toEqual(['key_size', 'algorithm']);
    expect(hasCategoryLabel(mixed, 'Algorithm')).toBe(true);
    expect(hasCategoryLabel(mixed, 'Key size')).toBe(true);
  });

  it('falls back to the primary category for older responses', () => {
    expect(categoriesOf(risk)).toEqual(['key_size']);
    expect(hasCategoryLabel(risk, 'Key size')).toBe(true);
  });
});

describe('workflow status', () => {
  it('defaults to NEW and upper-cases whatever it is given', () => {
    expect(wfOf(finding({ workflow_status: '' }))).toBe('NEW');
    expect(wfOf(finding({ workflow_status: 'resolved' }))).toBe('RESOLVED');
  });

  it('is open until a PERSON closes it', () => {
    // The workflow half of "open". The detection half is the server's; both are
    // needed, and a UI that used only this one would show findings that have
    // since been fixed.
    expect(isOpenWf(finding({ workflow_status: 'NEW' }))).toBe(true);
    expect(isOpenWf(finding({ workflow_status: 'NOTIFIED' }))).toBe(true);
    expect(isOpenWf(finding({ workflow_status: 'RESOLVED' }))).toBe(false);
    expect(isOpenWf(finding({ workflow_status: 'SUPPRESSED' }))).toBe(false);
  });
});
