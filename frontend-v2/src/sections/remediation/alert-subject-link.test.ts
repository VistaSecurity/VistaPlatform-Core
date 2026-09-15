import { describe, expect, it } from 'vitest';
import { isFindingsLens } from '../findings/lenses';
import { alertSubjectHref, alertSubjectText, subjectHrefGaps } from './alert-subject-link';

// The Subject column on Remediation → Alerts.
//
// The negatives are the point. A link that lands on a page which cannot resolve
// the subject renders as "no findings" / "no such asset", which a person reads
// as "nothing wrong with this object" — the exact false-clean this codebase
// keeps closing elsewhere. So every type without an id-addressable destination
// must come back null, and the test says so by name rather than by omission.

describe('alertSubjectHref', () => {
  it('links an asset to its own page', () => {
    expect(alertSubjectHref({ subject_type: 'asset', subject_id: 'a1', subject_label: 'web-01' }))
      .toBe('/inventory/assets/a1');
  });

  it('links a software install to the findings about that install', () => {
    expect(alertSubjectHref({ subject_type: 'software_install', subject_id: 'i1', subject_label: 'openssl 1.1.1k' }))
      .toBe('/risk-compliance/findings?lens=producer&subject_type=software_install&subject_id=i1');
  });

  it('links a crypto configuration the same way', () => {
    expect(alertSubjectHref({ subject_type: 'crypto_configuration', subject_id: 'c1' }))
      .toBe('/risk-compliance/findings?lens=producer&subject_type=crypto_configuration&subject_id=c1');
  });

  it('links a control to the control lens, expanded to it', () => {
    expect(alertSubjectHref({ subject_type: 'control', subject_id: 'ctl-9' }))
      .toBe('/risk-compliance/findings?lens=control&control=ctl-9');
  });

  it('links a certificate to the certificate lens seeded with its label', () => {
    expect(alertSubjectHref({ subject_type: 'certificate', subject_id: 'cert-1', subject_label: '*.example.com' }))
      .toBe('/inventory?lens=certificate&q=*.example.com');
  });

  it('does NOT link a certificate with no label — there is no ?cert=<id> route to fall back to', () => {
    expect(alertSubjectHref({ subject_type: 'certificate', subject_id: 'cert-1' })).toBeNull();
    expect(alertSubjectHref({ subject_type: 'certificate', subject_id: 'cert-1', subject_label: '   ' })).toBeNull();
  });

  it('does NOT link a subject type with no id-addressable destination', () => {
    for (const subject_type of subjectHrefGaps) {
      expect(alertSubjectHref({ subject_type, subject_id: 'x1', subject_label: 'whatever' })).toBeNull();
    }
  });

  it('does NOT link an alert carrying no subject at all', () => {
    expect(alertSubjectHref({})).toBeNull();
    expect(alertSubjectHref({ subject_type: 'asset' })).toBeNull();
    expect(alertSubjectHref({ subject_id: 'a1' })).toBeNull();
  });

  it('escapes the id and the label, so a subject naming itself "a&b" cannot forge a query parameter', () => {
    expect(alertSubjectHref({ subject_type: 'certificate', subject_id: 'c', subject_label: 'a&lens=keys' }))
      .toBe('/inventory?lens=certificate&q=a%26lens%3Dkeys');
    expect(alertSubjectHref({ subject_type: 'asset', subject_id: '../../etc' }))
      .toBe('/inventory/assets/..%2F..%2Fetc');
  });
});

describe('alertSubjectText', () => {
  it('prefers the label, falls back to the id, and never renders blank', () => {
    expect(alertSubjectText({ subject_label: 'web-01', subject_id: 'a1' })).toBe('web-01');
    expect(alertSubjectText({ subject_id: 'a1' })).toBe('a1');
    expect(alertSubjectText({ subject_label: '  ' , subject_id: 'a1' })).toBe('a1');
    expect(alertSubjectText({})).toBe('—');
  });
});

// The lens a subject link lands on has to be one that reads the FINDINGS table.
// The crypto-risk lenses ignore subject_type/subject_id entirely — so while the
// page default was `severity`, a link without a lens rendered an unfiltered
// crypto list under a banner reading "Showing findings on one software install
// only". The default is findings-scoped now; the links stay explicit anyway,
// because a default is a thing that changes. Asserted against the page's
// own lens registry rather than against the literal string, so a lens rename
// cannot leave this passing while the link breaks.
describe('a subject link lands on a lens that can honour it', () => {
  it.each(['software_install', 'crypto_configuration'])('%s', (subject_type) => {
    const href = alertSubjectHref({ subject_type, subject_id: 'x1' });
    const lens = new URLSearchParams(href!.split('?')[1]).get('lens');
    expect(lens).toBeTruthy();
    expect(isFindingsLens(lens!)).toBe(true);
  });

  it('the control link too', () => {
    const href = alertSubjectHref({ subject_type: 'control', subject_id: 'ctl-1' });
    const lens = new URLSearchParams(href!.split('?')[1]).get('lens');
    expect(isFindingsLens(lens!)).toBe(true);
  });
});
