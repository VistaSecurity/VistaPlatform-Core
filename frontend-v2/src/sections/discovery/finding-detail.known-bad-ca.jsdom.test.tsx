// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FindingDetail } from './finding-detail';

// The "Known-bad CA" row of the certificate preview. The TLS prober stores the
// NAME of the matched CA under cert_known_bad_ca; findings stored by older
// versions carry a boolean true. The preview is rendered through the real
// FindingDetail ("View full cert"), so what is asserted is what the operator sees.

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const CERT = {
  chain_order: 0,
  subject: 'CN=leaf.example.test',
  issuer: 'CN=Some Issuer',
  serial_number: '01',
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
  document.body.innerHTML = '';
});

// Open the certificate preview for a finding whose stored data has the given
// cert_known_bad_ca (or none, when `flag` is the `ABSENT` sentinel).
const ABSENT = Symbol('absent');
function openPreview(flag: unknown) {
  const data: Record<string, unknown> = { certificates: [CERT] };
  if (flag !== ABSENT) data.cert_known_bad_ca = flag;
  const finding = { protocol: 'tls', data } as unknown as Parameters<typeof FindingDetail>[0]['f'];
  act(() => root.render(<FindingDetail f={finding} />));
  const open = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('View full cert'));
  expect(open, 'the preview button').toBeTruthy();
  act(() => open!.click());
  // The preview is portalled to document.body, outside `host`.
  return document.body.textContent ?? '';
}

describe('certificate preview: Known-bad CA row', () => {
  it('names the CA when the stored value is a string', () => {
    const text = openPreview('Superfish');
    expect(text).toContain('Known-bad CA');
    expect(text).toContain('Superfish — do not trust');
  });

  it('warns without a name for a legacy boolean true', () => {
    const text = openPreview(true);
    expect(text).toContain('Known-bad CA');
    expect(text).toContain('yes — do not trust');
  });

  it.each([
    ['false', false],
    ['an empty string', ''],
    ['a blank string', '   '],
    ['null', null],
    ['absent', ABSENT],
  ])('shows no row for %s', (_label, flag) => {
    const text = openPreview(flag);
    expect(text).toContain('Trust & revocation'); // the section rendered…
    expect(text).not.toContain('Known-bad CA'); // …without the warning
    expect(text).not.toContain('do not trust');
  });

  it('renders a hostile CA name as text, never as markup', () => {
    const name = '<img src=x onerror=alert(1)>';
    const text = openPreview(name);
    expect(text).toContain(`${name} — do not trust`);
    expect(document.body.querySelector('img')).toBeNull();
  });
});
