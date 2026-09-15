// The Subject column, RENDERED.
//
// `alert-subject-link.test.ts` pins the mapping; this pins the markup that
// consumes it, and the two are not the same guard. Reverting the cell to the
// plain `<span>{a.subject_label}</span>` it used to be leaves every mapping
// test green — the helper would still be correct and nothing would call it.
// "Test the WIRING, not just the helper."
//
// renderToStaticMarkup rather than testing-library: the question is only what
// the cell prints, and MemoryRouter is all <Link> needs.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { SubjectCell, SubjectValue } from './alerts-page';

type Alert = Parameters<typeof SubjectCell>[0]['alert'];

// The two surfaces are rendered SEPARATELY and asserted separately. Rendering
// them into one string was the first draft, and it made every assertion below
// pass with the row cell hard-wired to plain text — the drawer's anchor was in
// the same markup. A negative assertion over two components at once cannot fail
// for one of them.
function renderCell(alert: Partial<Alert>): string {
  return renderToStaticMarkup(<MemoryRouter><SubjectCell alert={alert as Alert} /></MemoryRouter>);
}

function renderValue(alert: Partial<Alert>): string {
  return renderToStaticMarkup(<MemoryRouter><SubjectValue alert={alert as Alert} /></MemoryRouter>);
}

/** Every assertion runs against BOTH surfaces. */
function bothRenderings(alert: Partial<Alert>): string[] {
  return [renderCell(alert), renderValue(alert)];
}

describe('the Subject column', () => {
  it('renders an anchor to the asset page for an asset subject', () => {
    for (const html of bothRenderings({ subject_type: 'asset', subject_id: 'a1', subject_label: 'web-01' })) {
      expect(html).toContain('href="/inventory/assets/a1"');
      expect(html).toContain('web-01');
    }
  });

  it('renders an anchor to the findings list for a software install', () => {
    for (const html of bothRenderings({ subject_type: 'software_install', subject_id: 'i1', subject_label: 'openssl' })) {
      expect(html).toContain('subject_type=software_install&amp;subject_id=i1');
    }
  });

  it('renders an anchor to the certificate lens for a labelled certificate', () => {
    for (const html of bothRenderings({ subject_type: 'certificate', subject_id: 'c1', subject_label: '*.example.com' })) {
      expect(html).toContain('lens=certificate');
    }
  });

  it('renders PLAIN TEXT — no anchor — for a subject type with no destination', () => {
    for (const html of bothRenderings({ subject_type: 'sensor', subject_id: 's1', subject_label: 'floor-2 sensor' })) {
      expect(html).toContain('floor-2 sensor');
      expect(html).not.toContain('<a ');
    }
  });

  it('renders an em dash — and no anchor — for an alert with no subject at all', () => {
    for (const html of bothRenderings({ alert_type: 'service_down' })) {
      expect(html).toContain('—');
      expect(html).not.toContain('<a ');
    }
  });
});
