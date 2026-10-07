// A class proposal's matched rules carry a `source_url` copied from the rule
// catalogue, and the row renders it as a link inside the console of EVERY
// tenant. The server now refuses a non-https citation at the door; this is the
// second door: whatever the field holds when it reaches the browser, only an
// http(s) URL may become an href, so a stored `javascript:` / `data:` value
// cannot execute when a reviewer clicks "source".
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { describe, expect, it } from 'vitest';
import { ClassProposalRow } from './class-proposal-row';
import type { ClassProposal } from './class-proposal-queries';

function render(sourceURL: string | undefined): string {
  const proposal = {
    id: 'p-1',
    proposed_class_key: 'printer',
    matched_rules: [{ kind: 'oui', pattern: '00000C', class: 'printer', source_url: sourceURL }],
  } as unknown as ClassProposal;
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <PermissionProvider enabled={false}>
        <MemoryRouter>
          <ClassProposalRow proposal={proposal} busy={false} onAccept={() => {}} onReject={() => {}} />
        </MemoryRouter>
      </PermissionProvider>
    </QueryClientProvider>,
  );
}

describe('ClassProposalRow rule citation link', () => {
  it('links an https source', () => {
    expect(render('https://standards-oui.ieee.org/')).toContain('href="https://standards-oui.ieee.org/"');
  });

  it('never turns a non-http(s) source into a link', () => {
    for (const hostile of ['javascript:alert(1)', 'data:text/html,<b>x</b>', 'vbscript:msgbox(1)', '//evil.example/x', '/relative']) {
      const html = render(hostile);
      expect(html.toLowerCase()).not.toMatch(/href="(javascript|data|vbscript):/);
      expect(html).not.toContain(`href="${hostile}"`);
      expect(html).not.toContain('>source<');
    }
  });
});
