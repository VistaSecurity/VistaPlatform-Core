// Reachability for Settings → Policies → Trusted CAs: the rail entry
// alone is not enough — the page router must render the page for that key,
// or the entry leads to the "design pending" fallback.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';

it('routes the trusted-cas key to TrustedCAsPage', () => {
  const src = readFileSync(fileURLToPath(new URL('./settings-page.tsx', import.meta.url)), 'utf8');
  expect(src).toMatch(/case 'trusted-cas':\s*return <TrustedCAsPage/);
});
