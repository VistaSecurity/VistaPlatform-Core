// Certificate-hygiene observations (missing SCT, an untrusted/pinned CA, an
// incomplete chain, a missing Subject DN) were moved out of weak_reasons into
// their own cert_hygiene_flags field on ExternalConnection, specifically so
// they stop being counted as "weak crypto" — see CLAUDE.md "Crypto Assessment
// Source of Truth" and the CHANGELOG [Unreleased] entry. That backend split is
// only worth anything if the observation still reaches the user somewhere:
// this pins the two places it does on the Connections lens (Inventory →
// Connections) — the CSV export and the row's hygiene indicator — so a future
// edit can't silently drop cert_hygiene_flags from the UI the way the SCT text
// used to be silently dropped from weak_reasons's tooltip.
//
// inventory-page.tsx has no JSX/DOM-rendering test harness in this repo (see
// inventory-page.ownership-filter.test.ts), so — same shape as that guard —
// this is structural: it reads the source and asserts the shape of the
// relevant expressions rather than rendering the component.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./inventory-page.tsx', import.meta.url)), 'utf8');

describe('Connections lens: certificate-hygiene surfaced separately from strength', () => {
  it('CSV export includes a cert_hygiene_flags column, distinct from weak_reasons', () => {
    const headerLine = src.split('\n').find((l) => l.includes("'destination', 'port', 'source', 'protocol'"));
    expect(headerLine, 'connections CSV header row not found').toBeTruthy();
    expect(headerLine).toContain("'weak_reasons'");
    expect(headerLine).toContain("'cert_hygiene_flags'");
  });

  it('CSV row values read cn.cert_hygiene_flags (not folded into the weak_reasons cell)', () => {
    const rowLine = src.split('\n').find((l) => l.includes('vista-inventory-connections') === false && l.includes('cn.dest_hostname') && l.includes('cn.cipher_suite'));
    expect(rowLine, 'connections CSV row-mapping line not found').toBeTruthy();
    expect(rowLine).toMatch(/cn\.cert_hygiene_flags\?\.join\(['"]; ['"]\)/);
    // The weak_reasons cell must not also carry hygiene text appended to it —
    // they are two separate array accesses, not one concatenated string.
    expect(rowLine).toMatch(/weak_reasons.*\)\?\.join\(['"]; ['"]\).*cn\.cert_hygiene_flags/);
  });

  it('the connections row reads cert_hygiene_flags into its own hygieneFlags/hygieneTitle, separate from weak_reasons/reasonsTitle', () => {
    expect(src).toMatch(/const hygieneFlags = cn\.cert_hygiene_flags;/);
    expect(src).toMatch(/const hygieneTitle = hygieneFlags && hygieneFlags\.length > 0 \? hygieneFlags\.join\(['"]; ['"]\) : undefined;/);
    // reasonsTitle (weak_reasons) must be a SEPARATE variable — the strength
    // badge's tooltip source — not reused for hygiene text.
    expect(src).toMatch(/const reasonsTitle = weakReasons && weakReasons\.length > 0/);
  });

  it('renders a hygiene indicator icon, gated on hygieneTitle, alongside (not merged into) the strength badge', () => {
    const idx = src.indexOf('const hygieneTitle = hygieneFlags');
    expect(idx).toBeGreaterThan(-1);
    // The strength badge and the hygiene indicator must be two sibling
    // elements: the badge's own title stays reasonsTitle (weak_reasons), and
    // a second, conditionally-rendered element carries the hygiene tooltip.
    const after = src.slice(idx, idx + 2000);
    expect(after).toMatch(/title=\{reasonsTitle\}/);
    expect(after).toMatch(/\{hygieneTitle && \(/);
    expect(after).toMatch(/<Icon name="shield-alert"/);
    // The hygiene tooltip text must say it is NOT a crypto weakness — the
    // whole point of the split — not just repeat the flags with no context.
    expect(after).toMatch(/Certificate hygiene \(not a crypto weakness\)/);
  });
});
