// Discovery → Active Scan is folded into Inventory. Its list is the
// built-in "Never scanned" view of All assets and its Scan is the bulk bar's;
// the page, its rail entry and every link to it are gone, and a bookmark lands
// on the view. These are the reachability half — the behaviour has its own
// tests (scan-dialog, bulk-action-bar, assets-lens.bulk-select).
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SECTIONS } from '../../app/nav';
import { checkAssetQuery } from './query-editor';
import { BUILTIN_VIEWS, NEVER_SCANNED_HREF, NEVER_SCANNED_QUERY } from './builtin-views';

const src = fileURLToPath(new URL('../../', import.meta.url));
const read = (rel: string) => readFileSync(join(src, rel), 'utf8');

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return sourceFiles(p);
    return /\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [p] : [];
  });
}

describe('the retired page', () => {
  it('has no rail entry', () => {
    const paths = SECTIONS.flatMap((s) => (s.groups ?? []).flatMap((g) => g.items.map((i) => i.path)));
    expect(paths).not.toContain('/discovery/active-scan');
  });

  it('redirects to the Never scanned view of All assets', () => {
    expect(read('App.tsx')).toMatch(/<Route path="\/discovery\/active-scan" element=\{<Navigate to=\{NEVER_SCANNED_HREF\} replace \/>\} \/>/);
    const url = new URL(NEVER_SCANNED_HREF, 'http://x');
    expect(url.pathname).toBe('/inventory');
    expect(url.searchParams.get('lens')).toBe('assets');
    expect(url.searchParams.get('query')).toBe(NEVER_SCANNED_QUERY);
  });

  it('nothing links to it any more', () => {
    const linking = sourceFiles(src)
      .filter((f) => !f.endsWith('App.tsx'))
      .filter((f) => readFileSync(f, 'utf8').includes("'/discovery/active-scan'") || readFileSync(f, 'utf8').includes('"/discovery/active-scan"'));
    expect(linking).toEqual([]);
  });
});

describe('the Never scanned view', () => {
  it('is a built-in view whose query the editor accepts', () => {
    const view = BUILTIN_VIEWS.find((v) => v.name === 'Never scanned');
    expect(view?.query).toBe(NEVER_SCANNED_QUERY);
    expect(checkAssetQuery(NEVER_SCANNED_QUERY).ok).toBe(true);
  });

  it('is offered in the Views menu', () => {
    const menu = read('sections/inventory/saved-views.tsx');
    expect(menu).toMatch(/BUILTIN_VIEWS\.map\(\(v\) => \(/);
    expect(menu).toMatch(/onClick=\{\(\) => \{ onApply\(v\.query\); setOpen\(false\); \}\}/);
  });
});
