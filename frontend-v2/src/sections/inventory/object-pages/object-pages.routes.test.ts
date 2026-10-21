// The object pages are reachable (DCIM gap 7): every route is registered in
// App.tsx, the rail keeps the matching lens lit on each page, and the lens
// rows / trace hops / drawer titles link to the page (not to a lens query).
//
// Mutation: delete a <Route> line from App.tsx, or the pathname clause from
// app-shell.tsx → the matching row of each table fails.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { OBJECT_PAGE_BASE, OBJECT_PAGE_LENS, backTarget, objectPageHref } from './object-links';
import { SECTIONS } from '../../../app/nav';

const src = (p: string) => readFileSync(resolve(process.cwd(), 'src', p), 'utf8');

const PAGES = [
  ['prefix', 'PrefixPage', 'networks'],
  ['vlan', 'VlanPage', 'vlans'],
  ['circuit', 'CircuitPage', 'circuits'],
  ['cable', 'CablePage', 'cabling'],
] as const;

describe('object page routes', () => {
  it.each([...PAGES, ['interface', 'InterfacePage', 'assets'] as const])('%s: route registered', (kind, component) => {
    const app = src('App.tsx');
    expect(app).toContain(`<Route path="${OBJECT_PAGE_BASE[kind]}/:id" element={<${component} />} />`);
  });

  it.each([...PAGES, ['interface', 'InterfacePage', 'assets'] as const])('%s: rail keeps its lens lit', (kind, _c, lens) => {
    const shell = src('app/app-shell.tsx');
    expect(shell).toContain(`pathname.startsWith('${OBJECT_PAGE_BASE[kind]}/') && item.lens === '${lens}'`);
  });

  it.each(PAGES)('%s: the lens exists in the Infrastructure nav', (kind, _c, lens) => {
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    const items = inventory.groups!.flatMap((g) => g.items);
    expect(items.some((i) => i.lens === lens && i.path === OBJECT_PAGE_LENS[kind].href)).toBe(true);
  });

  it('hrefs are built in one place', () => {
    expect(objectPageHref('circuit', 'a b')).toBe('/inventory/circuits/a%20b');
  });

  it('backTarget only accepts in-app inventory paths', () => {
    expect(backTarget({ from: '/inventory?lens=vlans&group=g1' }, '/x')).toBe('/inventory?lens=vlans&group=g1');
    expect(backTarget({ from: '/inventory/assets/1' }, '/x')).toBe('/inventory/assets/1');
    expect(backTarget({ from: '//evil.example' }, '/x')).toBe('/x');
    expect(backTarget({ from: 'https://evil.example' }, '/x')).toBe('/x');
    expect(backTarget({ from: '/inventoryx' }, '/x')).toBe('/x');
    expect(backTarget(null, '/x')).toBe('/x');
  });

  it('trace hops and cable ends link circuits to the circuit page', () => {
    expect(src('sections/inventory/cabling/trace-view.tsx')).toContain('circuitHref(n.circuit_id)');
    expect(src('sections/inventory/cabling/cabling-lens.tsx')).toContain('circuitHref(t.circuit_id)');
  });
});
