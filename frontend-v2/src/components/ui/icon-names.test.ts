// Every icon the UI names as a string is one `Icon` can actually draw.
//
// `Icon` looks a kebab-case name up in an explicit, tree-shakeable map. A name
// the map lacks is neither a type error nor a runtime error: in production it
// renders a question-mark placeholder, silently, and in dev it console.warns —
// which nobody reads in review. Thirty-four names — a merge button, two delete
// buttons, the asset page's Overview and Endpoints tabs, the map's Topology
// view — and every asset-class glyph shipped that way at once, because that
// warning was the only check.
//
// Names reach `Icon` two ways, so there are two layers:
//   1. registries that carry `icon: '...'` as bare strings and are rendered
//      elsewhere — the inventory lenses, the asset tabs, the settings and
//      profile nav, and the asset-class taxonomy via `classIcon()` (which
//      handed lucide EXPORT names to a kebab-keyed map for a whole phase) —
//      checked by importing the real arrays;
//   2. everything else, checked by scanning the source since there is nothing
//      to import: `<Icon name="...">` literals in components; the string
//      branches of `name={cond ? 'a' : 'b'}` expressions (five names hid
//      there from a scan of literal props alone); `icon="..."` attributes on
//      the components that forward an `icon` prop to `Icon` (three more hid
//      there); `icon: '...'` fields in the smaller registries with no test of
//      their own; and the values of `*_ICON` lookup tables keyed by kind
//      rather than carrying an `icon:` field (four more hid there).
// The scans are anchored non-empty so a regex that quietly stops matching
// fails here rather than turning every assertion into "[] equals []", and
// every `<Icon` tag in scope has to classify as literal-named or
// expression-named — a tag the name regex cannot read is itself a failure,
// not a silent skip.
//
// `app/app-shell.tsx` has its own PascalCase `Icon` over a local record; the
// literal scan is scoped to files that import THIS one, so it is not confused
// by that.
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ASSET_CLASS_KEYS } from '@vistasecurity/primitives/assets';
import { LEGACY_TICKET_CATEGORIES, TICKET_CATEGORIES, ticketCategory } from '@vistasecurity/primitives/tickets';
import { ICON_NAMES } from './icon';
import { INVENTORY_LENSES } from '../../sections/inventory/lenses';
import { ASSET_TABS } from '../../sections/inventory/asset-tabs';
import { classIcon } from '../../sections/inventory/asset-shape';
import { PROFILE_NAV, SETTINGS_NAV } from '../../sections/settings/nav';

const srcRoot = fileURLToPath(new URL('../../', import.meta.url));

/** Every non-test, non-declaration .ts/.tsx under src/, as absolute paths. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (/\.tsx?$/.test(entry.name) && !/\.(test|d)\.tsx?$/.test(entry.name)) out.push(full);
  }
  return out;
}

interface Use { where: string; name: string }

const lineOf = (src: string, index: number): number => src.slice(0, index).split('\n').length;

// The shared component, imported under its own name. `Icon as LensIcon` is not
// rendered as `<Icon>`, so it is deliberately not matched.
const IMPORTS_SHARED_ICON = /import\s*\{[^}]*\bIcon\s*[,}][^;]*from\s*'(?:[./]+components\/ui|\.\/icon)'/;
// Every <Icon tag, then the ones whose `name` is a string literal or a `{expr}`.
const ICON_TAG = /<Icon\b/g;
const ICON_NAME = /<Icon\b[^>]*?\bname=(?:"([^"]+)"|'([^']+)'|(\{))/g;
// Inside a `name={...}` expression: a comparison operand (`mode === 'ask'`) is
// not an icon name, but every other kebab-case string is a branch that will be
// handed to `Icon` when its condition holds.
const COMPARISON = /[!=]==?\s*'[^']*'/g;
const KEBAB_STRING = /'([a-z][a-z0-9]*(?:-[a-z0-9]+)*)'/g;
// A kebab-case `icon: '...'` field anywhere — a registry rendered elsewhere.
const ICON_FIELD = /\bicon:\s*'([a-z][a-z0-9]*(?:-[a-z0-9]+)*)'/g;
// An `icon=` JSX attribute: a literal, or an expression handled like `name=`.
const ICON_ATTR = /\sicon=(?:"([^"]+)"|'([^']+)'|(\{))/g;
// A `FOO_ICON: Record<..., string> = { kind: 'name', ... }` lookup table.
const ICON_TABLE = /\b[A-Za-z_]*ICONS?\s*:\s*(?:Readonly<)?Record<[^=]*?string>+\s*=\s*\{([\s\S]*?)\n\}/g;
const TABLE_VALUE = /:\s*'([a-z][a-z0-9]*(?:-[a-z0-9]+)*)'/g;

/** The text of the `{...}` opening at `open`, with braces balanced. */
function braced(src: string, open: number): string {
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}' && (depth -= 1) === 0) return src.slice(open + 1, i);
  }
  throw new Error(`unbalanced braces after offset ${open}`);
}

function scan(): { literals: Use[]; fields: Use[]; unreadable: string[]; dynamic: number } {
  const literals: Use[] = [];
  const fields: Use[] = [];
  const unreadable: string[] = [];
  let dynamic = 0;
  for (const file of sourceFiles(srcRoot)) {
    const src = readFileSync(file, 'utf8');
    const rel = relative(srcRoot, file);
    for (const m of src.matchAll(ICON_FIELD)) fields.push({ where: `${rel}:${lineOf(src, m.index)}`, name: m[1] });
    for (const t of src.matchAll(ICON_TABLE)) {
      for (const v of t[1].replace(/\/\/.*$/gm, '').matchAll(TABLE_VALUE)) fields.push({ where: `${rel}:${lineOf(src, t.index)} (table)`, name: v[1] });
    }
    for (const m of src.matchAll(ICON_ATTR)) {
      const where = `${rel}:${lineOf(src, m.index)} (icon=)`;
      if (!m[3]) {
        fields.push({ where, name: m[1] ?? m[2] });
        continue;
      }
      const expr = braced(src, m.index + m[0].length - 1).replace(COMPARISON, '');
      for (const lit of expr.matchAll(KEBAB_STRING)) fields.push({ where: `${where} (branch)`, name: lit[1] });
    }
    if (!IMPORTS_SHARED_ICON.test(src)) continue;
    const tags = [...src.matchAll(ICON_TAG)].map((m) => m.index);
    const named = new Set<number>();
    for (const m of src.matchAll(ICON_NAME)) {
      named.add(m.index);
      const where = `${rel}:${lineOf(src, m.index)}`;
      if (!m[3]) {
        literals.push({ where, name: m[1] ?? m[2] });
        continue;
      }
      dynamic += 1;
      const expr = braced(src, m.index + m[0].length - 1).replace(COMPARISON, '');
      for (const lit of expr.matchAll(KEBAB_STRING)) literals.push({ where: `${where} (branch)`, name: lit[1] });
    }
    for (const at of tags) if (!named.has(at)) unreadable.push(`${rel}:${lineOf(src, at)}`);
  }
  return { literals, fields, unreadable, dynamic };
}

const unresolved = (uses: Use[]): string[] =>
  uses.filter((u) => !ICON_NAMES.includes(u.name)).map((u) => `${u.where}: ${u.name}`);

describe('icon names the UI uses', () => {
  it('has a map to check against', () => {
    expect(ICON_NAMES.length).toBeGreaterThan(100);
  });

  it('inventory lenses all resolve', () => {
    expect(INVENTORY_LENSES.length).toBeGreaterThan(5);
    expect(unresolved(INVENTORY_LENSES.map((l) => ({ where: `lens ${l.key}`, name: l.icon })))).toEqual([]);
  });

  it('asset tabs all resolve', () => {
    expect(ASSET_TABS.length).toBeGreaterThan(5);
    expect(unresolved(ASSET_TABS.map((t) => ({ where: `tab ${t.key}`, name: t.icon })))).toEqual([]);
  });

  it('settings and profile nav all resolve', () => {
    const items: Use[] = [
      ...SETTINGS_NAV.flatMap((s) => s.items.map((i) => ({ where: `settings ${s.section}/${i.key}`, name: i.icon }))),
      ...PROFILE_NAV.map((i) => ({ where: `profile ${i.key}`, name: i.icon })),
    ];
    expect(items.length).toBeGreaterThan(20);
    expect(unresolved(items)).toEqual([]);
  });

  it('every asset class, and the unknown-class fallback, all resolve', () => {
    expect(ASSET_CLASS_KEYS.length).toBeGreaterThan(20);
    const classes: Use[] = ASSET_CLASS_KEYS.map((key) => ({ where: `class ${key}`, name: classIcon(key) }));
    expect(unresolved([...classes, { where: 'class (unknown)', name: classIcon('not_a_class') }])).toEqual([]);
  });

  // Ticket categories live in packages/primitives, OUTSIDE the src/ tree the
  // field scan below walks, so they are checked by importing the real
  // registry — same reason as the asset classes above. The retired categories
  // are checked too: a pre-split row still renders an icon.
  it('every ticket category, writable and retired, resolves', () => {
    const cats: Use[] = TICKET_CATEGORIES.map((c) => ({ where: `ticket category ${c.key}`, name: c.icon }));
    const legacy: Use[] = LEGACY_TICKET_CATEGORIES.map((k) => ({
      where: `retired ticket category ${k}`,
      name: ticketCategory(k)!.icon,
    }));
    expect(cats.length).toBeGreaterThan(8);
    expect(unresolved([...cats, ...legacy])).toEqual([]);
  });

  const scanned = scan();

  it('reads the name of every <Icon> tag in scope', () => {
    // A tag the regex cannot classify would otherwise be a silent skip — the
    // exact failure mode this file exists to close.
    expect(scanned.unreadable).toEqual([]);
    expect(scanned.literals.length).toBeGreaterThan(200);
    expect(scanned.dynamic).toBeGreaterThan(20);
  });

  it('<Icon name="..."> literals across src/ all resolve', () => {
    expect(unresolved(scanned.literals)).toEqual([]);
  });

  it("icon: '...' fields, icon=\"...\" attributes and *_ICON tables across src/ all resolve", () => {
    expect(scanned.fields.filter((f) => f.where.endsWith('(icon=)')).length).toBeGreaterThan(100);
    expect(scanned.fields.filter((f) => f.where.endsWith('(table)')).length).toBeGreaterThan(10);
    expect(scanned.fields.length).toBeGreaterThan(200);
    expect(unresolved(scanned.fields)).toEqual([]);
  });
});
