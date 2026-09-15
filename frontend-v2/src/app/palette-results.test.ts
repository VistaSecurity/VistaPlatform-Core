// The palette's result model (ADR-0006 D9).
//
// One shape for both modes, and two NEW kinds — class and relationship — that
// the ADR asks for by name. What is pinned here is what a row links to, because
// that is the half a reader cannot check by looking at the palette: a row that
// renders beautifully and navigates to a page that filters on nothing is the
// failure this file exists to catch.
import { describe, expect, it } from 'vitest';
import { ASSET_CLASSES } from '@vistasecurity/primitives/assets';
import { ICON_NAMES } from '../components/ui/icon';
import {
  KIND_ICON, KIND_LABEL, assetItem, classItem, classesOfAssets, inventoryQueryLink, inventorySearchLink,
  matchingClasses, relationshipItem, sectionsOf,
  type Asset, type CommandItem, type Relationship, type ResultKind,
} from './palette-results';

const ASSET_ID = '550e8400-e29b-41d4-a716-446655440000';

function asset(over: Partial<Asset> = {}): Asset {
  return {
    id: ASSET_ID,
    display_name: 'web01',
    class_key: 'server',
    environment: 'production',
    risk_score: 0,
    ...over,
  } as unknown as Asset;
}

describe('the deep link into Inventory', () => {
  it('carries a PREDICATE as ?query= on the lens that has the editor', () => {
    // `query`, not `q`. They are different parameters: `q` seeds the free-text
    // search box, `query` is the predicate the facet rail writes and the editor
    // edits. Landing a predicate in `q` would render a page that filtered on a
    // string nobody meant as a search term.
    const to = inventoryQueryLink('environment:production and status:monitoring');
    const url = new URL(to, 'https://vista.example');
    expect(url.pathname).toBe('/inventory');
    expect(url.searchParams.get('lens')).toBe('assets');
    expect(url.searchParams.get('query')).toBe('environment:production and status:monitoring');
    expect(url.searchParams.get('q')).toBeNull();
  });

  it('round-trips a predicate containing every character the language uses', () => {
    // Quotes, brackets, comparison operators and a regex all appear in real
    // predicates; a link that mangled one would silently open on a DIFFERENT
    // query from the one the answer was about.
    const predicate = 'cert:(not_after < now+30d) and hostname ~ "^web[0-9]+$" and risk >= high';
    const url = new URL(inventoryQueryLink(predicate), 'https://vista.example');
    expect(url.searchParams.get('query')).toBe(predicate);
  });

  it('omits the parameter entirely for an empty predicate', () => {
    expect(inventoryQueryLink('   ')).toBe('/inventory?lens=assets');
  });

  it('keeps the free-text link on ?q=, which is a different thing', () => {
    const url = new URL(inventorySearchLink('certificate', 'web01.example'), 'https://vista.example');
    expect(url.searchParams.get('q')).toBe('web01.example');
    expect(url.searchParams.get('query')).toBeNull();
  });
});

describe('asset rows', () => {
  it('open the asset PAGE', () => {
    expect(assetItem(asset()).to).toBe(`/inventory/assets/${ASSET_ID}`);
  });

  it('badge Medium and above, and nothing below', () => {
    expect(assetItem(asset({ risk_score: 75, risk_level: 'High' } as Partial<Asset>)).badge).toBe('High');
    expect(assetItem(asset({ risk_score: 10 } as Partial<Asset>)).badge).toBeUndefined();
  });

  it('does not badge a score of 0', () => {
    // 0 with nothing that scored it is NOT ASSESSED. A badge reading
    // "Informational" on it would render "nobody looked" as "we looked and it
    // was fine", which is the flattening the whole codebase is written against.
    expect(assetItem(asset({ risk_score: 0 } as Partial<Asset>)).badge).toBeUndefined();
  });
});

describe('class rows (D9)', () => {
  it('link to the assets IN the class, by SUBTREE', () => {
    const item = classItem('hardware');
    const url = new URL(item.to, 'https://vista.example');
    // `class:` and not `class=`: a person typing "hardware" means everything
    // under it, and the exact operator would return only assets classified as
    // the bare parent — usually none.
    expect(url.searchParams.get('query')).toBe(`class:${ASSET_CLASSES.hardware.path}`);
    expect(item.kind).toBe('class');
    expect(item.label).toBe(ASSET_CLASSES.hardware.label);
  });

  it('matches on label, key and dotted path', () => {
    expect(matchingClasses('server').some((c) => c.id === 'class-server')).toBe(true);
    expect(matchingClasses('hardware.computer').length).toBeGreaterThan(0);
    expect(matchingClasses('Firewall').some((c) => c.id === 'class-firewall')).toBe(true);
  });

  it('matches nothing for an empty term, and is capped', () => {
    expect(matchingClasses('')).toEqual([]);
    // A one-letter term matches most of the taxonomy; without the cap it would
    // push every other kind of result off the list.
    expect(matchingClasses('e').length).toBeLessThanOrEqual(4);
  });

  it('offers only classes that exist in the generated registry', () => {
    for (const item of matchingClasses('a', 50)) {
      const key = item.id.replace(/^class-/, '');
      expect(Object.keys(ASSET_CLASSES)).toContain(key);
    }
  });
});

// Ask mode used to render asset rows and NOTHING else, so D9's "renders the
// tool results as the same result rows" was two-thirds true: the same question
// typed as a search offered classes and relationships, and asked in words
// offered neither. One surface, two behaviours, depending on phrasing.
describe('the classes an answer is about', () => {
  it('turns the answer rows into the SAME class rows search mode builds', () => {
    const rows = classesOfAssets([asset({ class_key: 'server' })]);
    expect(rows).toEqual([classItem('server')]);
  });

  it('deduplicates, so ten servers are one class row', () => {
    const rows = classesOfAssets([
      asset({ class_key: 'server' }),
      asset({ class_key: 'server' }),
      asset({ class_key: 'switch' }),
    ]);
    expect(rows.map((r) => r.id)).toEqual(['class-server', 'class-switch']);
  });

  it('keeps the answer ORDER, which is the server ranking', () => {
    const rows = classesOfAssets([
      asset({ class_key: 'switch' }),
      asset({ class_key: 'server' }),
    ]);
    expect(rows.map((r) => r.id)).toEqual(['class-switch', 'class-server']);
  });

  it('caps, so class rows cannot bury the answer they came from', () => {
    const many = ['server', 'switch', 'router', 'firewall'].map(
      (k) => asset({ class_key: k }));
    expect(classesOfAssets(many, 3)).toHaveLength(3);
  });

  it('skips a class the generated registry does not carry', () => {
    // A tenant leaf subclass has no label and no path here, and `classItem`
    // reads both from the registry. A row with a blank label linking to an
    // empty predicate is worse than no row.
    expect(classesOfAssets([asset({ class_key: 'a-tenant-subclass' })])).toEqual([]);
    expect(classesOfAssets([asset({ class_key: '' })])).toEqual([]);
  });

  it('is empty for an empty answer', () => {
    expect(classesOfAssets([])).toEqual([]);
  });
});

describe('relationship rows (D9)', () => {
  const edge = {
    id: 'e1',
    type: 'runs_on',
    label: 'runs on',
    source_kind: 'measured',
    status: 'active',
    peer: { asset_id: 'peer-1', display_name: 'esxi-03', deleted: false },
  } as unknown as Relationship;

  it('read as a sentence from the matched asset\'s own side', () => {
    const item = relationshipItem(ASSET_ID, 'web01', edge);
    expect(item.kind).toBe('relationship');
    expect(item.label).toBe('web01 runs on esxi-03');
    expect(item.sublabel).toBe('measured · active');
  });

  it('open the Relationships tab of the asset the search matched', () => {
    // Not the peer's page: the user asked about this asset, and the tab is
    // where the edge, its provenance and the impact closure are.
    expect(relationshipItem(ASSET_ID, 'web01', edge).to)
      .toBe(`/inventory/assets/${ASSET_ID}/relationships`);
  });

  it('falls back to the server label, then the type, and names an unnamed peer', () => {
    const bare = { ...edge, label: undefined, peer: undefined } as unknown as Relationship;
    expect(relationshipItem(ASSET_ID, 'web01', bare).label).toBe('web01 runs_on an unnamed asset');

    // A peer whose display name is the empty STRING has no name — `??` would
    // have kept it and rendered "web01 runs on ".
    const blank = {
      ...edge,
      peer: { asset_id: 'p', display_name: '', primary_identifier: 'serial:ABC123', deleted: false },
    } as unknown as Relationship;
    expect(relationshipItem(ASSET_ID, 'web01', blank).label).toBe('web01 runs on serial:ABC123');
  });
});

describe('the result model itself', () => {
  it('labels and ICONS every kind, including the two D9 added', () => {
    const kinds: ResultKind[] = ['nav', 'asset', 'cert', 'device', 'sensor', 'class', 'relationship'];
    for (const kind of kinds) {
      expect(KIND_LABEL[kind], `${kind} has no section label`).toBeTruthy();
      // Named AND drawable. `Icon` falls back to a question mark for a name it
      // does not know — silently in production, by design — so a kind whose
      // glyph was never added renders a placeholder nobody notices in review.
      expect(ICON_NAMES, `${kind} names an icon the Icon map cannot draw`).toContain(KIND_ICON[kind]);
    }
  });

  it('groups CONTIGUOUS runs, so ranking is never rearranged to tidy a header', () => {
    const items = [
      { kind: 'asset' }, { kind: 'asset' }, { kind: 'class' }, { kind: 'asset' },
    ] as CommandItem[];
    expect(sectionsOf(items)).toEqual([
      { kind: 'asset', start: 0, count: 2 },
      { kind: 'class', start: 2, count: 1 },
      { kind: 'asset', start: 3, count: 1 },
    ]);
  });

  it('has no sections for no items', () => {
    expect(sectionsOf([])).toEqual([]);
  });
});
