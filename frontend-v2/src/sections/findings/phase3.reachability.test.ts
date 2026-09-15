// Phase-3 reachability: every producer, every new alert type, and the two
// settings pages the phase added — in BOTH polarities.
//
// Phase 3 shipped six finding producers, three alert types and two settings
// controls. The feature framework's rule is that no layer ships without its
// consumer, and the failure this file is built to catch is the quiet one: a
// producer that writes findings nobody can filter to, a kind whose evidence
// panel falls through to the generic "raised by X" card, an alert type the
// registry knows about that never reaches a screen, a settings control that
// exists in a file no route renders.
//
// What each of the six phase-3 UI surfaces is pinned by, so a reader can find
// the rest rather than assume this file is all of it:
//
//	Findings page: producer facet + inspector evidence   THIS FILE
//	asset page Findings tab                              THIS FILE
//	Software tab / lens EOL + CVE columns                 software.reachability.test.ts
//	topology view                                         topology.reachability.test.ts
//	dashboard Inventory health hero                        inventory-health.test.ts
//	                                                       inventory-health-hero.test.tsx
//	Settings → Alert Rules (the three new types)          THIS FILE
//	Settings → Asset Lifecycle (drift baseline)           THIS FILE
//
// Reading the real registries and the real source: a facet this test invented
// would prove nothing about what the app serves.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FINDING_KINDS, FINDING_PRODUCERS } from '@vistasecurity/primitives/findings';
import { ASSET_TABS, assetTabPath, findAssetTab, isTabLive } from '../inventory/asset-tabs';
import { SETTINGS_NAV } from '../settings/nav';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
const here = new URL('.', import.meta.url).pathname;
const read = (rel: string) => readFileSync(here + rel, 'utf8');
const readRepo = (rel: string) => readFileSync(repoRoot + rel, 'utf8');

// The producers whose findings a TENANT sees on the Findings page. `compliance`
// is one of them; it just reaches the page from the framework side.
const PRODUCER_KEYS = FINDING_PRODUCERS.map((p) => p.key);

describe('the Findings page reaches every producer', () => {
  it('has more than the one producer it started with', () => {
    // The anchor. Every assertion below iterates PRODUCER_KEYS, so a registry
    // that somehow came back empty would make all of them vacuously true.
    expect(PRODUCER_KEYS).toContain('compliance');
    expect(PRODUCER_KEYS).toContain('eol');
    expect(PRODUCER_KEYS).toContain('vulnerability');
    expect(PRODUCER_KEYS).toContain('crypto');
    expect(PRODUCER_KEYS).toContain('configuration');
    expect(PRODUCER_KEYS).toContain('hygiene');
    expect(PRODUCER_KEYS).toContain('drift');
  });

  it('builds the producer facet from the REGISTRY, so a producer with no findings still shows a 0', () => {
    // Not from the keys the response happens to carry. "We looked and found
    // none" and "nobody has looked" are different answers, and only the
    // registry knows which producers exist.
    const page = read('findings-page.tsx');
    expect(page).toContain('FINDING_PRODUCERS.map((p) => ({ key: p.key, label: p.label, count: counts[p.key] ?? 0 }))');
  });

  it('puts the producer filter in the URL, so a filtered view is linkable', () => {
    const page = read('findings-page.tsx');
    expect(page).toContain("params.get('producer')");
    expect(page).toContain("prm.set('producer', key)");
  });

  it('gives EVERY producer its own evidence panel in the inspector', () => {
    // The other polarity of the generic fallback at the bottom of
    // ProducerEvidence. That fallback stops a new producer white-screening the
    // drawer, which is right — and it also means a producer can ship with no
    // evidence panel at all and look fine, showing "Raised by the Drift
    // producer" over a finding whose whole value is the comparison it carries.
    const page = read('findings-page.tsx');
    const inspector = page.slice(page.indexOf('function ProducerEvidence('));
    expect(inspector.length, 'ProducerEvidence not found in findings-page.tsx').toBeGreaterThan(500);
    for (const key of PRODUCER_KEYS) {
      expect(inspector, `no evidence panel for the ${key} producer — its findings reach the drawer and ` +
        'show the generic "raised by" card instead of what it measured').toContain(`producer === '${key}'`);
    }
  });

  it('reads each producer evidence shape through the shared readers', () => {
    // The readers are where a malformed document turns into a blank panel
    // rather than a white screen, and each is pinned in both polarities in
    // producer-evidence.test.ts. What this asserts is that the page USES them.
    const page = read('findings-page.tsx');
    for (const reader of ['eolEvidence', 'cveList', 'configurationEvidence', 'hygieneEvidence', 'driftEvidence']) {
      expect(page, `findings-page.tsx does not use ${reader}`).toContain(reader);
    }
  });

  it('labels every registered KIND from the registry rather than from a second list', () => {
    const evidence = read('producer-evidence.ts');
    expect(evidence).toContain('FINDING_KINDS.find((k) => k.key === kind)');
    // And the registry actually carries the phase-3 kinds, so the label lookup
    // has something to find.
    const kindKeys = FINDING_KINDS.map((k) => k.key);
    for (const kind of ['os_end_of_life', 'known_vulnerability', 'plaintext_management', 'no_owner', 'new_issuer']) {
      expect(kindKeys, `the generated finding registry has no ${kind} kind`).toContain(kind);
    }
  });
});

describe('the asset page Findings tab', () => {
  it('is in the registry and is LIVE', () => {
    const tab = findAssetTab('findings');
    expect(tab.key).toBe('findings');
    expect(isTabLive(tab)).toBe(true);
  });

  it('carries no leftover placeholder', () => {
    // The other polarity: a tab that is in the registry, has a URL and renders
    // "arrives in phase 3" is reachable and useless.
    expect(ASSET_TABS.find((t) => t.key === 'findings')!.placeholder).toBeUndefined();
  });

  it('has a URL a person can be sent', () => {
    expect(assetTabPath('abc', 'findings')).toBe('/inventory/assets/abc/findings');
  });
});

describe('Settings → Alert Rules shows the alert catalog', () => {
  const nav = SETTINGS_NAV.flatMap((s) => s.items);

  it('has a built nav entry', () => {
    const item = nav.find((i) => i.key === 'alert-rules');
    expect(item, 'Settings has no Alert Rules entry').toBeDefined();
    expect(item!.built).toBe(true);
  });

  it('renders EVERY catalog entry, so a new alert type needs no UI change to be visible', () => {
    // This is what makes the three types workstream 3.9 added reachable: the
    // page maps the whole catalog rather than a hand-kept list. A filtered
    // render here is how an alert type ships live in the backend and is
    // invisible to the tenant who would route it.
    const src = readFileSync(here + '../settings/pages-integrations.tsx', 'utf8');
    expect(src).toContain("clients.compliance.GET('/alert-catalog'");
    expect(src).toContain('catalog.map((entry) => <CatalogCard key={entry.id} entry={entry} />)');
    expect(src).toContain('<AlertCatalogSection />');
  });

  it('the three types workstream 3.9 added are tenant-track and live in the registry', () => {
    // The other end of the same chain. GET /alert-catalog returns tenant-track
    // entries, so a type that is platform-track or not live never reaches the
    // page however faithfully the page renders what it is given.
    const registry = alertRegistryFromYaml();
    for (const id of ['known_vulnerability', 'end_of_life', 'hygiene_score_drop']) {
      const entry = registry.find((e) => e.id === id);
      expect(entry, `standards/alert-registry.yaml has no ${id} entry`).toBeDefined();
      expect(entry!.track, `${id} is not on the tenant track, so it never reaches Settings → Alert Rules`).toBe('tenant');
      expect(entry!.status, `${id} is not live`).toBe('live');
    }
  });
});

describe('Settings → Asset Lifecycle shows the drift baseline', () => {
  const nav = SETTINGS_NAV.flatMap((s) => s.items);

  it('has a built nav entry that says the baseline window lives there', () => {
    const item = nav.find((i) => i.key === 'asset-lifecycle');
    expect(item, 'Settings has no Asset Lifecycle entry').toBeDefined();
    expect(item!.built).toBe(true);
    expect(item!.job.toLowerCase()).toContain('drift baseline');
  });

  it('renders the baseline form and writes it back', () => {
    // Read AND write. A read-only card showing the default would look right on
    // screen and leave the producer on 30 days whatever the tenant chose.
    const src = readFileSync(here + '../settings/pages-infra.tsx', 'utf8');
    expect(src).toContain('DriftBaselineForm');
    expect(src).toContain('baseline_days');
    expect(src).toContain("'/settings/drift'");
  });
});

/** `id:` / `track:` / `status:` triples from standards/alert-registry.yaml. */
function alertRegistryFromYaml(): Array<{ id: string; track: string; status: string }> {
  const src = readRepo('standards/alert-registry.yaml');
  const body = src.slice(src.indexOf('\nalert_types:'));
  expect(body.length, 'could not find the `alert_types:` list in standards/alert-registry.yaml').toBeGreaterThan(100);
  const out: Array<{ id: string; track: string; status: string }> = [];
  let current: { id: string; track: string; status: string } | null = null;
  for (const line of body.split('\n')) {
    const id = /^\s*-\s+id:\s*([a-z0-9_]+)\s*$/.exec(line);
    if (id) {
      if (current) out.push(current);
      current = { id: id[1], track: '', status: '' };
      continue;
    }
    if (!current) continue;
    const track = /^\s+track:\s*([a-z]+)\s*$/.exec(line);
    if (track) current.track = track[1];
    const status = /^\s+status:\s*([a-z]+)\s*$/.exec(line);
    if (status) current.status = status[1];
  }
  if (current) out.push(current);
  return out;
}


// The search box, wired to the SERVER (seeds part 3).
//
// It used to filter the rows the page already held, and the page holds at most
// five pages of 200 — so a `?q=<product>` link into the 1,200th finding
// rendered "no findings match", indistinguishable on screen from a clean
// estate. `queries.jsdom.test.tsx` pins the REQUEST; this pins the page not
// undoing it, which is the regression a later "let's also filter locally, just
// in case" would be.
describe('the Findings search box', () => {
  const page = read('findings-page.tsx');

  it('sends the term to the list query', () => {
    // `dq` among the hook's arguments, not necessarily last — the call gained a
    // severity argument after it. Still positional, so a \b-bounded match is
    // what distinguishes it from `dqSomething`.
    expect(page).toMatch(/useFindingsList\([^)]*\bdq\b/);
  });

  it('debounces it, so typing is not one request per keystroke', () => {
    expect(page).toContain('setDq(q.trim())');
  });

  it('seeds itself from `?q=` so a link lands filtered', () => {
    expect(page).toContain("params.get('q')");
  });

  it('seeds the SENT term eagerly too, so the link searches on FIRST paint', () => {
    // `q` is what the box holds; `dq` is what is sent, and it is debounced.
    // Seeding `dq` from `''` instead still searches — 300 ms later — so the bug
    // is a page that renders the whole unsearched estate first and then
    // narrows. On a `?q=<product>` link out of the software surfaces, that
    // flash is every finding the tenant has under a heading naming one product.
    // Mutation-verified: `useState('')` leaves every other assertion here green.
    expect(page).toContain('const [dq, setDq] = useState(q)');
  });

  it('does NOT re-filter the findings stream in the browser', () => {
    // The other polarity, and the one that matters. The server also matches the
    // finding's KIND, so a narrower local pass would drop rows the server
    // matched — a filter that reads as applied and removes the right answers.
    expect(page).not.toContain('matchesFindingSearch');
  });
});
