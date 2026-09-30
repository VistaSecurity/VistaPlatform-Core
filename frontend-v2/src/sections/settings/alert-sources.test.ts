// B-33 regression guard — the routing-rule "Alert source" dropdown must offer
// exactly the values a routing rule can actually match (rule_engine.go
// exact-matches tenant_notification_rules.alert_source), not a hand-maintained
// list that has drifted from what any producer emits.
//
// alert-sources.ts imports the app's `clients` (openapi-fetch), which binds
// to globalThis.fetch/Request at client-creation time — so this module must be
// imported dynamically, AFTER the fetch/Request stubs are installed, same as
// clients.csrf.test.ts / edition-gating.test.ts. A static top-level import
// here would eval clients.ts against the real (unstubbed) globals first and
// poison the module cache for the rest of the file.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

const fetchStub = vi.fn(async () => nextResponse());
let nextResponse: () => Response = () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });

class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}

const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

let mod: typeof import('./alert-sources');

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('document', { cookie: '' });
  mod = await import('./alert-sources');
});

afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

afterEach(() => fetchStub.mockClear());

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('B-33: alertSourceOptions', () => {
  it('always leads with "all", even with no registry sources loaded yet', () => {
    expect(mod.alertSourceOptions([], 'all')[0]).toBe('all');
  });

  it('never offers a fictional value the old hardcoded list had — certificates, platform', () => {
    const options = mod.alertSourceOptions(['inventory-service', 'compliance-engine'], 'all');
    expect(options).not.toContain('certificates');
    expect(options).not.toContain('platform');
  });

  it('includes every registry (tenant-track) source the catalog reports', () => {
    const registrySources = ['inventory-service', 'compliance-engine', 'sensor-manager', 'device-interrogation-service', 'cluster-sensor-service', 'audit', 'auth-service'];
    const options = mod.alertSourceOptions(registrySources, 'all');
    for (const s of registrySources) expect(options).toContain(s);
  });

  it('includes the non-registry producers (system, digest, billing-service)', () => {
    const options = mod.alertSourceOptions(['inventory-service'], 'all');
    for (const s of mod.NON_REGISTRY_ALERT_SOURCES) expect(options).toContain(s);
  });

  it("carries the currently-edited rule's source even if unknown, so the <select> value is never orphaned", () => {
    const options = mod.alertSourceOptions(['inventory-service'], 'a-legacy-value-nothing-emits-anymore');
    expect(options).toContain('a-legacy-value-nothing-emits-anymore');
  });

  it('never duplicates "all" when the current rule source is already "all"', () => {
    const options = mod.alertSourceOptions(['inventory-service'], 'all');
    expect(options.filter((s) => s === 'all')).toHaveLength(1);
  });

  it('de-duplicates a registry source that is also a non-registry source (defensive)', () => {
    const options = mod.alertSourceOptions(['system'], 'all');
    expect(options.filter((s) => s === 'system')).toHaveLength(1);
  });
});

describe('B-33: fetchAlertCatalogSources', () => {
  it('throws on a 500 rather than resolving an empty source list', async () => {
    nextResponse = () => json({ error: 'boom' }, 500);
    await expect(mod.fetchAlertCatalogSources()).rejects.toThrow();
  });

  it('extracts the `source` field off each catalog entry', async () => {
    nextResponse = () => json({ catalog: [{ id: 'certificate_expiring', source: 'inventory-service' }, { id: 'sensor_offline', source: 'sensor-manager' }] });
    await expect(mod.fetchAlertCatalogSources()).resolves.toEqual(['inventory-service', 'sensor-manager']);
  });
});

// ---------------------------------------------------------------------------
// M26 — the dropdown must offer every source a producer can publish.
//
// The dropdown was a hand-kept list; `discovery`, `ticketing`,
// `remediation_plans` and `billing` were real producers it omitted, so a rule
// scoped to them could never be created and source-specific routing for those
// events silently never fired. This finds every AlertSource the Go producers
// publish to `notifications.send` — from the source, not from a second list — and
// fails when the UI's option universe lacks one.
//
// Mutation-check both ways: drop an entry from NON_REGISTRY_ALERT_SOURCES (fails
// naming it); add `AlertSource: "brand_new"` to any producer (fails naming it).
// ---------------------------------------------------------------------------

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

function walkGo(dir: string, out: string[] = []): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === 'vendor' || e.name === '.git') continue;
      walkGo(p, out);
    } else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) {
      out.push(p);
    }
  }
  return out;
}

/** Sources published to notifications.send: every file that publishes to the
 *  subject or POSTs to /internal/send, outside notification-service itself. */
function producerSources(): { literals: Map<string, string[]>; dynamicFiles: string[] } {
  const literals = new Map<string, string[]>();
  const dynamicFiles: string[] = [];
  for (const file of [...walkGo(join(REPO_ROOT, 'services')), ...walkGo(join(REPO_ROOT, 'shared'))]) {
    const rel = file.slice(REPO_ROOT.length + 1);
    if (rel.startsWith('services/notification-service/')) continue; // the consumer, not a producer
    const src = readFileSync(file, 'utf8');
    if (!src.includes('SubjectNotificationsSend') && !src.includes('/internal/send')) continue;
    for (const m of src.matchAll(/(?:AlertSource:|"alert_source":)\s*"([^"]+)"/g)) {
      literals.set(m[1], [...(literals.get(m[1]) ?? []), rel]);
    }
    if (/AlertSource:\s*[A-Za-z_]/.test(src)) dynamicFiles.push(rel);
  }
  return { literals, dynamicFiles };
}

/** Sources standards/alert-registry.yaml assigns to TENANT-track alert types —
 *  what GET /alert-catalog (and so the dropdown) returns. */
function tenantTrackRegistrySources(): string[] {
  const text = readFileSync(join(REPO_ROOT, 'standards', 'alert-registry.yaml'), 'utf8');
  const sources: string[] = [];
  for (const block of text.split(/\n {2}- id: /).slice(1)) {
    const track = /\n\s+track:\s*(\w+)/.exec(block)?.[1];
    const source = /\n\s+source:\s*(\S+)/.exec(block)?.[1];
    if (track === 'tenant' && source) sources.push(source);
  }
  return sources;
}

// Producers whose AlertSource is a variable, not a literal. Each is safe ONLY
// because of the reason given; a NEW dynamic producer must be added here on
// purpose (or, better, pass a literal).
const DYNAMIC_PRODUCERS: Record<string, string> = {
  'services/compliance-engine/internal/services/alert_engine_service.go':
    "the stateful alert engine forwards the alert's registry `source` (tenant-track sources are in the option list via GET /alert-catalog)",
  'services/monitoring-service/internal/jobs/alert_evaluator.go':
    'reads req["alert_source"], whose literal ("monitoring") is scanned in the same file',
  'services/cluster-sensor-service/internal/services/alert_service.go':
    'reads req["alert_source"], whose literal ("discovery") is scanned in the same file',
};

// Sources that only ever appear on PLATFORM-scoped notifications (tenant_id
// nil), which are routed by platform rules in admin-ui — Settings → Notification
// Delivery — never by a tenant's routing rule, so the tenant dropdown must not
// offer them.
const PLATFORM_SCOPED_SOURCES = new Set(['monitoring']);

describe('M26: every Go-published alert source is offered by the routing-rule dropdown', () => {
  it('finds the producers (guards against the scan silently matching nothing)', () => {
    const { literals } = producerSources();
    // A scan that finds nothing would make every assertion below vacuous.
    expect([...literals.keys()]).toEqual(expect.arrayContaining(['discovery', 'ticketing', 'remediation_plans', 'audit']));
    // Core publishes five sources; Enterprise adds billing (ee/billing), which the
    // public (Core) tree does not carry.
    let minProducers = 5;
    expect(literals.size).toBeGreaterThanOrEqual(minProducers);
  });

  it('offers every source a producer publishes', () => {
    const { literals } = producerSources();
    const offered = new Set(mod.alertSourceOptions(tenantTrackRegistrySources(), 'all'));
    const missing = [...literals.entries()]
      .filter(([source]) => !offered.has(source) && !PLATFORM_SCOPED_SOURCES.has(source))
      .map(([source, files]) => `${source}  (published by ${[...new Set(files)].join(', ')})`);
    expect(missing, `producers publish alert sources the dropdown does not offer — add them to NON_REGISTRY_ALERT_SOURCES in alert-sources.ts:\n${missing.join('\n')}`).toEqual([]);
  });

  it('knows every producer whose source is a variable', () => {
    const { dynamicFiles } = producerSources();
    const unknown = dynamicFiles.filter((f) => !(f in DYNAMIC_PRODUCERS));
    expect(unknown, `a producer publishes a non-literal AlertSource this guard cannot resolve — pass a literal or add it to DYNAMIC_PRODUCERS with a reason:\n${unknown.join('\n')}`).toEqual([]);
  });

  it('does not offer platform-scoped sources to tenants', () => {
    const offered = new Set(mod.alertSourceOptions(tenantTrackRegistrySources(), 'all'));
    for (const s of PLATFORM_SCOPED_SOURCES) expect(offered.has(s)).toBe(false);
  });
});
