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
