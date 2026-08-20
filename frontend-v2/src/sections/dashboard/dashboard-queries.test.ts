// B-28 regression guard — dashboard rollup queries must not read a fetch
// failure as a real zero.
//
// Before the fix, fetchDashboardSensors / fetchDashboardDeviceAgents /
// fetchDashboardTicketStats destructured only `data` and never threw, so a
// non-2xx (device-interrogation-service or sensor-manager down, or a
// discovery.read permission gate on /agents) resolved as [] / undefined
// instead of an error — the Discovery stage and the Overdue-tickets tile then
// read "0/0" with no error shown anywhere on the page.
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

let dash: typeof import('./dashboard-queries');

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  vi.stubGlobal('document', { cookie: '' });
  dash = await import('./dashboard-queries');
});

afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

afterEach(() => fetchStub.mockClear());

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('B-28: fetchDashboardSensors', () => {
  it('throws on a 500 instead of resolving an empty fleet', async () => {
    nextResponse = () => json({ error: 'boom' }, 500);
    await expect(dash.fetchDashboardSensors()).rejects.toThrow();
  });
  it('resolves the sensor list on 200', async () => {
    nextResponse = () => json({ sensors: [{ id: 's1', status: 'active' }] });
    await expect(dash.fetchDashboardSensors()).resolves.toEqual([{ id: 's1', status: 'active' }]);
  });
});

describe('B-28: fetchDashboardDeviceAgents', () => {
  it('throws on a 500 (or a discovery.read 403) instead of resolving an empty fleet', async () => {
    nextResponse = () => json({ error: 'forbidden' }, 403);
    await expect(dash.fetchDashboardDeviceAgents()).rejects.toThrow();
  });
  it('resolves the agent list on 200', async () => {
    nextResponse = () => json({ agents: [{ id: 'a1', status: 'active' }] });
    await expect(dash.fetchDashboardDeviceAgents()).resolves.toEqual([{ id: 'a1', status: 'active' }]);
  });
});

describe('B-28: fetchDashboardTicketStats', () => {
  it('throws on a 500 instead of resolving undefined stats', async () => {
    nextResponse = () => json({ error: 'boom' }, 500);
    await expect(dash.fetchDashboardTicketStats()).rejects.toThrow();
  });
  it('resolves the ticket stats on 200', async () => {
    nextResponse = () => json({ stats: { total: 4, overdue: 1 } });
    await expect(dash.fetchDashboardTicketStats()).resolves.toEqual({ total: 4, overdue: 1 });
  });
});
