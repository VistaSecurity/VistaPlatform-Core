// @vitest-environment jsdom
// Discover assets, "find everything on this host or network" ( WP4a):
// every state of spec §1's table, driven through the REAL dialog with only the
// network mocked — depth, Advanced (Custom ports, pace, OT), Run from, the
// dry-run preview (debounced, stale requests cancelled, every outcome), Start,
// the "started" state, and closing at any moment.
//
// Every server answer is mocked: nothing here needs a running platform.
import { act, type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DiscoverAssetsModal } from './discover-modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const mocks = vi.hoisted(() => ({
  post: vi.fn(), create: vi.fn(), preview: vi.fn(), get: vi.fn(), sensors: vi.fn(), navigate: vi.fn(), close: vi.fn(),
  ot: { on: true },
}));
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: mocks.post, GET: mocks.get }, sensors: { GET: mocks.sensors } } }));
vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('@vistasecurity/primitives/features', () => ({ useFeature: (name: string) => (name === 'ot_active_probing' ? mocks.ot.on : false) }));
vi.mock('../../components/ui', () => ({
  // The real Modal closes on its × / Esc / scrim only when `dismissible`; the
  // stand-in renders a Close button under the same condition.
  Modal: ({ children, primary, secondary, footerNote, onClose, dismissible }: {
    children: ReactNode; primary: ReactNode; secondary: ReactNode; footerNote: ReactNode; onClose?: () => void; dismissible?: boolean;
  }) => (
    <div>
      {dismissible !== false && onClose && <button aria-label="Close dialog" onClick={onClose}>×</button>}
      {children}<footer>{secondary}{primary}</footer><p data-testid="note">{footerNote}</p>
    </div>
  ),
  ModalField: ({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) => <div><span>{label}</span>{children}<small>{hint}</small></div>,
  ModalInput: (props: InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  ModalSelect: (props: SelectHTMLAttributes<HTMLSelectElement>) => <select {...props} />,
  Icon: () => null,
}));

const now = () => new Date().toISOString();
const SENSORS = [
  { id: '11111111-1111-4111-8111-111111111111', name: 'edge-a', status: 'active', last_heartbeat: now(), tags: [], platform: 'linux' },
  { id: '22222222-2222-4222-8222-222222222222', name: 'edge-b', status: 'offline', last_heartbeat: '2020-01-01T00:00:00Z', tags: [], platform: 'linux' },
  { id: '33333333-3333-4333-8333-333333333333', name: 'platform-sensor', status: 'active', last_heartbeat: now(), tags: ['system'], platform: 'platform' },
];
const ok = (data: unknown, status = 200) => ({ data, response: { ok: true, status } });
const failed = (status: number, error: unknown) => ({ error, response: { ok: false, status } });

const plan = (over: Record<string, unknown> = {}) => ({
  depth: 'standard', pace: 'normal', tcp_ports: '1-1024,1080', udp_ports: '53,123', tcp_port_count: 1364, udp_port_count: 11,
  run_from_requested: 'auto', executor_resolved: 'sensor', sensor_id: SENSORS[0].id, sensor_name: 'edge-a',
  executor_reason: 'every target is on networks it reports, and sensor edge-a is online',
  depth_adjustments: [], targets: [], estimated_probes: 349_250, probe_limit: 25_000_000, ...over,
});
const previewOf = (over: Record<string, unknown> = {}, planOver: Record<string, unknown> = {}) => ok({
  plan: plan(planOver),
  estimate: { probes: 349_250, addresses: 254, seconds_best: 95, seconds_worst: 3500, basis: 'An estimate, not a promise: liveness checks usually remove many addresses.' },
  confirmation_required: false,
  external_targets: [],
  ...over,
});
const created = (planOver: Record<string, unknown> = {}) => ok({ job: { id: 'a1b2c3d4-0000-4000-8000-000000000000', status: 'queued', targets: ['10.0.0.0/24'], plan: plan(planOver) } }, 202);

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  try { localStorage.clear(); } catch { /* no storage */ }
  mocks.ot.on = true;
  mocks.create.mockReset().mockResolvedValue(created());
  mocks.preview.mockReset().mockResolvedValue(previewOf());
  mocks.post.mockReset().mockImplementation((_path: string, opts: { body: { dry_run?: boolean } }): unknown =>
    (opts.body.dry_run ? mocks.preview(opts) : mocks.create(opts)));
  mocks.get.mockReset();
  mocks.sensors.mockReset().mockResolvedValue(ok({ sensors: SENSORS }));
  mocks.navigate.mockReset();
  mocks.close.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { mutations: { retry: false }, queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(open = true) {
  await act(async () => { root.render(<QueryClientProvider client={cache}><DiscoverAssetsModal open={open} onClose={mocks.close} /></QueryClientProvider>); });
}
function setValue(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}
const q = <T extends Element>(sel: string) => host.querySelector<T>(sel);
async function type(label: string, value: string) {
  const el = q<HTMLInputElement>(`[aria-label="${label}"]`);
  if (!el) throw new Error(`no field "${label}" in: ${host.textContent}`);
  await act(async () => setValue(el, value));
}
const button = (label: string) => [...host.querySelectorAll('button')].find((b) => b.getAttribute('aria-label') === label || b.textContent?.trim() === label || b.textContent?.includes(label));
async function click(label: string) {
  const b = button(label);
  if (!b) throw new Error(`no "${label}" button in: ${host.textContent}`);
  await act(async () => { b.click(); });
}
/** The radio/checkbox whose label reads `text`. */
function choice(text: string): HTMLInputElement {
  const label = [...host.querySelectorAll('label')].find((l) => l.textContent?.trim().startsWith(text));
  const input = label?.querySelector('input');
  if (!input) throw new Error(`no choice "${text}" in: ${host.textContent}`);
  return input;
}
async function pick(text: string) {
  const c = choice(text);
  await act(async () => { c.click(); });
}
const runFrom = () => q<HTMLSelectElement>('select[aria-label="Run from"]')!;
const previews = () => mocks.preview.mock.calls.map((c) => (c[0] as { body: Record<string, unknown> }).body);
const creates = () => mocks.create.mock.calls.map((c) => (c[0] as { body: Record<string, unknown> }).body);
const panel = () => q<HTMLElement>('[data-testid="discover-preview"]')?.textContent ?? '';
const sleep = (ms: number) => act(() => new Promise<void>((r) => { setTimeout(r, ms); }));
async function ready(targets = '10.0.0.0/24') {
  await render();
  await vi.waitFor(() => expect(runFrom().disabled).toBe(false));
  await type('Targets', targets);
}
async function startAndWait() {
  await vi.waitFor(() => expect(button('Start discovery')?.disabled).toBe(false));
  await click('Start discovery');
}

describe('configure', () => {
  it('opens on Standard, Run from Auto, with Advanced collapsed and nothing to preview yet', async () => {
    await render();
    await vi.waitFor(() => expect(runFrom().disabled).toBe(false));
    expect(choice('Standard').checked).toBe(true);
    expect(['Quick', 'Thorough', 'Custom'].map((d) => choice(d).checked)).toEqual([false, false, false]);
    expect(host.textContent).toContain('About 1,400 common TCP ports plus common UDP services.');
    expect(runFrom().value).toBe('auto');
    expect(button('Advanced')?.getAttribute('aria-expanded')).toBe('false');
    expect(q('[aria-label="TCP ports"]')).toBeNull();
    expect(host.textContent).not.toContain('Probe industrial');
    // No protocol to pick: services are identified from what answers.
    expect(host.textContent).not.toMatch(/Protocols|Execution mode/);
    expect(panel()).toContain('Enter targets');
    expect(button('Start discovery')?.disabled).toBe(true);
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('sends the chosen depth in the scan-plan shape, never protocols or ports', async () => {
    await ready();
    await pick('Quick');
    await startAndWait();
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]).toEqual({ targets: ['10.0.0.0/24'], scan_depth: 'quick', pace: 'normal', run_from: 'auto' });
  });

  it('Custom opens Advanced; a range means the range, and a bad entry is the server\'s sentence (H8)', async () => {
    await ready();
    await pick('Custom');
    expect(button('Advanced')?.getAttribute('aria-expanded')).toBe('true');
    expect(button('Start discovery')?.disabled).toBe(true); // Custom with no ports
    expect(host.textContent).toContain('Custom needs TCP ports, UDP ports or both');

    await type('TCP ports', 'http');
    expect(q('[role="alert"]')?.textContent).toContain('TCP ports: port spec entry "http": "http" is not a port number');
    expect(button('Start discovery')?.disabled).toBe(true);

    await type('TCP ports', '22, 8000-8100');
    expect(host.textContent).toContain('102 TCP ports');
    await type('UDP ports', '161');
    await startAndWait();
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]).toMatchObject({ scan_depth: 'custom', tcp_ports: '22,8000-8100', udp_ports: '161' });
    expect(creates()[0]).not.toHaveProperty('ports');
  });

  it('a preset shows its ports read-only, from the server\'s plan', async () => {
    await ready();
    await click('Advanced');
    await vi.waitFor(() => expect(q<HTMLInputElement>('[aria-label="TCP ports"]')?.value).toBe('1-1024,1080'));
    expect(q<HTMLInputElement>('[aria-label="TCP ports"]')?.readOnly).toBe(true);
    expect(q<HTMLInputElement>('[aria-label="UDP ports"]')?.value).toBe('53,123');
  });

  it('sends the chosen pace', async () => {
    await ready();
    await click('Advanced');
    expect(choice('Normal').checked).toBe(true);
    expect(host.textContent).toContain('May report slow ports as filtered.');
    expect(host.textContent).toContain('For fragile or closely monitored networks.');
    await pick('Fast');
    await startAndWait();
    await vi.waitFor(() => expect(creates()[0]).toMatchObject({ pace: 'fast' }));
  });
});

describe('OT/ICS probing (owner decision D6)', () => {
  it('is under Advanced, unchecked, with its acknowledgement — and sends nothing until chosen', async () => {
    await ready();
    await click('Advanced');
    const box = choice('Probe industrial (OT/ICS) devices');
    expect(box.checked).toBe(false);
    expect(host.textContent).toContain('documented, read-only');
    expect(host.textContent).toContain('Industrial controllers can be');
    expect(host.textContent).toContain('standard port only');
    await startAndWait();
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]).not.toHaveProperty('ot_probe_protocols');
  });

  it('sends ot_probe_protocols only for the protocols ticked', async () => {
    await ready();
    await click('Advanced');
    await pick('Probe industrial (OT/ICS) devices');
    expect(choice('Modbus').checked).toBe(false);
    expect(button('Start discovery')?.disabled).toBe(true);
    expect(host.textContent).toContain('Choose at least one industrial protocol');
    await pick('Modbus');
    await pick('BACnet');
    await startAndWait();
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]).toMatchObject({ ot_probe_protocols: ['Modbus', 'BACnet'] });
  });

  it('is absent when the tenant\'s switch is off', async () => {
    mocks.ot.on = false;
    await ready();
    await click('Advanced');
    expect(host.textContent).not.toContain('Probe industrial');
    expect(host.textContent).not.toContain('Modbus');
  });
});

describe('Run from', () => {
  it('offers Auto, the platform sensor and each tenant sensor; an offline one is listed but disabled', async () => {
    await ready();
    const opts = [...runFrom().options].map((o) => [o.value, o.textContent, o.disabled]);
    expect(opts).toEqual([
      ['auto', 'Auto — a sensor on those networks, else the platform sensor', false],
      ['platform', 'Platform sensor', false],
      [`sensor:${SENSORS[0].id}`, 'edge-a', false],
      [`sensor:${SENSORS[1].id}`, 'edge-b (offline)', true],
    ]);
  });

  it('maps Platform and a named sensor to run_from — never "cloud" (H37)', async () => {
    await ready();
    await act(async () => setValue(runFrom(), `sensor:${SENSORS[0].id}`));
    await startAndWait();
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]).toMatchObject({ run_from: 'sensor', sensor_id: SENSORS[0].id });
    expect(creates()[0]).not.toHaveProperty('execution_mode');
  });

  it('Platform sensor is run_from platform', async () => {
    await ready();
    await act(async () => setValue(runFrom(), 'platform'));
    await startAndWait();
    await vi.waitFor(() => expect(creates()[0]).toMatchObject({ run_from: 'platform' }));
    expect(JSON.stringify(creates()[0])).not.toContain('cloud');
  });

  it('while the sensors load, the control and Start wait — no silent "platform"', async () => {
    mocks.sensors.mockReturnValue(new Promise(() => {}));
    await render();
    await type('Targets', '10.0.0.5');
    expect(runFrom().disabled).toBe(true);
    expect(host.textContent).toContain('Loading your sensors');
    expect(button('Start discovery')?.disabled).toBe(true);
  });

  it('a failed sensor list says so and runs from the platform', async () => {
    mocks.sensors.mockResolvedValue(failed(500, { error: 'boom' }));
    await ready('10.0.0.5');
    expect(host.textContent).toContain('The sensor list could not be loaded, so this scan runs from the platform sensor');
    expect([...runFrom().options].map((o) => o.value)).toEqual(['platform']);
  });

  it('no tenant sensors says so and runs from the platform', async () => {
    mocks.sensors.mockResolvedValue(ok({ sensors: [SENSORS[2]] }));
    await ready('10.0.0.5');
    expect(host.textContent).toContain('You have no sensors registered');
    await startAndWait();
    await vi.waitFor(() => expect(creates()[0]).toMatchObject({ run_from: 'platform' }));
  });
});

describe('preview', () => {
  it('waits for the form to sit still: one dry run for a burst of typing', async () => {
    await render();
    await vi.waitFor(() => expect(runFrom().disabled).toBe(false));
    await type('Targets', '10');
    await type('Targets', '10.0.0.1');
    await type('Targets', '10.0.0.0/24');
    await sleep(300);
    expect(mocks.preview).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(mocks.preview).toHaveBeenCalledTimes(1), { timeout: 2000 });
    await sleep(700);
    expect(previews()).toEqual([{ targets: ['10.0.0.0/24'], scan_depth: 'standard', pace: 'normal', run_from: 'auto', dry_run: true }]);
  });

  it('cancels a preview the form has moved past', async () => {
    let firstSignal: AbortSignal | undefined;
    mocks.preview.mockImplementationOnce((opts: { signal?: AbortSignal }) => { firstSignal = opts.signal; return new Promise(() => {}); });
    await ready('10.0.0.5');
    await vi.waitFor(() => expect(mocks.preview).toHaveBeenCalledTimes(1), { timeout: 2000 });
    expect(firstSignal?.aborted).toBe(false);
    await type('Targets', '10.0.0.6');
    await vi.waitFor(() => expect(mocks.preview).toHaveBeenCalledTimes(2), { timeout: 2000 });
    expect(firstSignal?.aborted).toBe(true);
    await vi.waitFor(() => expect(panel()).toContain('edge-a'));
  });

  it('shows size, a duration range with the server\'s basis, and where it runs and why', async () => {
    await ready();
    expect(panel()).toMatch(/Estimating…|Enter targets/);
    await vi.waitFor(() => expect(panel()).toContain('About 2 minutes to 1 hour'), { timeout: 2000 });
    expect(panel()).toContain('254 addresses · up to 1,364 TCP ports and 11 UDP services each · 349,250 probes');
    expect(panel()).toContain('liveness checks usually remove many addresses');
    expect(panel()).toContain('Runs from edge-a — every target is on networks it reports');
  });

  it('names the targets the server will scan at less depth, and how to change that', async () => {
    mocks.preview.mockResolvedValue(previewOf({}, {
      depth: 'thorough',
      targets: [{ target: '93.184.216.34', class: 'external', depth: 'standard', addresses: 1, tcp_ports: '', udp_ports: '', tcp_port_count: 1364, udp_port_count: 11, estimated_probes: 1375 }],
      depth_adjustments: [{ target: '93.184.216.34', requested: 'thorough', applied: 'standard', reason: 'outside your registered networks' }],
    }));
    await ready('93.184.216.34');
    await pick('Thorough');
    await vi.waitFor(() => expect(panel()).toContain('1 target is outside your registered networks, so it will be scanned at Standard depth.'), { timeout: 2000 });
    expect(panel()).toContain('93.184.216.34');
    expect(panel()).toContain('Network Segments');
  });

  it('when targets need confirming, Start asks first — and only "Scan anyway" confirms', async () => {
    const external = [{ target: '93.184.216.34', addresses: ['93.184.216.34'] }];
    mocks.preview.mockResolvedValue(previewOf({ confirmation_required: true, external_targets: external }));
    await ready('93.184.216.34');
    await vi.waitFor(() => expect(panel()).toContain('You will be asked to confirm when you start'), { timeout: 2000 });
    await click('Start discovery');
    expect(q('[role="alertdialog"]')?.textContent).toContain('1 target is outside your registered networks. Only scan systems you are authorized to test.');
    expect(mocks.create).not.toHaveBeenCalled();
    await click('Scan anyway');
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]).toMatchObject({ targets: ['93.184.216.34'], external_targets_confirmed: true });
    expect(previews().every((b) => !('external_targets_confirmed' in b))).toBe(true);
  });

  it('a budget refusal is shown in the server\'s words, with the largest target, and Start is withheld', async () => {
    mocks.preview.mockResolvedValue(failed(422, {
      error: 'scan_budget_exceeded',
      details: 'this scan would send about 67,119,104 probes; the limit is 25,000,000',
      estimated_probes: 67_119_104, probe_limit: 25_000_000,
      largest_target: { target: '10.0.0.0/22', addresses: 1024, tcp_port_count: 65535, udp_port_count: 11, estimated_probes: 67_119_104 },
    }));
    await ready('10.0.0.0/22');
    await vi.waitFor(() => expect(q('[role="alert"]')?.textContent).toContain('the limit is 25,000,000'), { timeout: 2000 });
    expect(q('[role="alert"]')?.textContent).toContain('10.0.0.0/22 — 1,024 addresses × 65,546 ports');
    expect(button('Start discovery')?.disabled).toBe(true);
    expect(host.textContent).not.toContain('scan_budget_exceeded');
  });

  it('a target too large to expand is shown with its count', async () => {
    mocks.preview.mockResolvedValue(failed(422, { error: 'scan_target_too_large', details: '"10.0.0.0/16" names 65536 addresses', oversize_targets: [{ target: '10.0.0.0/16', addresses: '65536' }], target_limit: 4096 }));
    await ready('10.0.0.0/16');
    await vi.waitFor(() => expect(q('[role="alert"]')?.textContent).toContain('10.0.0.0/16 — 65536 addresses'), { timeout: 2000 });
    expect(button('Start discovery')?.disabled).toBe(true);
  });

  it('"not available yet" is a calm notice, not an alert, and does not hide Start', async () => {
    mocks.preview.mockResolvedValue(failed(422, { error: 'scan_plan_unavailable', details: 'scan depth is not available yet on this deployment; use protocols and ports' }));
    await ready();
    await vi.waitFor(() => expect(panel()).toContain('not available on this installation'), { timeout: 2000 });
    expect(q('[role="alert"]')).toBeNull();
    expect(panel()).not.toMatch(/scan_plan_unavailable|protocols and ports/);
    expect(button('Start discovery')?.disabled).toBe(false);
  });

  it('a failed preview says it could not estimate — and Start still works', async () => {
    mocks.preview.mockResolvedValue(failed(500, undefined));
    await ready();
    await vi.waitFor(() => expect(panel()).toContain("Couldn't estimate this scan"), { timeout: 2000 });
    await click('Start discovery');
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
  });

  it('a request the server would refuse (an offline sensor) is said in its words, and Start is withheld', async () => {
    mocks.preview.mockResolvedValue(failed(409, { error: 'sensor edge-a is offline: nothing was scanned' }));
    await ready();
    await vi.waitFor(() => expect(q('[role="alert"]')?.textContent).toContain('sensor edge-a is offline'), { timeout: 2000 });
    expect(q('[role="alert"]')?.textContent).toContain("This scan can't start as set up");
    expect(button('Start discovery')?.disabled).toBe(true);
  });

  it('a sensor that cannot run a scan by depth is refused in the server\'s words, with the platform offered (#2194)', async () => {
    const details = "sensor edge-a's software does not support scan depth — upgrade it, or run the scan from the platform; nothing was scanned";
    mocks.preview.mockImplementation((opts: { body: { run_from?: string } }) =>
      Promise.resolve(opts.body.run_from === 'sensor' ? failed(409, { error: 'sensor_scan_plan_unsupported', details }) : previewOf()));
    await ready();
    await act(async () => setValue(runFrom(), `sensor:${SENSORS[0].id}`));
    await vi.waitFor(() => expect(q('[role="alert"]')?.textContent).toContain(details), { timeout: 2000 });
    expect(host.textContent).not.toContain('sensor_scan_plan_unsupported');
    expect(button('Start discovery')?.disabled).toBe(true);
    // Offered, not done behind the person's back: one click moves Run from.
    await click('Run from the platform sensor instead');
    expect(runFrom().value).toBe('platform');
    await vi.waitFor(() => expect(previews()[previews().length - 1]).toMatchObject({ run_from: 'platform' }), { timeout: 2000 });
    await vi.waitFor(() => expect(button('Start discovery')?.disabled).toBe(false), { timeout: 2000 });
  });

  it('the same refusal on Start is shown in the server\'s words too', async () => {
    const details = "sensor edge-a's software does not support scan depth — upgrade it, or run the scan from the platform; nothing was scanned";
    mocks.preview.mockReturnValue(new Promise(() => {}));
    mocks.create.mockResolvedValueOnce(failed(409, { error: 'sensor_scan_plan_unsupported', details }));
    await ready();
    await act(async () => setValue(runFrom(), `sensor:${SENSORS[0].id}`));
    await click('Start discovery');
    await vi.waitFor(() => expect(q('[role="alert"]')?.textContent).toContain(details));
    expect(button('Run from the platform sensor instead')).toBeDefined();
    expect(host.textContent).not.toContain('Started');
  });

  it('the tenant\'s rate limit is "couldn\'t estimate", not a refusal', async () => {
    mocks.preview.mockResolvedValue(failed(429, { error: 'rate limit exceeded' }));
    await ready();
    await vi.waitFor(() => expect(panel()).toContain("Couldn't estimate this scan"), { timeout: 2000 });
    expect(button('Start discovery')?.disabled).toBe(false);
  });

  it('a slow preview does not hold Start', async () => {
    mocks.preview.mockReturnValue(new Promise(() => {}));
    await ready();
    await vi.waitFor(() => expect(mocks.preview).toHaveBeenCalled(), { timeout: 2000 });
    expect(panel()).toContain('Estimating…');
    await click('Start discovery');
    await vi.waitFor(() => expect(creates()).toHaveLength(1));
  });

  it('zero addresses says there is nothing to scan', async () => {
    mocks.preview.mockResolvedValue(ok({ plan: plan(), estimate: { probes: 0, addresses: 0, seconds_best: 0, seconds_worst: 0, basis: '' }, confirmation_required: false, external_targets: [] }));
    await ready();
    await vi.waitFor(() => expect(panel()).toContain('Nothing to scan'), { timeout: 2000 });
  });
});

describe('start and "started"', () => {
  it('says what started and where, links to Discovery Jobs, and does not poll the job', async () => {
    mocks.create.mockResolvedValue(created({ depth: 'thorough', pace: 'polite' }));
    await ready();
    await startAndWait();
    await vi.waitFor(() => expect(host.textContent).toContain('Started — track it in Discovery Jobs'));
    const status = q('[role="status"]')?.textContent ?? '';
    expect(status).toContain('Thorough');
    expect(status).toContain('Polite');
    expect(status).toContain('edge-a — every target is on networks it reports');
    expect(status).toContain('a1b2c3d4');
    expect(status).toContain('You can close this dialog');
    await sleep(100);
    expect(mocks.get).not.toHaveBeenCalled();
    await click('View in Discovery Jobs');
    expect(mocks.close).toHaveBeenCalled();
    // Straight onto this job's detail ('s ?job= deep link), not the list.
    expect(mocks.navigate).toHaveBeenCalledWith('/discovery/jobs?job=a1b2c3d4-0000-4000-8000-000000000000');
  });

  it('a refused start keeps the form and says why in the footer', async () => {
    mocks.create.mockResolvedValue(failed(409, { error: 'validation_error', details: 'sensor offline: nothing was scanned' }));
    await ready();
    await startAndWait();
    await vi.waitFor(() => expect(q('[data-testid="note"]')?.textContent).toBe('sensor offline: nothing was scanned'));
    expect(q('textarea[aria-label="Targets"]')).not.toBeNull();
  });

  it('remembers depth, pace and run-from for next time — never the OT opt-in', async () => {
    await ready();
    await pick('Thorough');
    await click('Advanced');
    await pick('Polite');
    await pick('Probe industrial (OT/ICS) devices');
    await pick('Modbus');
    await startAndWait();
    await vi.waitFor(() => expect(host.textContent).toContain('Started'));
    await render(false);
    await render(true);
    await vi.waitFor(() => expect(choice('Thorough').checked).toBe(true));
    await click('Advanced');
    expect(choice('Polite').checked).toBe(true);
    expect(choice('Probe industrial (OT/ICS) devices').checked).toBe(false);
  });
});

describe('closable at any moment', () => {
  it('while configuring', async () => {
    await ready();
    await click('Close dialog');
    expect(mocks.close).toHaveBeenCalledTimes(1);
  });

  it('while a start is in flight — and a late answer does not take over a reopened dialog', async () => {
    let resolve: (v: unknown) => void = () => {};
    mocks.create.mockReturnValueOnce(new Promise((r) => { resolve = r; }));
    await ready();
    await startAndWait();
    await vi.waitFor(() => expect(button('Starting…')?.disabled).toBe(true));
    expect(button('Close dialog')).toBeDefined();
    await click('Close dialog');
    expect(mocks.close).toHaveBeenCalledTimes(1);
    await render(false);
    await render(true);
    await act(async () => { resolve(created()); });
    await sleep(50);
    expect(host.textContent).not.toContain('Started — track it');
    expect(q('textarea[aria-label="Targets"]')).not.toBeNull();
  });

  it('on the confirmation and once started', async () => {
    mocks.create.mockResolvedValueOnce(failed(422, { error: 'external_targets_unconfirmed', details: 'confirm', external_targets: [{ target: '93.184.216.34', addresses: ['93.184.216.34'] }] }));
    await ready('93.184.216.34');
    await click('Start discovery');
    await vi.waitFor(() => expect(q('[role="alertdialog"]')).not.toBeNull());
    expect(button('Close dialog')).toBeDefined();
    await click('Scan anyway');
    await vi.waitFor(() => expect(host.textContent).toContain('Started'));
    await click('Close');
    expect(mocks.close).toHaveBeenCalled();
  });
});
