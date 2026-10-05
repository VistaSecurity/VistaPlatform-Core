// The Discover wizard's pure decisions ( WP4a): the request it sends, what
// it calls a mistake, and how it words the server's plan and estimate.
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_DEPTH,
  DEPTHS,
  REMEMBER_KEY,
  asCreatedJob,
  asPreview,
  buildJobRequest,
  checkForm,
  describeAdjustments,
  describeEstimate,
  describeExecutor,
  describeSeconds,
  describeSize,
  initialForm,
  loadRememberedChoice,
  saveRememberedChoice,
  type DiscoverForm,
  type DiscoveryScanPlan,
} from './discover-plan';

const form = (over: Partial<DiscoverForm> = {}): DiscoverForm => ({ ...initialForm(null), targets: '10.0.0.0/24', ...over });
const req = (f: DiscoverForm, opts: { otAvailable?: boolean; dryRun?: boolean; confirmed?: boolean } = {}) =>
  buildJobRequest(f, checkForm(f, opts.otAvailable ?? true), { otAvailable: opts.otAvailable ?? true, ...opts });

const plan = (over: Partial<DiscoveryScanPlan> = {}): DiscoveryScanPlan => ({
  depth: 'standard', pace: 'normal', tcp_ports: '1-1024', udp_ports: '53,123', tcp_port_count: 1364, udp_port_count: 11,
  run_from_requested: 'auto', executor_resolved: 'platform', executor_reason: 'no sensor serves every target',
  depth_adjustments: [], targets: [], estimated_probes: 0, probe_limit: 25_000_000, ...over,
});

describe('the default form', () => {
  it('is Standard (owner decision D4), Normal pace, Run from Auto, OT off', () => {
    const f = initialForm(null);
    expect(DEFAULT_DEPTH).toBe('standard');
    expect(f).toMatchObject({ depth: 'standard', pace: 'normal', runFrom: 'auto', ot: false, otProtocols: [] });
  });

  it('offers the four depths with a plain description each, and no protocol list', () => {
    expect(DEPTHS.map((d) => d.value)).toEqual(['quick', 'standard', 'thorough', 'custom']);
    for (const d of DEPTHS) expect(d.description).not.toMatch(/\b(TLS|SSH|SMB|Modbus)\b/);
  });
});

describe('buildJobRequest', () => {
  it('sends the scan-plan shape and never the legacy protocols/ports', () => {
    expect(req(form())).toEqual({ targets: ['10.0.0.0/24'], scan_depth: 'standard', pace: 'normal', run_from: 'auto' });
    const b = req(form({ depth: 'quick' }));
    expect(b.scan_depth).toBe('quick');
    expect(b).not.toHaveProperty('protocols');
    expect(b).not.toHaveProperty('ports');
  });

  it('Custom sends both port fields in the platform spelling; a preset sends neither', () => {
    expect(req(form({ depth: 'custom', tcpPorts: ' 8000-8100, 22', udpPorts: '161' }))).toMatchObject({ tcp_ports: '22,8000-8100', udp_ports: '161' });
    expect(req(form({ depth: 'custom', tcpPorts: '443' }))).not.toHaveProperty('udp_ports');
    const preset = req(form({ depth: 'thorough', tcpPorts: '443', udpPorts: '53' }));
    expect(preset).not.toHaveProperty('tcp_ports');
    expect(preset).not.toHaveProperty('udp_ports');
  });

  it('sends ot_probe_protocols only when the box is ticked AND the switch is on', () => {
    expect(req(form())).not.toHaveProperty('ot_probe_protocols');
    expect(req(form({ otProtocols: ['Modbus'] }))).not.toHaveProperty('ot_probe_protocols');
    expect(req(form({ ot: true, otProtocols: ['BACnet', 'Modbus'] }))).toMatchObject({ ot_probe_protocols: ['Modbus', 'BACnet'] });
    expect(req(form({ ot: true, otProtocols: ['Modbus'] }), { otAvailable: false })).not.toHaveProperty('ot_probe_protocols');
  });

  it('a dry run is marked and never carries the external confirmation', () => {
    expect(req(form(), { dryRun: true })).toMatchObject({ dry_run: true });
    expect(req(form(), { dryRun: true, confirmed: true })).not.toHaveProperty('external_targets_confirmed');
    expect(req(form())).not.toHaveProperty('external_targets_confirmed');
    expect(req(form(), { confirmed: true })).toMatchObject({ external_targets_confirmed: true });
  });
});

describe('checkForm', () => {
  const problems = (f: DiscoverForm, ot = true) => checkForm(f, ot).problems.map((p) => p.field);
  it('needs a target, and at most 1000', () => {
    expect(problems(form({ targets: ' , \n' }))).toEqual(['targets']);
    expect(problems(form({ targets: Array.from({ length: 1001 }, (_, i) => `10.0.${i >> 8}.${i & 255}`).join('\n') }))).toEqual(['targets']);
    expect(problems(form())).toEqual([]);
  });

  it('Custom needs ports, and each field is parsed as the platform parses it', () => {
    expect(problems(form({ depth: 'custom' }))).toEqual(['ports']);
    expect(problems(form({ depth: 'custom', tcpPorts: '8000-8100' }))).toEqual([]);
    const bad = checkForm(form({ depth: 'custom', tcpPorts: 'http', udpPorts: '0' }), true).problems;
    expect(bad).toEqual([
      { field: 'tcp', message: 'port spec entry "http": "http" is not a port number' },
      { field: 'udp', message: 'port spec entry "0": port 0 is out of range 1-65535' },
    ]);
  });

  it('a ticked OT box needs a protocol — unless the switch is off, when there is no box', () => {
    expect(problems(form({ ot: true }))).toEqual(['ot']);
    expect(problems(form({ ot: true }), false)).toEqual([]);
  });
});

describe('the server answer', () => {
  it('tells a preview from a created job', () => {
    const preview = { plan: plan(), estimate: { probes: 1, addresses: 1, seconds_best: 0, seconds_worst: 0, basis: '' }, confirmation_required: false, external_targets: [] };
    expect(asPreview(preview)).toBe(preview);
    expect(asCreatedJob(preview)).toBeNull();
    const created = { job: { id: 'j1', status: 'queued' } };
    expect(asPreview(created)).toBeNull();
    expect(asCreatedJob(created)).toEqual({ id: 'j1', status: 'queued' });
  });
});

describe('estimate wording', () => {
  it('is a range, never one false-precision number', () => {
    expect(describeEstimate({ probes: 1, addresses: 254, seconds_best: 95, seconds_worst: 3500, basis: 'b' }).duration).toBe('About 2 minutes to 1 hour');
    expect(describeEstimate({ probes: 1, addresses: 1, seconds_best: 2, seconds_worst: 40, basis: 'b' }).duration).toBe('Under a minute');
    expect(describeEstimate({ probes: 1, addresses: 1, seconds_best: 0, seconds_worst: 0, basis: 'b' }).duration).toMatch(/^Not timed/);
    expect(describeEstimate({ probes: 1, addresses: 1, seconds_best: 1, seconds_worst: 2, basis: 'the basis' }).basis).toBe('the basis');
  });

  it('rounds to what a person can plan around', () => {
    expect(describeSeconds(59)).toBe('under a minute');
    expect(describeSeconds(61)).toBe('about 2 minutes');
    expect(describeSeconds(7200)).toBe('about 2 hours');
    expect(describeSeconds(3 * 86400)).toBe('about 3 days');
  });

  it('states the size: addresses, ports per address, probes', () => {
    expect(describeSize(plan(), { probes: 349_250, addresses: 254, seconds_best: 1, seconds_worst: 2, basis: '' }))
      .toBe('254 addresses · up to 1,364 TCP ports and 11 UDP services each · 349,250 probes');
  });

  it('says where it runs and the server\'s reason', () => {
    expect(describeExecutor(plan())).toEqual({ where: 'Runs from the platform sensor', why: 'no sensor serves every target' });
    expect(describeExecutor(plan({ executor_resolved: 'sensor', sensor_name: 'edge-a', executor_reason: 'it reports every target' })).where).toBe('Runs from edge-a');
  });
});

describe('depth adjustments', () => {
  const target = (t: string, cls: 'private' | 'external') => ({ target: t, class: cls, depth: 'standard' as const, addresses: 1, tcp_ports: '', udp_ports: '', tcp_port_count: 0, udp_port_count: 0, estimated_probes: 0 });
  it('none → nothing to say', () => {
    expect(describeAdjustments(plan())).toBeNull();
  });
  it('external downgrades are said in the owner\'s words, with the register hint', () => {
    const p = plan({
      depth: 'thorough',
      targets: [target('93.184.216.34', 'external'), target('198.51.100.7', 'external'), target('10.0.0.0/24', 'private')],
      depth_adjustments: [
        { target: '93.184.216.34', requested: 'thorough', applied: 'standard', reason: 'outside your registered networks' },
        { target: '198.51.100.7', requested: 'thorough', applied: 'standard', reason: 'outside your registered networks' },
      ],
    });
    const d = describeAdjustments(p)!;
    expect(d.headline).toBe('2 targets are outside your registered networks, so they will be scanned at Standard depth.');
    expect(d.targets.map((t) => t.target)).toEqual(['93.184.216.34', '198.51.100.7']);
    expect(d.registerHint).toBe(true);
  });
});

describe('remembered choices', () => {
  const store = () => {
    const m = new Map<string, string>();
    return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), m };
  };
  it('remembers depth, pace and run-from — never Custom, ports or the OT opt-in', () => {
    const s = store();
    saveRememberedChoice(s, form({ depth: 'thorough', pace: 'polite', runFrom: 'platform', ot: true, otProtocols: ['Modbus'], tcpPorts: '1' }));
    expect(loadRememberedChoice(s)).toEqual({ depth: 'thorough', pace: 'polite', runFrom: 'platform' });
    expect(s.m.get(REMEMBER_KEY)).not.toMatch(/ot|Modbus|tcp/i);
    saveRememberedChoice(s, form({ depth: 'custom' }));
    expect(loadRememberedChoice(s)?.depth).toBeUndefined();
    expect(initialForm(loadRememberedChoice(s))).toMatchObject({ depth: 'standard', ot: false });
  });
  it('a broken or blocked store forgets quietly', () => {
    expect(loadRememberedChoice({ getItem: () => '{nope' })).toBeNull();
    expect(loadRememberedChoice({ getItem: () => { throw new Error('blocked'); } })).toBeNull();
    expect(loadRememberedChoice({ getItem: () => JSON.stringify({ depth: 'everything', runFrom: 'cloud' }) })).toEqual({});
    expect(() => saveRememberedChoice({ setItem: () => { throw new Error('quota'); } }, form())).not.toThrow();
  });
});
