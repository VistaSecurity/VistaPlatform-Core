// The Discover wizard's decisions ( WP4a), out of the component so each
// is testable without a DOM: what the choices are and how they are worded,
// what the person has filled in wrongly, the request the dialog sends, and how
// the server's plan and estimate are told back to them.
//
// The request is built as the generated CreateDiscoveryJobRequest, so a
// contract change to POST /discovery/jobs breaks `tsc` here rather than
// silently sending a field the server no longer reads.
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { parsePortSpec, type PortSpecResult } from './discover-port-spec';
import { AUTO, PLATFORM, choiceFromValue } from './active-scan-run-from';

type Schemas = inventoryComponents['schemas'];
export type CreateDiscoveryJobRequest = Schemas['CreateDiscoveryJobRequest'];
export type DiscoveryJobPreview = Schemas['DiscoveryJobPreview'];
export type DiscoveryScanPlan = Schemas['DiscoveryScanPlan'];
export type DiscoveryScanEstimate = Schemas['DiscoveryScanEstimate'];
export type DiscoveryJob = Schemas['DiscoveryJob'];
export type ScanDepth = NonNullable<CreateDiscoveryJobRequest['scan_depth']>;
export type ScanPace = NonNullable<CreateDiscoveryJobRequest['pace']>;

// ─── The choices ──────────────────────────────────────────────────────────────

/** Scan depth: what each one looks at, in plain words. No protocol is picked —
 *  services are identified from what answers. */
export const DEPTHS: { value: ScanDepth; label: string; description: string }[] = [
  { value: 'quick', label: 'Quick', description: 'Crypto and infrastructure ports only. The fastest look.' },
  { value: 'standard', label: 'Standard', description: 'About 1,400 common TCP ports plus common UDP services.' },
  { value: 'thorough', label: 'Thorough', description: 'All 65,535 TCP ports plus common UDP services — can take a long time.' },
  { value: 'custom', label: 'Custom', description: 'You choose the TCP and UDP ports, under Advanced.' },
];
/** Owner decision D4. */
export const DEFAULT_DEPTH: ScanDepth = 'standard';

export const PACES: { value: ScanPace; label: string; hint: string }[] = [
  { value: 'polite', label: 'Polite', hint: 'Fewer connections at once, longer waits. For fragile or closely monitored networks.' },
  { value: 'normal', label: 'Normal', hint: 'The usual balance of speed and care.' },
  { value: 'fast', label: 'Fast', hint: 'For a well-provisioned LAN. May report slow ports as filtered.' },
];
export const DEFAULT_PACE: ScanPace = 'normal';

/** The OT/ICS opt-in (owner decision D6): in no preset, never pre-chosen. The
 *  values are the server's canonical `ot_probe_protocols` names. */
export const OT_PROTOCOLS: { value: string; label: string }[] = [
  { value: 'Modbus', label: 'Modbus' },
  { value: 'OPC_UA', label: 'OPC UA' },
  { value: 'EtherNet_IP', label: 'EtherNet/IP' },
  { value: 'BACnet', label: 'BACnet' },
];

export const depthLabel = (d: string | undefined) => DEPTHS.find((x) => x.value === d)?.label ?? d ?? '';
export const paceLabel = (p: string | undefined) => PACES.find((x) => x.value === p)?.label ?? p ?? '';

// ─── The form ─────────────────────────────────────────────────────────────────

export const MAX_TARGETS = 1000;

export interface DiscoverForm {
  targets: string;
  depth: ScanDepth;
  tcpPorts: string;
  udpPorts: string;
  pace: ScanPace;
  /** The "Run from" select's value: `auto`, `platform` or `sensor:<id>`. */
  runFrom: string;
  /** The "Probe industrial (OT/ICS) devices" box. */
  ot: boolean;
  otProtocols: string[];
}

export function initialForm(remembered?: RememberedChoice | null): DiscoverForm {
  return {
    targets: '',
    depth: remembered?.depth ?? DEFAULT_DEPTH,
    tcpPorts: '',
    udpPorts: '',
    pace: remembered?.pace ?? DEFAULT_PACE,
    runFrom: remembered?.runFrom ?? AUTO,
    ot: false,
    otProtocols: [],
  };
}

export function parseTargets(text: string): string[] {
  return text.split(/[\n,]/).map((t) => t.trim()).filter(Boolean);
}

export type FieldProblem = { field: 'targets' | 'ports' | 'tcp' | 'udp' | 'ot'; message: string };

export interface FormCheck {
  targets: string[];
  /** Parsed Custom ports; undefined when the field is empty or the depth is not Custom. */
  tcp?: PortSpecResult;
  udp?: PortSpecResult;
  /** Empty means the form can be previewed and started. */
  problems: FieldProblem[];
}

/**
 * What is wrong with the form, field by field. `otAvailable` is the tenant's
 * `ot_active_probing` switch: when it is off the OT box is not shown and
 * nothing about it can be wrong.
 */
export function checkForm(form: DiscoverForm, otAvailable: boolean): FormCheck {
  const targets = parseTargets(form.targets);
  const problems: FieldProblem[] = [];
  if (targets.length === 0) problems.push({ field: 'targets', message: 'Enter at least one target.' });
  if (targets.length > MAX_TARGETS) problems.push({ field: 'targets', message: `${targets.length} targets — one scan takes at most ${MAX_TARGETS}.` });
  const out: FormCheck = { targets, problems };
  if (form.depth === 'custom') {
    const hasTCP = form.tcpPorts.trim() !== '';
    const hasUDP = form.udpPorts.trim() !== '';
    if (!hasTCP && !hasUDP) problems.push({ field: 'ports', message: 'Custom needs TCP ports, UDP ports or both — e.g. 22,443,8000-8100.' });
    if (hasTCP) {
      out.tcp = parsePortSpec(form.tcpPorts);
      if (!out.tcp.ok) problems.push({ field: 'tcp', message: out.tcp.error });
    }
    if (hasUDP) {
      out.udp = parsePortSpec(form.udpPorts);
      if (!out.udp.ok) problems.push({ field: 'udp', message: out.udp.error });
    }
  }
  if (otAvailable && form.ot && form.otProtocols.length === 0) {
    problems.push({ field: 'ot', message: 'Choose at least one industrial protocol, or untick the box.' });
  }
  return out;
}

/**
 * The POST /discovery/jobs body for this form. Only a valid form (no
 * problems) is ever sent. `confirmed` is the person's "Scan anyway" to targets
 * outside the registered networks and is sent ONLY from that button; a dry run
 * never carries it, so the preview shows what would need confirming.
 */
export function buildJobRequest(
  form: DiscoverForm,
  check: FormCheck,
  opts: { otAvailable: boolean; dryRun?: boolean; confirmed?: boolean },
): CreateDiscoveryJobRequest {
  const choice = choiceFromValue(form.runFrom);
  const body: CreateDiscoveryJobRequest = {
    targets: check.targets,
    scan_depth: form.depth,
    pace: form.pace,
    run_from: choice.run_from,
  };
  if (choice.sensor_id) body.sensor_id = choice.sensor_id;
  if (form.depth === 'custom') {
    if (check.tcp?.ok) body.tcp_ports = check.tcp.canonical;
    if (check.udp?.ok) body.udp_ports = check.udp.canonical;
  }
  // The OT opt-in rides only on the box AND the tenant's switch: never from a
  // depth, never left behind by a box the switch has since hidden.
  if (opts.otAvailable && form.ot && form.otProtocols.length > 0) {
    body.ot_probe_protocols = OT_PROTOCOLS.map((p) => p.value).filter((v) => form.otProtocols.includes(v));
  }
  if (opts.dryRun) body.dry_run = true;
  else if (opts.confirmed) body.external_targets_confirmed = true;
  return body;
}

// ─── The answer ───────────────────────────────────────────────────────────────

type CreateJobAnswer = DiscoveryJobPreview | Schemas['DiscoveryJobResponse'];

/** POST /discovery/jobs answers 200 with a preview only for a dry run. */
export function asPreview(data: CreateJobAnswer): DiscoveryJobPreview | null {
  return 'estimate' in data && 'confirmation_required' in data ? (data as DiscoveryJobPreview) : null;
}

/** …and 202 with `{ job }` for a real create. */
export function asCreatedJob(data: CreateJobAnswer): DiscoveryJob | null {
  const job = (data as { job?: unknown }).job;
  return job && typeof job === 'object' && typeof (job as DiscoveryJob).id === 'string' ? (job as DiscoveryJob) : null;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;

/** A duration in words, rounded to what a person can plan around. */
export function describeSeconds(s: number): string {
  if (s < 60) return 'under a minute';
  const minutes = Math.ceil(s / 60);
  // "about 59 minutes" is false precision for what is a rough bound.
  if (minutes < 50) return `about ${plural(minutes, 'minute')}`;
  const hours = Math.round(s / 3600);
  if (hours < 48) return `about ${plural(Math.max(1, hours), 'hour')}`;
  return `about ${plural(Math.round(s / 86400), 'day')}`;
}

/**
 * The estimate as a RANGE, never one number: the server's best case (every
 * address answers at once) to its worst (every address is up and drops every
 * probe). `basis` is the server's own sentence for what that assumes.
 */
export function describeEstimate(e: DiscoveryScanEstimate): { duration: string; basis: string } {
  let duration: string;
  if (e.seconds_best === 0 && e.seconds_worst === 0) {
    duration = 'Not timed: this scan has no TCP ports, and UDP probes are paced separately.';
  } else {
    const best = describeSeconds(e.seconds_best);
    const worst = describeSeconds(e.seconds_worst);
    duration = best === worst ? `${best[0].toUpperCase()}${best.slice(1)}` : `${best[0].toUpperCase()}${best.slice(1)} to ${worst.replace(/^about /, '')}`;
  }
  return { duration, basis: e.basis };
}

/** "254 addresses · 1,364 TCP ports and 11 UDP services each · 349,250 probes". */
export function describeSize(plan: DiscoveryScanPlan, e: DiscoveryScanEstimate): string {
  const ports = [
    plan.tcp_port_count > 0 ? plural(plan.tcp_port_count, 'TCP port') : '',
    plan.udp_port_count > 0 ? plural(plan.udp_port_count, 'UDP service') : '',
  ].filter(Boolean).join(' and ');
  return [plural(e.addresses, 'address', 'addresses'), ports ? `up to ${ports} each` : '', plural(e.probes, 'probe')].filter(Boolean).join(' · ');
}

/** Where the scan will run, and the server's reason — Auto says what it chose. */
export function describeExecutor(plan: Pick<DiscoveryScanPlan, 'executor_resolved' | 'sensor_name' | 'executor_reason'>): { where: string; why: string } {
  const where = plan.executor_resolved === 'sensor' ? `Runs from ${(plan.sensor_name ?? '').trim() || 'a tenant sensor'}` : 'Runs from the platform sensor';
  return { where, why: plan.executor_reason };
}

/**
 * The targets the server will scan at less depth than asked. When every one
 * is outside the registered networks — the only reason the server downgrades
 * today (owner decision D3) — it is said in those words; otherwise the
 * server's per-target reason is all there is to go on.
 */
export function describeAdjustments(plan: DiscoveryScanPlan): { headline: string; targets: { target: string; reason: string }[]; registerHint: boolean } | null {
  const adj = plan.depth_adjustments ?? [];
  if (adj.length === 0) return null;
  const classOf = (t: string) => plan.targets.find((x) => x.target === t)?.class;
  const allExternal = adj.every((a) => classOf(a.target) === 'external');
  const applied = new Set(adj.map((a) => a.applied));
  const n = adj.length;
  const subject = n === 1 ? '1 target is' : `${n} targets are`;
  const headline = allExternal && applied.size === 1
    ? `${subject} outside your registered networks, so ${n === 1 ? 'it' : 'they'} will be scanned at ${depthLabel([...applied][0])} depth${[...applied][0] === 'custom' ? ' with fewer ports' : ''}.`
    : `${n === 1 ? '1 target' : `${n} targets`} will be scanned at less depth than you chose.`;
  return { headline, targets: adj.map((a) => ({ target: a.target, reason: a.reason })), registerHint: allExternal };
}

// ─── Remembered choices ───────────────────────────────────────────────────────
// Spec §1: depth, pace and run-from are per scan, the last choice remembered in
// this browser as a convenience only. Never the ports, never Custom (it means
// nothing without its ports) and NEVER the OT opt-in, which is chosen fresh
// every time.

export const REMEMBER_KEY = 'vista.discover-assets.last-choice';
export interface RememberedChoice { depth?: ScanDepth; pace?: ScanPace; runFrom?: string }

export function loadRememberedChoice(storage: Pick<Storage, 'getItem'> | undefined): RememberedChoice | null {
  try {
    const raw = storage?.getItem(REMEMBER_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as Record<string, unknown>;
    const out: RememberedChoice = {};
    if (DEPTHS.some((d) => d.value === v.depth && d.value !== 'custom')) out.depth = v.depth as ScanDepth;
    if (PACES.some((p) => p.value === v.pace)) out.pace = v.pace as ScanPace;
    if (typeof v.runFrom === 'string' && (v.runFrom === AUTO || v.runFrom === PLATFORM || v.runFrom.startsWith('sensor:'))) out.runFrom = v.runFrom;
    return out;
  } catch {
    return null;
  }
}

export function saveRememberedChoice(storage: Pick<Storage, 'setItem'> | undefined, form: DiscoverForm): void {
  try {
    const v: RememberedChoice = { pace: form.pace, runFrom: form.runFrom };
    if (form.depth !== 'custom') v.depth = form.depth;
    storage?.setItem(REMEMBER_KEY, JSON.stringify(v));
  } catch {
    // A convenience only: a private window or blocked storage just forgets.
  }
}
