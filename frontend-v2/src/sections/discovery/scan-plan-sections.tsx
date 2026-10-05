// The scan-plan sections of the Discovery Jobs detail ( WP4b): what was
// scanned and how, what answered, and what was found — grouped by host. The
// wording lives in scan-plan-view.ts (table-tested); this file lays it out and
// owns each section's loading / empty / error / partial state.
import { useId, useState } from 'react';
import { Icon, MiniBar } from '../../components/ui';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { FindingDetail } from './finding-detail';
import { useDiscoveryJobHosts } from './queries';
import { DANGER, MUTED, WARN, type ScanJob } from './scan-job-state';
import {
  coverageHostsLine,
  coveragePortsLine,
  depthAdjustmentGroups,
  depthLabel,
  fmtCount,
  hostOpenCount,
  hostsFinished,
  isQuietHost,
  isTarpitHost,
  livenessLabel,
  nothingAnswered,
  paceLabel,
  partialStop,
  planExecutorLabel,
  portHasDetail,
  portServiceLabel,
  portTransportLabel,
  progressPercent,
  quietHostLine,
  remainingWarnings,
  runFromLabel,
  tarpitSummary,
  targetClassLabel,
  zeroResponderGuidance,
  type JobCoverage,
  type ScanHost,
  type ScanHostPort,
  type ScanPlan,
} from './scan-plan-view';

type DiscoveryFinding = inventoryComponents['schemas']['DiscoveryFinding'];

/** Hosts per page of results. Small enough that a page renders at once; the pager does the rest. */
export const HOSTS_PAGE_SIZE = 25;
const TARGETS_SHOWN = 10;

export function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} style={{ marginTop: 18 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
        <h3 id={id} style={{ margin: 0, fontSize: 11, fontWeight: 700, letterSpacing: 0.4, textTransform: 'uppercase', color: MUTED }}>{title}</h3>
        {right}
      </div>
      {children}
    </section>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 12, padding: '4px 0', fontSize: 12 }}>
      <span style={{ width: 120, flex: 'none', color: MUTED }}>{label}</span>
      <span style={{ color: 'var(--app-t1)', minWidth: 0, wordBreak: 'break-word' }}>{children}</span>
    </div>
  );
}

function Callout({ tone, icon, children, role }: { tone: string; icon: string; children: React.ReactNode; role?: 'alert' | 'status' }) {
  return (
    <div role={role} style={{ display: 'flex', gap: 9, alignItems: 'flex-start', padding: '9px 12px', borderRadius: 10, marginTop: 8, fontSize: 12.5, lineHeight: 1.5, color: 'var(--app-t1)', background: `color-mix(in srgb, ${tone} 10%, transparent)`, border: `1px solid color-mix(in srgb, ${tone} 30%, transparent)` }}>
      <span style={{ color: tone, flex: 'none', marginTop: 1 }}><Icon name={icon} size={14} /></span>
      <div style={{ minWidth: 0 }}>{children}</div>
    </div>
  );
}

function Skeleton({ rows = 3, label }: { rows?: number; label: string }) {
  return (
    <div aria-busy="true" aria-label={label} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} style={{ height: 14, borderRadius: 6, background: 'var(--app-track)', width: `${90 - i * 15}%` }} />
      ))}
    </div>
  );
}

function ErrorRetry({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div role="alert" style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: DANGER }}>
      <span style={{ flex: 1 }}>{message}</span>
      <button className="ui-btn sm" onClick={onRetry}>Retry</button>
    </div>
  );
}

// ─── 1. What was scanned, and how ───────────────────────────────────────────

export function PlanSummarySection({ job, plan, live }: { job: ScanJob; plan: ScanPlan; live: boolean }) {
  const groups = depthAdjustmentGroups(plan.depth_adjustments);
  const targets = plan.targets ?? [];
  const c = job.coverage;
  const pct = progressPercent(job.progress);
  return (
    <Section title="What this scan does">
      {live && (
        <div
          role="progressbar"
          aria-label="Scan progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
          style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}
        >
          <MiniBar pct={pct} h={6} />
          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', flex: 'none' }}>
            {pct}%{c && c.hosts_total > 0 ? ` · ${fmtCount(hostsFinished(c))} of ${fmtCount(c.hosts_total)} hosts` : ''}
          </span>
        </div>
      )}
      <Fact label="Depth">
        {depthLabel(plan.depth)} · {paceLabel(plan.pace)} pace
      </Fact>
      <Fact label="Ports">
        {fmtCount(plan.tcp_port_count)} TCP{plan.tcp_ports ? <span className="mono" style={{ color: MUTED }}> ({plan.tcp_ports})</span> : null}
        {plan.udp_port_count > 0 ? <> · {fmtCount(plan.udp_port_count)} UDP services</> : null}
      </Fact>
      <Fact label="Ran from">
        {planExecutorLabel(plan)}
        <span style={{ color: MUTED }}> — you chose {runFromLabel(plan.run_from_requested)}{plan.executor_reason ? `; ${plan.executor_reason}` : ''}</span>
      </Fact>
      <Fact label="Targets">
        <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {targets.slice(0, TARGETS_SHOWN).map((t) => (
            <span key={t.target}>
              <span className="mono">{t.target}</span>
              <span style={{ color: MUTED }}> · {fmtCount(t.addresses)} {t.addresses === 1 ? 'address' : 'addresses'} · {targetClassLabel(t.class)} · {depthLabel(t.depth)}</span>
            </span>
          ))}
          {targets.length > TARGETS_SHOWN && <span style={{ color: MUTED }}>and {fmtCount(targets.length - TARGETS_SHOWN)} more</span>}
        </span>
      </Fact>
      {groups.map((g) => (
        <Callout key={g.text} tone={WARN} icon="info">
          <div>{g.text}</div>
          <div className="mono" style={{ fontSize: 11, color: MUTED, marginTop: 2 }}>{g.targets.join(', ')}</div>
        </Callout>
      ))}
    </Section>
  );
}

// ─── 2. What answered ───────────────────────────────────────────────────────

export function CoverageSection({ job, plan, loading, error, onRetry }: {
  job: ScanJob;
  plan: ScanPlan;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
}) {
  const c = job.coverage;
  if (!c) {
    let body: React.ReactNode;
    if (error) body = <ErrorRetry message="Could not load this scan's coverage." onRetry={onRetry} />;
    else if (loading) body = <Skeleton label="Loading coverage" rows={2} />;
    else if (plan.executor_resolved === 'sensor') body = <div style={{ fontSize: 12, color: MUTED }}>Coverage by host is reported for scans run by the Platform sensor; this one runs on {planExecutorLabel(plan)}. Its findings are below.</div>;
    else body = <div style={{ fontSize: 12, color: MUTED }}>Coverage appears once the scan starts on its hosts.</div>;
    return <Section title="Coverage">{body}</Section>;
  }

  const zero = nothingAnswered(c);
  const partial = partialStop(job, c);
  const warnings = remainingWarnings(c, { zeroResponder: zero, partial: !!partial });
  return (
    <Section title="Coverage">
      <div style={{ fontSize: 13, color: 'var(--app-t1)' }}>{coverageHostsLine(c)}</div>
      <div style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 3 }}>Ports: {coveragePortsLine(c)}</div>
      {(c.tarpit_hosts > 0 || c.udp_answered > 0 || c.ot_suspect_hosts > 0) && (
        <div style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 3 }}>
          {[
            c.udp_answered > 0 ? `UDP services answered: ${fmtCount(c.udp_answered)}` : '',
            c.tarpit_hosts > 0 ? `Hosts answering on every port: ${fmtCount(c.tarpit_hosts)}` : '',
            c.ot_suspect_hosts > 0 ? `Industrial (OT/ICS) hosts scanned gently: ${fmtCount(c.ot_suspect_hosts)}` : '',
          ].filter(Boolean).join(' · ')}
        </div>
      )}
      <div style={{ fontSize: 11, color: MUTED, marginTop: 4 }}>
        "No answer" means nothing came back — an address with nothing on it and a firewall that drops everything look the same.
      </div>
      {zero && (
        <Callout tone={WARN} icon="alert-triangle" role="status">
          <div style={{ fontWeight: 600 }}>{zeroResponderGuidance(plan)}</div>
          <div style={{ fontSize: 11.5, color: MUTED, marginTop: 3 }}>
            Ran from {planExecutorLabel(plan)} (you chose {runFromLabel(plan.run_from_requested)}){plan.executor_reason ? ` — ${plan.executor_reason}` : ''}.
          </div>
        </Callout>
      )}
      {partial && (
        <Callout tone={WARN} icon="circle-alert" role="status">{partial}</Callout>
      )}
      {warnings.length > 0 && (
        <ul aria-label="Scan warnings" style={{ listStyle: 'none', margin: '8px 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {warnings.map((w) => (
            <li key={w}>
              <Callout tone={WARN} icon="alert-triangle">{w}</Callout>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

// ─── 3. Who answered and what was open, by host ─────────────────────────────

function PortRow({ port }: { port: ScanHostPort }) {
  const [open, setOpen] = useState(false);
  const detailId = useId();
  const hasDetail = portHasDetail(port);
  const d = port.data ?? {};
  const finding = { protocol: port.protocol, protocol_version: typeof d.version === 'string' ? d.version : null, port: port.port, data: d } as DiscoveryFinding;
  return (
    <>
      <tr>
        <td className="mono" style={{ padding: '4px 8px 4px 0' }}>{port.port}</td>
        <td className="mono" style={{ padding: '4px 8px', color: MUTED }}>{portTransportLabel(port)}</td>
        <td style={{ padding: '4px 8px', color: port.identified ? 'var(--app-t1)' : 'var(--app-t2)' }}>{portServiceLabel(port)}</td>
        <td style={{ padding: '4px 0', textAlign: 'right' }}>
          {hasDetail && (
            <button className="ui-btn sm ghost" aria-expanded={open} aria-controls={detailId} onClick={() => setOpen((v) => !v)}>
              {open ? 'Hide detail' : 'Detail'}
            </button>
          )}
        </td>
      </tr>
      {hasDetail && open && (
        <tr id={detailId}>
          <td colSpan={4}>
            <FindingDetail f={finding} />
          </td>
        </tr>
      )}
    </>
  );
}

function HostRow({ host }: { host: ScanHost }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const name = host.hostname ? `${host.address} (${host.hostname})` : host.address;

  if (isTarpitHost(host)) {
    const t = tarpitSummary(host);
    return (
      <li style={{ padding: '8px 0', borderTop: '1px solid var(--app-border)', fontSize: 12 }} data-testid="tarpit-host">
        <span className="mono" style={{ color: 'var(--app-t1)' }}>{name}</span>
        <span style={{ color: 'var(--app-t2)' }}> — {t.line}</span>
        {t.ports.length > 0 && <span className="mono" style={{ color: MUTED }}>: {t.ports.join(', ')}</span>}
      </li>
    );
  }

  // Answered, nothing open: one secondary line, nothing to expand.
  if (isQuietHost(host)) {
    return (
      <li style={{ padding: '6px 0 6px 23px', borderTop: '1px solid var(--app-border)', fontSize: 11.5, color: MUTED }} data-testid="quiet-host">
        <span className="mono">{name}</span> — {quietHostLine(host)}
      </li>
    );
  }

  const n = hostOpenCount(host);
  const liveness = livenessLabel(host.unit?.liveness_state);
  return (
    <li style={{ borderTop: '1px solid var(--app-border)' }}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: '8px 0', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left', color: 'inherit', font: 'inherit' }}
      >
        <Icon name={open ? 'chevron-down' : 'chevron-right'} size={13} />
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</span>
        <span style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{`${fmtCount(n)} open ${n === 1 ? 'port' : 'ports'}`}</span>
        {liveness && <span style={{ fontSize: 11, color: MUTED, width: 150, textAlign: 'right' }}>{liveness}</span>}
      </button>
      {open && (
        <div id={panelId} style={{ padding: '0 0 10px 23px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <caption style={{ position: 'absolute', left: -9999 }}>Open ports on {host.address}</caption>
            <thead>
              <tr style={{ color: MUTED, fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.3, textAlign: 'left' }}>
                <th style={{ padding: '2px 8px 2px 0', fontWeight: 600 }}>Port</th>
                <th style={{ padding: '2px 8px', fontWeight: 600 }}>Transport</th>
                <th style={{ padding: '2px 8px', fontWeight: 600 }}>Service</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {host.ports.map((p) => <PortRow key={p.finding_id} port={p} />)}
            </tbody>
          </table>
        </div>
      )}
    </li>
  );
}

export function HostResultsSection({ jobId, live, coverage }: { jobId: string; live: boolean; coverage?: JobCoverage | null }) {
  const [page, setPage] = useState(1);
  const q = useDiscoveryJobHosts(jobId, page, HOSTS_PAGE_SIZE, { live });
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / HOSTS_PAGE_SIZE));
  const hosts = q.data?.hosts ?? [];

  let body: React.ReactNode;
  if (!q.data && q.isError) {
    body = <ErrorRetry message="Could not load this scan's results." onRetry={() => void q.refetch()} />;
  } else if (!q.data) {
    body = <Skeleton label="Loading results" rows={4} />;
  } else if (total === 0) {
    // Every host that answered is listed — with open ports or without — so
    // an empty list after the scan means no host answered, when the coverage
    // says so; without coverage only "no listening ports" is known.
    const text = live
      ? 'No host has answered yet — hosts appear here as the scan finishes them.'
      : coverage && coverage.hosts_responded === 0
        ? 'No host answered.'
        : coverage
          ? 'No listening ports were found on the hosts that answered.'
          : 'No listening ports were found.';
    body = <div style={{ fontSize: 12, color: MUTED }}>{text}</div>;
  } else {
    const first = (page - 1) * HOSTS_PAGE_SIZE + 1;
    const last = Math.min(total, first + hosts.length - 1);
    body = (
      <>
        {q.isError && <ErrorRetry message="Could not refresh these results; showing the last ones loaded." onRetry={() => void q.refetch()} />}
        <ul aria-label="Hosts that answered" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {hosts.map((h) => <HostRow key={h.address} host={h} />)}
        </ul>
        <nav aria-label="Results pages" style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8, fontSize: 12, color: MUTED }}>
          <span style={{ flex: 1 }}>Hosts {fmtCount(first)}–{fmtCount(last)} of {fmtCount(total)}</span>
          <button className="ui-btn sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
          <button className="ui-btn sm" disabled={page >= pages} onClick={() => setPage((p) => Math.min(pages, p + 1))}>Next</button>
        </nav>
      </>
    );
  }

  return (
    <Section
      title="Results by host"
      right={q.data ? <span style={{ fontSize: 11, color: MUTED }}>{fmtCount(total)} {total === 1 ? 'host' : 'hosts'}{live ? ' so far' : ''}</span> : undefined}
    >
      {body}
    </Section>
  );
}
