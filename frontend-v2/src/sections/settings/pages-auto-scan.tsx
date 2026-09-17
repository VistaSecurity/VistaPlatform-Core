// Settings · Infrastructure · Active Scanning — the tenant-admin controls for
// the one thing the platform does to their network without being asked.
//
// Three jobs, in this order, because that is the order the questions arrive in:
// what is it doing right now, what will it do, and what has it done. The
// summary is not decoration — a capability that acts unasked and reports
// nowhere is indistinguishable from a bug, and discovery jobs have no listing
// page of their own today.
import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, SRow, SInput, SToggle, STable, STableRow, STag, StateNote, relTime, GREEN, AMBER } from './kit';
import type { SettingsNavItem } from './nav';
import { scanJobFromRecent, scanJobState } from '../discovery/scan-job-state';
import {
  type AutoScanDraft, type AutoScanLimits, type AutoScanPolicy, type AutoScanSummary,
  describePolicy, draftFromPolicy, draftToPayload, formatPorts, isDirty, validateDraft,
} from './auto-scan-form';
import { describeNotScanned, notScannedHeadline } from './auto-scan-not-scanned';

interface AutoScanData {
  policy: AutoScanPolicy;
  limits: AutoScanLimits;
  summary: AutoScanSummary;
}

const QUERY_KEY = ['settings', 'auto-scan'];

function useAutoScan() {
  return useQuery({
    queryKey: QUERY_KEY,
    queryFn: async (): Promise<AutoScanData> => {
      const { data, error } = await clients.inventory.GET('/discovery/auto-scan', {});
      if (error || !data) throw new Error('Failed to load the automatic-scanning policy');
      return { policy: data.auto_scan, limits: data.limits, summary: data.summary };
    },
  });
}

export function AutoScanPage({ meta }: { meta: SettingsNavItem }) {
  const { data, isLoading, isError } = useAutoScan();

  return (
    <SPage eyebrow="Discovery" title="Active Scanning" job={meta.job} maxWidth={1000}>
      {isError ? (
        <SCard>
          <StateNote
            icon="alert-triangle" tone="var(--danger-text)"
            title="Couldn't load the policy"
            message="The automatic-scanning policy failed to load."
          />
        </SCard>
      ) : isLoading || !data ? (
        <SCard>
          <StateNote icon="loader" tone="var(--app-t3)" title="Loading…" message="Fetching the automatic-scanning policy." />
        </SCard>
      ) : (
        <>
          {/* Keyed on the saved values so a successful save re-seeds the form
              from what the SERVER stored, not from what was typed — the server
              normalizes (dedupes and sorts ports, canonicalizes protocols) and
              the box should show what is actually in force. */}
          <AutoScanForm
            key={`${data.policy.rescan_interval_hours}:${data.policy.ports.join(',')}:${data.policy.protocols.join(',')}:${String(data.policy.enabled)}:${String(data.policy.scan_on_first_observation)}:${String(data.policy.prefer_observing_sensor ?? true)}`}
            policy={data.policy}
            limits={data.limits}
            summary={data.summary}
          />
          <ScanActivitySection summary={data.summary} />
          <NotScannedSection summary={data.summary} />
        </>
      )}
    </SPage>
  );
}

// ---- What it did NOT scan, and why ------------------------------------------
//
// The panel for the tenant whose estate the sweep refuses in full — a Tailscale
// or ZeroTier network lives entirely in 100.64/10 — who would otherwise read
// "Automatic scanning: on" over a sweep that never scans a host. Loading and
// error states are the page's: this renders only once the summary has loaded.
function NotScannedSection({ summary }: { summary: AutoScanSummary }) {
  const rows = describeNotScanned(summary.not_scanned);
  const headline = notScannedHeadline(rows, summary.last_sweep_at);
  const cols = [
    { label: 'Why', w: '1fr' },
    { label: 'Hosts', w: '80px', align: 'right' as const },
    { label: '', w: '300px' },
  ];

  return (
    <SSection
      title="Not scanned"
      desc="Hosts in the inventory that the last pass looked at and refused, by reason. Automatic scans only ever reach addresses that are demonstrably yours; anything else is listed here rather than scanned."
    >
      {rows.length === 0 ? (
        <SCard>
          <StateNote
            icon={summary.last_sweep_at ? 'circle-check' : 'radar'}
            tone={summary.last_sweep_at ? GREEN : 'var(--app-t3)'}
            title={summary.last_sweep_at ? 'Every eligible host was scanned' : 'No pass has run yet'}
            message={summary.last_sweep_at
              ? 'The last pass refused nothing. Hosts it left out because their own interval had not elapsed are not refusals — they are simply not due.'
              : headline}
          />
        </SCard>
      ) : (
        <>
          <p style={{ fontSize: 12.5, color: 'var(--app-t2)', margin: '0 0 10px' }}>{headline}</p>
          <STable cols={cols}>
            {rows.map((row, i) => (
              <STableRow
                key={row.reason}
                first={i === 0}
                cols={cols}
                cells={[
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{row.label}</span>
                    <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{row.detail}</span>
                  </span>,
                  <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{row.count}</span>,
                  row.registerSegmentsHref ? (
                    <Link to={row.registerSegmentsHref} className="ui-btn sm" style={{ textDecoration: 'none' }}>
                      <Icon name="network" size={13} />
                      Register the segment to include these hosts
                    </Link>
                  ) : (
                    <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Nothing to do</span>
                  ),
                ]}
              />
            ))}
          </STable>
        </>
      )}
    </SSection>
  );
}

function AutoScanForm({ policy, limits, summary }: { policy: AutoScanPolicy; limits: AutoScanLimits; summary: AutoScanSummary }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<AutoScanDraft>(() => draftFromPolicy(policy));

  const problem = validateDraft(draft, limits);
  const dirty = isDirty(draft, policy);
  const set = <K extends keyof AutoScanDraft>(key: K, value: AutoScanDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));

  const toggleProtocol = (proto: string) => {
    setDraft((d) => ({
      ...d,
      protocols: d.protocols.includes(proto) ? d.protocols.filter((p) => p !== proto) : [...d.protocols, proto],
    }));
  };

  const save = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.inventory.PUT('/discovery/auto-scan', {
        body: draftToPayload(draft),
      });
      if (!response.ok || error || !data) throw new Error('Failed to save the policy');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: QUERY_KEY }),
  });

  return (
    <>
      <SSection
        title="What the platform scans on its own"
        desc="Active scanning probes your own internal hosts for the cryptography they present — certificates, TLS versions, cipher suites, SSH algorithms. Only addresses inside your private ranges or your registered network segments are ever scanned; public addresses and third-party systems are never probed."
      >
        <SCard>
          <SRow
            label="Automatic scanning"
            hint="The master switch. With this off, nothing is scanned unless you start a scan yourself from Discovery."
          >
            <SToggle on={draft.enabled} onChange={(v) => set('enabled', v)} />
          </SRow>
          <SRow
            label="Scan on first observation"
            hint="Scan a new internal host the moment it appears in the inventory, instead of waiting for the next scheduled pass. Independent of the rescan schedule below."
          >
            <SToggle on={draft.scanOnFirstObservation} onChange={(v) => set('scanOnFirstObservation', v)} />
          </SRow>
          <SRow
            label="Rescan every"
            hint={`How long a host's last automatic scan may age before it is scanned again, in hours. ${limits.min_rescan_interval_hours}–${limits.max_rescan_interval_hours}.`}
          >
            <SInput value={draft.intervalHours} onChange={(v) => set('intervalHours', v)} type="number" width={110} />
          </SRow>
          <SRow
            label="Prefer the observing sensor"
            hint="Run each automatic scan from the sensor of yours that most recently saw the host (or one on the same network), so hosts only reachable from inside your network are scanned from there. Off runs every automatic scan from the platform sensor."
            last
          >
            <SToggle on={draft.preferObservingSensor} onChange={(v) => set('preferObservingSensor', v)} />
          </SRow>
        </SCard>
        <p style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 12 }}>
          {describePolicy(draft, summary.assets_in_scope)}
        </p>
        {/* What "from where" means, beside the switch that decides it — a
            tenant would otherwise learn it from a host that is in scope and
            never scanned. */}
        <p style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 8 }}>
          {draft.preferObservingSensor
            ? 'A host one of your sensors has observed is scanned from that sensor. A host only the platform has seen is scanned from the platform sensor, which reaches only what the platform can route to. If the observing sensor is offline when a pass runs, the host waits for the next pass rather than being scanned from somewhere that cannot see it.'
            : 'Automatic scans run from the platform sensor inside the cluster, so they only reach hosts the platform itself can route to. A host reachable only from inside a network where you run your own sensor is not scanned automatically — scan those from Discovery → Active Scan with "Run from" set to that sensor.'}
        </p>
      </SSection>

      <SSection
        title="What each scan probes"
        desc="The protocols and ports every automatic scan tries. The defaults are the well-known TLS and SSH ports. They are deliberately narrower than the Discover wizard's list: file-sharing and industrial-control ports are fine for a scan you chose, once, but not for one that repeats on every host every interval — add them here if you want them."
      >
        <SCard>
          <SRow label="Protocols" hint="Only TLS and SSH can be scanned automatically. Industrial (OT) probes are never run unattended.">
            <span style={{ display: 'inline-flex', gap: 14 }}>
              {limits.supported_protocols.map((proto) => (
                <label key={proto} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t1)' }}>
                  <input
                    type="checkbox"
                    checked={draft.protocols.includes(proto)}
                    onChange={() => toggleProtocol(proto)}
                    aria-label={proto}
                  />
                  {proto}
                </label>
              ))}
            </span>
          </SRow>
          <SRow label="Ports" hint={`Comma-separated. At most ${limits.max_ports}.`} last>
            <SInput value={draft.portsText} onChange={(v) => set('portsText', v)} width={420} mono />
          </SRow>
        </SCard>
        <div style={{ marginTop: 10 }}>
          <button
            className="ui-btn sm ghost"
            onClick={() => set('portsText', formatPorts(limits.default_ports))}
            disabled={draft.portsText === formatPorts(limits.default_ports)}
          >
            Reset ports to the defaults
          </button>
        </div>
      </SSection>

      {problem && (
        <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 8 }}>{problem}</div>
      )}

      <PermissionGate
        permission={TENANT_PERMISSIONS.settings.update}
        fallback={<p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14 }}>You don’t have permission to change automatic scanning.</p>}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
          <button className="ui-btn accent" disabled={!dirty || !!problem || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save policy'}
          </button>
          {save.isError && <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn’t save — try again.</span>}
          {save.isSuccess && !dirty && <span style={{ fontSize: 12, color: GREEN }}>Saved.</span>}
          {dirty && !save.isPending && <span style={{ fontSize: 11.5, color: AMBER }}>Unsaved changes</span>}
        </div>
      </PermissionGate>
    </>
  );
}

// ---- What it has actually done --------------------------------------------
//
// Read-only, and deliberately on this page: scans the platform ran unasked
// appear nowhere else in the product. Discovery → Discovery Jobs lists device
// interrogations, not discovery jobs. Since each run also says WHICH
// executor ran it and in what state — "Failed: sensor offline" with the
// sensor's last heartbeat is visible here or nowhere.

/** The run's state chip — the same rule the Active Scan page's feedback uses. */
function RunState({ job }: { job: AutoScanSummary['recent_jobs'][number] }) {
  const s = scanJobState(scanJobFromRecent(job));
  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, fontWeight: 600, color: s.color }}>
        <span style={{ width: 6, height: 6, borderRadius: 50, background: s.color }} />{s.label}
      </span>
      {s.detail && <span title={s.detail} style={{ fontSize: 10.5, color: 'var(--app-t3)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.detail}</span>}
    </span>
  );
}

function ScanActivitySection({ summary }: { summary: AutoScanSummary }) {
  const cols = [
    { label: 'Scan', w: '1fr' },
    { label: 'Hosts', w: '80px', align: 'right' as const },
    { label: 'Executor', w: '150px' },
    { label: 'State', w: '190px' },
    { label: 'Started', w: '120px' },
  ];

  return (
    <SSection title="Recent automatic scans" desc="What the platform has scanned for you, without being asked.">
      <SCard>
        <SRow label="Last pass" hint="When the platform last looked for hosts that were due.">
          <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>
            {summary.last_sweep_at
              ? `${relTime(summary.last_sweep_at)} — ${summary.last_sweep_jobs} scan${summary.last_sweep_jobs === 1 ? '' : 's'} covering ${summary.last_sweep_assets} asset${summary.last_sweep_assets === 1 ? '' : 's'}`
              : 'No pass has run yet.'}
          </span>
        </SRow>
        <SRow label="Next pass" hint="The platform looks for due hosts on this schedule; a host is only scanned once its own interval has elapsed.">
          <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>
            {summary.next_sweep_at ? relTime(summary.next_sweep_at) : '—'}
          </span>
        </SRow>
        <SRow label="Assets in scope" hint="Assets automatic scanning covers today — internal address, not archived or denied, not third-party." last>
          <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{summary.assets_in_scope}</span>
        </SRow>
      </SCard>

      <div style={{ marginTop: 14 }}>
        {summary.recent_jobs.length === 0 ? (
          <SCard>
            <StateNote
              icon="radar" tone="var(--app-t3)"
              title="No automatic scans yet"
              message="Nothing has been scanned automatically. New internal hosts are scanned as they appear, so the first entries show up once discovery finds something."
            />
          </SCard>
        ) : (
          <STable cols={cols}>
            {summary.recent_jobs.map((job, i) => (
              <STableRow
                key={job.id}
                first={i === 0}
                cols={cols}
                cells={[
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                    <Icon name="radar" size={13} />
                    <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{job.id.slice(0, 8)}</span>
                    <STag>Automatic</STag>
                  </span>,
                  <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{job.target_count}</span>,
                  <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{job.executor === 'sensor' ? job.executor_name ?? 'Tenant sensor' : 'Platform sensor'}</span>,
                  <RunState job={job} />,
                  <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{relTime(job.created_at)}</span>,
                ]}
              />
            ))}
          </STable>
        )}
      </div>
    </SSection>
  );
}
