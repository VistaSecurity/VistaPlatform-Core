// Discovery agent detail, and the settings surface that makes an agent
// manageable without logging into its host.
//
// Rendered on the shared runtime frame (runtime-drawer.tsx), so it has the same
// header, tab order, Health opening block, job history and restart control as
// the sensor drawer. What an agent cannot do is left out rather than shown
// empty: it has no Discoveries stream (its work is jobs). Its Logs tab works
// through the heartbeat rather than a command queue — see shared/agentlogs.
import { useState } from 'react';
import { Link } from 'react-router';
import { TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { MetaRow, SectionLabel } from '../../components/ui';
import { jobTypeLabel, relTime, sensorOnline, durationFmt } from './kit';
import { hostInventorySummary, addressTooltip, profileLabel } from './agent-fleet';
import { useDeviceAgents } from './queries';
import { SettingsPanel } from './settings-panel';
import { useAgentConfig, useAgentConfigHistory, useSaveAgentConfig, useRequestAgentRestart } from './agent-config-queries';
import { useAgentJobs, useAgentLogs, useJobResults, useRequestAgentLogs } from './agent-job-queries';
import { ConfigHistorySection } from './config-history';
import type { SettingValue } from './agent-config';
import {
  RuntimeDrawer, ConnectionHealth, JobHistoryList, MetricCard, PayloadBlock, DetailRow, RestartControl,
  ManagedHereNote, Muted, fmtTs, LogExportPanel, type LogExportState, type RecentJob, type RuntimeTabKey,
} from './runtime-drawer';

// The row shape the fleet query returns, rather than a hand-written interface:
// a local copy would drift from the generated contract silently.
export type DeviceAgentRow = NonNullable<ReturnType<typeof useDeviceAgents>['data']>[number];

type AgentJob = NonNullable<ReturnType<typeof useAgentJobs>['data']>['jobs'][number];

const AGENT_TABS: readonly RuntimeTabKey[] = ['overview', 'health', 'jobs', 'logs', 'settings'];

export function AgentDetailDrawer({ agent, onClose }: { agent: DeviceAgentRow; onClose: () => void }) {
  const [tab, setTab] = useState<RuntimeTabKey>('overview');
  const on = sensorOnline(agent.status, agent.last_heartbeat);
  const name = agent.name || `agent-${agent.id.slice(0, 8)}`;

  return (
    <RuntimeDrawer
      icon="server-cog"
      eyebrow="Discovery agent"
      name={name}
      online={on}
      status={agent.status}
      badges={<>
        {agent.version && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>v{agent.version}</span>}
        {agent.ip_address && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{agent.ip_address}</span>}
      </>}
      tabs={AGENT_TABS}
      tab={tab}
      onTab={setTab}
      onClose={onClose}
    >
      {tab === 'overview' && <AgentOverview agent={agent} />}
      {tab === 'health' && <AgentHealth agent={agent} />}
      {tab === 'jobs' && <AgentJobs agentId={agent.id} />}
      {tab === 'logs' && <AgentLogs agentId={agent.id} />}
      {tab === 'settings' && <AgentSettings agent={agent} />}
    </RuntimeDrawer>
  );
}

function AgentOverview({ agent }: { agent: DeviceAgentRow }) {
  const on = sensorOnline(agent.status, agent.last_heartbeat);
  return (
    <>
      <SectionLabel icon="info">Summary</SectionLabel>
      <MetaRow k="Status" v={(agent.status || 'unknown').replace('_', ' ')} />
      <MetaRow k={on ? 'Last heartbeat' : 'Last seen'} v={relTime(agent.last_heartbeat)} />
      <MetaRow k="Version" v={agent.version ? `v${agent.version}` : null} mono />
      <MetaRow k="IP address" v={agent.ip_address} mono title={addressTooltip(agent) || undefined} />
      {(agent.addresses?.length ?? 0) > 1 && (
        <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)' }}>
          <div style={{ fontSize: 11, color: 'var(--app-t3)', marginBottom: 5 }}>All addresses</div>
          {agent.addresses?.map((a) => (
            <div key={`${a.interface_name}-${a.address}`} style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '2px 0' }}>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>
                {a.address}{a.prefix_length ? `/${a.prefix_length}` : ''}
              </span>
              <span style={{ fontSize: 11, color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>
                {a.interface_name}{a.is_primary ? ' · primary' : ''}
              </span>
            </div>
          ))}
        </div>
      )}
      <MetaRow k="Platform" v={agent.platform} />
      <MetaRow k="Profile" v={profileLabel(agent.profile)} />
      {agent.description && <MetaRow k="Description" v={agent.description} />}
      {/* What the agent learned about its OWN host, which no job count can
          say — a host inventory is not work anybody queued. */}
      <MetaRow k="Host inventory" v={hostInventorySummary(agent) || 'Never reported'} />
    </>
  );
}

function AgentHealth({ agent }: { agent: DeviceAgentRow }) {
  const on = sensorOnline(agent.status, agent.last_heartbeat);
  const config = useAgentConfig(agent.id);
  const jobs = useAgentJobs(agent.id);
  const recent = jobs.data?.jobs ?? [];
  const failed = recent.filter((j) => ['failed', 'error'].includes((j.status || '').toLowerCase())).length;
  const done = recent.filter((j) => ['completed', 'success'].includes((j.status || '').toLowerCase())).length;

  return (
    <>
      <ConnectionHealth
        noun="agent"
        online={on}
        lastHeartbeat={agent.last_heartbeat}
        version={agent.version}
        configStatus={config.data?.status}
        configLoading={config.isLoading}
      />

      <SectionLabel icon="activity">Work</SectionLabel>
      {/* An agent reports no process telemetry (memory, uptime) — its
          heartbeat carries version, address and interfaces only — so its
          health is what the platform sees it do. */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 6 }}>
        <MetricCard icon="list-checks" label="Jobs (all time)" value={(agent.job_count ?? 0).toLocaleString()} />
        <MetricCard icon="clock" label="Last job" value={agent.last_job_at ? relTime(agent.last_job_at) : 'Never'} />
        <MetricCard icon="check" label={`Completed (last ${recent.length || 0})`} value={jobs.isLoading ? '…' : String(done)} />
        <MetricCard
          icon="alert-triangle"
          label={`Failed (last ${recent.length || 0})`}
          value={jobs.isLoading ? '…' : String(failed)}
          tone={failed > 0 ? 'var(--danger-text)' : undefined}
        />
      </div>
      {jobs.isError && <Muted danger>Couldn't load this agent's recent jobs.</Muted>}

      <SectionLabel icon="server">Host</SectionLabel>
      <MetaRow k="Host inventory" v={agent.last_host_inventory_at ? relTime(agent.last_host_inventory_at) : 'Never reported'} title={fmtTs(agent.last_host_inventory_at)} />
      {agent.host_inventory_packages != null && <MetaRow k="Packages" v={agent.host_inventory_packages.toLocaleString()} />}
      {agent.host_inventory_listeners != null && <MetaRow k="Listeners" v={agent.host_inventory_listeners.toLocaleString()} />}
    </>
  );
}

function agentJobRow(j: AgentJob): RecentJob {
  return {
    id: j.id,
    title: jobTypeLabel(j.job_type) || j.job_type,
    target: j.device_name || j.integration_name || null,
    status: j.status,
    createdAt: j.created_at,
    error: j.error_message,
  };
}

function AgentJobs({ agentId }: { agentId: string }) {
  const q = useAgentJobs(agentId);
  const jobs = q.data?.jobs ?? [];
  const byId = new Map(jobs.map((j) => [j.id, j]));
  return (
    <>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.6, margin: '14px 0 0' }}>
        Jobs reach an agent from <Link to="/discovery/devices" style={{ color: 'var(--accent)' }}>Managed Devices</Link>{' '}
        and the asset scan actions. Every job in the tenant is listed in{' '}
        <Link to="/discovery/jobs" style={{ color: 'var(--accent)' }}>Discovery Jobs</Link>.
      </div>
      <JobHistoryList
        jobs={jobs.map(agentJobRow)}
        total={q.data?.total}
        isLoading={q.isLoading}
        isError={q.isError}
        emptyText="No jobs have been assigned to this agent."
        renderDetail={(id) => <AgentJobDetail job={byId.get(id)!} />}
      />
    </>
  );
}

function AgentJobDetail({ job }: { job: AgentJob }) {
  const finished = ['completed', 'success', 'failed', 'error'].includes((job.status || '').toLowerCase());
  const results = useJobResults(job.id, finished);
  return (
    <>
      <DetailRow k="Job" v={job.id} mono />
      {job.asset_id
        ? <DetailRow k="Target" v={<Link to={`/inventory/assets/${job.asset_id}`} style={{ color: 'var(--accent)' }}>{job.device_name || 'View asset'}</Link>} />
        : <DetailRow k="Target" v={job.integration_name} />}
      <DetailRow k="Queued" v={fmtTs(job.created_at)} mono />
      <DetailRow k="Started" v={job.started_at ? fmtTs(job.started_at) : null} mono />
      <DetailRow k="Finished" v={job.completed_at ? fmtTs(job.completed_at) : null} mono />
      <DetailRow k="Duration" v={job.duration_seconds != null ? durationFmt(job.duration_seconds) : null} />
      <DetailRow k="Assets found" v={job.assets_discovered != null ? String(job.assets_discovered) : null} />
      {finished && (results.isLoading
        ? <Muted>Loading results…</Muted>
        : results.isError
          ? <Muted danger>Couldn't load the results.</Muted>
          : results.data && <PayloadBlock label="Results" value={{ summary: results.data.summary, assets: results.data.assets }} />)}
    </>
  );
}

function AgentLogs({ agentId }: { agentId: string }) {
  const q = useAgentLogs(agentId);
  const request = useRequestAgentLogs(agentId);
  // sensors.update: the gate on POST /agents/{id}/logs/request.
  const canRequest = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const [lineCount, setLineCount] = useState(200);

  const d = q.data;
  const state: LogExportState = q.isError
    ? { kind: 'error', message: "Couldn't load this agent's logs." }
    : q.isLoading || !d
      ? { kind: 'loading' }
      : d.request
        // A request this agent cannot collect would otherwise wait for ever.
        ? (d.supported ? { kind: 'waiting', requestedAt: d.request.requested_at } : { kind: 'unsupported' })
        : d.export
          ? { kind: 'ready', lines: d.export.lines ?? [], receivedAt: d.export.received_at }
          : !d.supported
            ? { kind: 'unsupported' }
            : { kind: 'none' };

  return (
    <LogExportPanel
      noun="agent"
      state={state}
      canRequest={canRequest}
      lineCount={lineCount}
      onLineCount={setLineCount}
      onFetch={() => request.mutate(lineCount)}
      fetching={request.isPending}
      fetchError={request.isError ? request.error.message : null}
      unsupportedText="This agent has not said it can send its logs. Agents older than this release cannot; a current agent that has not checked in for 15 minutes reads the same. Upgrade or restart the agent, then try again."
    />
  );
}

function AgentSettings({ agent }: { agent: DeviceAgentRow }) {
  // Not destructured: the hook's methods read `this`, and relationships-tab.tsx
  // records that destructuring them trips.
  const canEdit = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const q = useAgentConfig(agent.id);
  const save = useSaveAgentConfig(agent.id);
  // Fetched only once the section is opened: a drawer somebody glances at
  // should not query an audit table.
  const [historyOpen, setHistoryOpen] = useState(false);
  const history = useAgentConfigHistory(agent.id, historyOpen);

  if (q.isLoading) return <Muted>Loading settings…</Muted>;
  if (q.isError || !q.data) return <Muted danger>Couldn't load this agent's settings.</Muted>;

  return (
    <>
      <SettingsPanel
        settings={q.data.settings}
        status={q.data.status}
        version={q.data.version}
        scope="device"
        canEdit={canEdit}
        saving={save.isPending}
        save={(values: Record<string, SettingValue>, confirmed: boolean) => save.mutateAsync({ values, confirmed })}
      />
      <ManagedHereNote noun="agent" canEdit={canEdit} />
      <ConfigHistorySection
        changes={history.data}
        isLoading={history.isLoading}
        isError={history.isError}
        onOpen={() => setHistoryOpen(true)}
      />
      <RestartSection agentId={agent.id} />
    </>
  );
}

// ---- Restart ---------------------------------------------------------------
//
// Gated on sensors.manage, not sensors.update: this is disruptive, and
// disruptive is the side of that line where manage lives. Configuration is the
// other side.
function RestartSection({ agentId }: { agentId: string }) {
  const canRestart = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.manage);
  const restart = useRequestAgentRestart(agentId);

  if (!canRestart) return null;

  return (
    <RestartControl
      noun="agent"
      // The caveat BEFORE the click, not after it: an agent that nothing
      // supervises stops rather than restarting. That is the one way this
      // disappoints, and an operator should meet it while they can still
      // change their mind.
      caveat="The agent exits and its service manager starts it again. If this agent was launched by hand rather than installed as a service, it will stop instead of restarting."
      pending={restart.isPending}
      onConfirm={() => restart.mutate()}
      successNote={restart.isSuccess ? `Requested. ${restart.data.note}` : undefined}
      error={restart.isError ? (restart.error instanceof Error ? restart.error.message : 'Could not request a restart') : null}
    />
  );
}
