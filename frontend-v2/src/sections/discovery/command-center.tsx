import { useState } from 'react';
import { useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { jobMeta, sensorOnline, onlineCount, relTime, PageWrap } from './kit';
import { useSensors, useSensorStats, useDiscoveryCounts, useDeviceAgents, useJobs, useJobStats, usePendingAssets } from './queries';
import { DiscoverAssetsModal } from './discover-modal';
import { ImportSpreadsheetModal } from './import-modal';

// Discovery · Command Center — ported from the mock's `discovery` view:
// a 4-stat strip (each card navigates to its sub-page) over a two-panel grid
// (sensor fleet · recent jobs), all live.

function StatCard({ label, val, sub, tone, icon, to }: { label: string; val: string | number; sub: string; tone?: string; icon: string; to?: string }) {
  const nav = useNavigate();
  return (
    <button onClick={() => to && nav(to)} className="panel" style={{ padding: '16px 18px', textAlign: 'left', cursor: to ? 'pointer' : 'default', flex: 1, border: 'none' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span className="eyebrow-app">{label}</span>
        <Icon name={icon} size={15} style={{ color: tone || 'var(--app-t3)' }} />
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 7, marginTop: 11 }}>
        <span className="mono" style={{ fontSize: 26, fontWeight: 700, color: 'var(--app-t1)' }}>{val}</span>
        <span style={{ fontSize: 12, color: tone || 'var(--app-t3)' }}>{sub}</span>
      </div>
    </button>
  );
}

function PanelHead({ title, action, to }: { title: string; action: string; to: string }) {
  const nav = useNavigate();
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
      <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--app-t1)' }}>{title}</h3>
      <button className="ui-btn sm" onClick={() => nav(to)}>{action}<Icon name="arrow-up-right" /></button>
    </div>
  );
}

export function CommandCenterPage() {
  const sensorsQ = useSensors();
  const statsQ = useSensorStats();
  const agentsQ = useDeviceAgents();
  const countsQ = useDiscoveryCounts();
  const jobsQ = useJobs();
  const jobStatsQ = useJobStats();
  const pendingQ = usePendingAssets();

  const sensors = sensorsQ.data ?? [];
  const agents = agentsQ.data ?? [];
  const counts = countsQ.data ?? {};
  const jobs = jobsQ.data?.jobs ?? [];
  // Combined across BOTH fleets (M-13): the Sensors & Agents page header
  // counts sensors + device agents, and this tile must not disagree — a
  // device agent going offline used to leave "Sensors online" all-green
  // because agents were excluded entirely.
  const sensorTotal = statsQ.data?.total_sensors ?? sensors.length;
  const sensorOnlineCount = statsQ.data?.active_sensors ?? onlineCount(sensors);
  const total = sensorTotal + agents.length;
  const online = sensorOnlineCount + onlineCount(agents);
  const offline = total - online;
  const running = jobStatsQ.data?.in_progress ?? 0;
  const failed = jobStatsQ.data?.failed ?? 0;
  const pending = pendingQ.data?.length ?? 0;
  const dash = (q: { isLoading: boolean }, v: string | number) => (q.isLoading ? '…' : v);
  const [discoverOpen, setDiscoverOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);

  return (
    <PageWrap>
      <div className="fade-up" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>Command Center</h2>
        <PermissionGate permission={TENANT_PERMISSIONS.discovery.create}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="ui-btn" onClick={() => setImportOpen(true)}><Icon name="upload" size={14} />Import from spreadsheet</button>
            <button className="ui-btn accent" onClick={() => setDiscoverOpen(true)}><Icon name="radar" size={14} />Discover assets</button>
          </div>
        </PermissionGate>
      </div>

      <DiscoverAssetsModal open={discoverOpen} onClose={() => setDiscoverOpen(false)} />
      <ImportSpreadsheetModal open={importOpen} onClose={() => setImportOpen(false)} />

      <div className="fade-up" style={{ display: 'flex', gap: 14, marginBottom: 16 }}>
        <StatCard label="Fleet online" val={statsQ.isLoading || agentsQ.isLoading ? '…' : `${online}/${total}`} sub={offline > 0 ? `${offline} offline` : 'all healthy'} tone={offline > 0 ? 'var(--warn-strong)' : 'var(--ok)'} icon="radar" to="/discovery/sensors" />
        <StatCard label="Jobs running" val={dash(jobStatsQ, running)} sub="in progress" tone="var(--info)" icon="loader" to="/discovery/jobs" />
        <StatCard label="Failed jobs" val={dash(jobStatsQ, failed)} sub={failed > 0 ? 'need attention' : 'none failing'} tone={failed > 0 ? 'var(--danger)' : 'var(--app-t3)'} icon="x-circle" to="/discovery/logs" />
        <StatCard label="Pending approvals" val={dash(pendingQ, pending)} sub="awaiting review" tone="var(--info)" icon="inbox" to="/discovery/approvals" />
      </div>

      <div className="fade-up" style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 16, animationDelay: '.05s' }}>
        <div className="panel" style={{ padding: 20 }}>
          <PanelHead title="Sensor fleet" action="Manage" to="/discovery/sensors" />
          {sensorsQ.isLoading ? (
            <MiniNote text="Loading sensors…" />
          ) : sensorsQ.isError ? (
            <MiniNote text="Couldn't load sensors." />
          ) : sensors.length === 0 ? (
            <MiniNote text="No sensors registered yet." />
          ) : (
            sensors.map((s, i) => {
              const on = sensorOnline(s.status, s.last_heartbeat);
              return (
                <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '9px 0', borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 50, flex: 'none', background: on ? 'var(--ok)' : 'var(--danger)', boxShadow: on ? '0 0 6px var(--ok)' : 'none' }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.name}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {[s.sensor_type || s.profile, (s.network_interfaces ?? []).join(', ')].filter(Boolean).join(' · ')}
                    </div>
                  </div>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', flex: 'none' }}>{counts[s.id] != null ? `${counts[s.id]} found` : ''}</span>
                  <span style={{ fontSize: 11, color: on ? 'var(--app-t3)' : 'var(--danger-text)', flex: 'none' }}>{on ? relTime(s.last_heartbeat) : 'offline ' + relTime(s.last_heartbeat)}</span>
                </div>
              );
            })
          )}
        </div>

        <div className="panel" style={{ padding: 20 }}>
          <PanelHead title="Recent jobs" action="All jobs" to="/discovery/jobs" />
          {jobsQ.isLoading ? (
            <MiniNote text="Loading jobs…" />
          ) : jobsQ.isError ? (
            <MiniNote text="Couldn't load jobs." />
          ) : jobs.length === 0 ? (
            <MiniNote text="No discovery jobs have run yet." />
          ) : (
            jobs.slice(0, 6).map((j, i) => {
              const m = jobMeta(j.status);
              return (
                <div key={j.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 0', borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                  <span style={{ width: 22, height: 22, borderRadius: 6, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${m.c} 12%, transparent)`, color: m.c }}>
                    <Icon name={m.icon} size={12} />
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.job_type || 'Job'}</div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {[j.device_name || j.integration_name, relTime(j.started_at || j.created_at)].filter(Boolean).join(' · ')}
                    </div>
                  </div>
                  <span style={{ fontSize: 11, color: m.c, flex: 'none' }}>{m.l}</span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </PageWrap>
  );
}

function MiniNote({ text }: { text: string }) {
  return <div style={{ padding: '18px 0', fontSize: 12, color: 'var(--app-t3)' }}>{text}</div>;
}
