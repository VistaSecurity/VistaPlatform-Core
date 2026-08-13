import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, sensorOnline, relTime } from './kit';
import { useSensors, useDiscoveryCounts, useDeviceAgents } from './queries';
import { RegisterSensorModal, DeleteSensorModal, DeleteAgentModal, PendingRegistrationsSection } from './sensor-modals';
import { SensorDetailDrawer } from './sensor-detail-drawer';
import { profileLabel, jobsSummary, hostSummary, addressTooltip } from './agent-fleet';

// Discovery → Sensors & Agents. TWO tables, because a sensor and a discovery
// agent are two different things:
//
//   Sensors          — passive libpcap binaries. Sensor · Type · Segment ·
//                      Assets found · Version · Status. From sensor-manager.
//   Discovery agents — command-driven interrogation binaries. Agent · Host ·
//                      Profile · Jobs · Version · Status. From
//                      device-interrogation-service.
//
// They used to share one sensor-shaped table, which meant every agent row
// rendered "—" for Segment and Assets found (neither of which an agent has)
// while the fields an agent DOES have — its address inventory, its profile, what
// jobs it has run — had nowhere to go. Merging them cost both kinds their detail
// to gain a row count nobody needed.
//
// "Assets found" joins GET /sensors/discovery-counts (sensors only); "Segment"
// renders the monitored interface subnets a sensor reports. Write surface
// (register / delete / pending registrations) lives in sensor-modals.tsx.

type SensorRow = NonNullable<ReturnType<typeof useSensors>['data']>[number];

const SENSOR_COLS = [
  { label: 'Sensor', w: '1.4fr' },
  { label: 'Type', w: '1fr' },
  { label: 'Segment', w: '1fr' },
  { label: 'Assets found', w: '120px', align: 'right' as const },
  { label: 'Version', w: '90px' },
  { label: 'Status', w: '110px', align: 'right' as const },
  { label: '', w: '44px', align: 'right' as const },
];

const AGENT_COLS = [
  { label: 'Agent', w: '1.4fr' },
  { label: 'Host', w: '1.1fr' },
  { label: 'Interrogates', w: '1fr' },
  { label: 'Jobs', w: '150px' },
  { label: 'Version', w: '90px' },
  { label: 'Status', w: '110px', align: 'right' as const },
  { label: '', w: '44px', align: 'right' as const },
];

export function SensorsPage() {
  const q = useSensors();
  const agentsQ = useDeviceAgents();
  const countsQ = useDiscoveryCounts();
  const counts = countsQ.data ?? {};

  const [registerOpen, setRegisterOpen] = useState(false);
  const [toDelete, setToDelete] = useState<{ id: string; name: string } | null>(null);
  const [agentToDelete, setAgentToDelete] = useState<{ id: string; name: string } | null>(null);
  const [selected, setSelected] = useState<SensorRow | null>(null);

  const sensors = q.data ?? [];
  const agents = agentsQ.data ?? [];

  // The page count still spans both fleets — the tenant thinks of this page as
  // "everything I have deployed", even though the tables are separate.
  const bothLoaded = !q.isLoading && !agentsQ.isLoading;
  const total = sensors.length + agents.length;

  // The sensors table owns the page's empty state: if there are no sensors AND
  // no agents, this is the one place that says so. When there are agents but no
  // sensors, the note correctly reports the sensor fleet as empty and the agents
  // table renders below it.
  const note = queryNote(q, bothLoaded && total === 0, {
    thing: 'sensors',
    emptyMessage: 'No sensors or agents are registered for this tenant yet.',
  });
  const sensorNote = note ?? (bothLoaded && sensors.length === 0
    ? queryNote(q, true, { thing: 'sensors', emptyMessage: 'No network sensors are registered for this tenant yet.' })
    : null);

  return (
    <PageWrap title="Sensors & Agents" count={bothLoaded ? total : ''}>
      <PermissionGate permission={TENANT_PERMISSIONS.sensors.manage}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
          <button className="ui-btn accent" onClick={() => setRegisterOpen(true)}>
            <Icon name="plus" size={14} />Register sensor or agent
          </button>
        </div>
      </PermissionGate>

      {sensorNote ?? (
        <DTable
          cols={SENSOR_COLS}
          rows={sensors}
          rowKey={(s) => s.id}
          onRow={(s) => setSelected(s)}
          render={(s) => {
            const on = sensorOnline(s.status, s.last_heartbeat);
            return (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 50, flex: 'none', background: on ? 'var(--ok)' : 'var(--danger)' }} />
                  <div style={{ minWidth: 0 }}>
                    <CellMono v={s.name} />
                    <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {[s.platform, s.ip_address, on ? relTime(s.last_heartbeat) : null].filter(Boolean).join(' · ')}
                    </div>
                  </div>
                </div>
                <CellTxt v={s.sensor_type || s.profile} />
                <CellTxt v={(s.network_interfaces ?? []).join(', ')} />
                <CellMono right v={counts[s.id] ?? '—'} />
                <CellMono v={s.version ? 'v' + s.version : '—'} c="var(--app-t3)" />
                <StatusCell status={s.status} online={on} />
                <span style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <PermissionGate permission={TENANT_PERMISSIONS.sensors.delete} fallback={<span />}>
                    <button
                      className="ui-btn sm ghost"
                      style={{ color: 'var(--danger-text)', flex: 'none', padding: '0 7px' }}
                      title="Delete sensor"
                      onClick={(e) => { e.stopPropagation(); setToDelete({ id: s.id, name: s.name }); }}
                    >
                      <Icon name="x" size={13} />
                    </button>
                  </PermissionGate>
                </span>
              </>
            );
          }}
        />
      )}

      {/* Quiet when the tenant has no agents — an empty second table is noise,
          not information, and the sensors table above already carries the
          page-level "nothing registered yet" state. */}
      {agents.length > 0 && (
        <div style={{ marginTop: 26 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--app-t1)' }}>Discovery agents</h3>
            <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{agents.length}</span>
          </div>
          <DTable
            cols={AGENT_COLS}
            rows={agents}
            rowKey={(a) => a.id}
            render={(a) => {
              const on = sensorOnline(a.status, a.last_heartbeat);
              const jobs = jobsSummary(a);
              const host = hostSummary(a);
              return (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
                    <span style={{ width: 8, height: 8, borderRadius: 50, flex: 'none', background: on ? 'var(--ok)' : 'var(--danger)' }} />
                    <div style={{ minWidth: 0 }}>
                      {/* Agents can enroll before a name is set; fall back to a
                          short id so the row is never blank. */}
                      <CellMono v={a.name || `agent-${a.id.slice(0, 8)}`} />
                      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {[a.description, a.platform].filter(Boolean).join(' · ') || '—'}
                      </div>
                    </div>
                  </div>
                  {/* The cell shows the primary and a count; the tooltip carries
                      the full inventory with prefixes, which is what makes the
                      addresses answer "which segments is this agent on?". */}
                  <div style={{ minWidth: 0 }} title={addressTooltip(a) || undefined}>
                    <CellMono v={host.primary} />
                    {host.extra && (
                      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{host.extra}</div>
                    )}
                  </div>
                  <CellTxt v={profileLabel(a.profile)} />
                  <div style={{ minWidth: 0 }}>
                    <CellTxt v={jobs.last} c={a.last_job_at ? 'var(--app-t2)' : 'var(--app-t3)'} />
                    {jobs.count && (
                      <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{jobs.count}</div>
                    )}
                  </div>
                  <CellMono v={a.version ? 'v' + a.version : '—'} c="var(--app-t3)" />
                  <StatusCell status={a.status} online={on} />
                  <span style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    {/* discovery.manage, not sensors.delete: the endpoint behind
                        this is device-interrogation-service's, gated the same as
                        its other destructive routes. */}
                    <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage} fallback={<span />}>
                      <button
                        className="ui-btn sm ghost"
                        style={{ color: 'var(--danger-text)', flex: 'none', padding: '0 7px' }}
                        title="Delete agent"
                        onClick={(e) => { e.stopPropagation(); setAgentToDelete({ id: a.id, name: a.name || `agent-${a.id.slice(0, 8)}` }); }}
                      >
                        <Icon name="x" size={13} />
                      </button>
                    </PermissionGate>
                  </span>
                </>
              );
            }}
          />
        </div>
      )}

      <PendingRegistrationsSection />

      <RegisterSensorModal open={registerOpen} onClose={() => setRegisterOpen(false)} />
      <DeleteSensorModal open={!!toDelete} sensor={toDelete} onClose={() => setToDelete(null)} />
      <DeleteAgentModal open={!!agentToDelete} agent={agentToDelete} onClose={() => setAgentToDelete(null)} />
      {selected && <SensorDetailDrawer sensor={selected} onClose={() => setSelected(null)} />}
    </PageWrap>
  );
}

// Shared status cell — both fleets use the same online/pending/offline colouring.
function StatusCell({ status, online }: { status?: string | null; online: boolean }) {
  return (
    <span style={{ textAlign: 'right', fontSize: 11.5, fontWeight: 600, color: online ? 'var(--ok)' : status === 'pending' ? 'var(--warn)' : 'var(--danger)' }}>
      {(status || 'unknown').replace('_', ' ')}
    </span>
  );
}
