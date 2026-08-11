import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, sensorOnline, relTime } from './kit';
import { useSensors, useDiscoveryCounts, useDeviceAgents } from './queries';
import { RegisterSensorModal, DeleteSensorModal, PendingRegistrationsSection } from './sensor-modals';
import { SensorDetailDrawer } from './sensor-detail-drawer';

// Discovery → Sensors & Agents — the mock's `discovery-sensors` table:
// Sensor · Type · Segment · Assets found · Version · Status. Two live sources are
// merged into one fleet list: network sensors from sensor-manager (GET /sensors)
// and enrolled device interrogation agents from device-interrogation-service
// (GET /agents) — they live in different services/tables but the tenant thinks
// of them as one "Sensors & Agents" list. "Assets found" joins
// GET /sensors/discovery-counts (sensors only); "Segment" renders the monitored
// interface subnets a sensor reports. Write surface (register / delete / pending
// registrations) lives in sensor-modals.tsx.

type SensorRow = NonNullable<ReturnType<typeof useSensors>['data']>[number];
type AgentRow = NonNullable<ReturnType<typeof useDeviceAgents>['data']>[number];

// Unified fleet row — a sensor or a device agent, flattened to the columns the
// table renders. `raw`/`kind` let row actions (drill-in, delete) branch by kind:
// only sensors have a detail drawer and a delete endpoint here.
type FleetRow = {
  kind: 'sensor' | 'agent';
  id: string;
  name: string;
  platform?: string | null;
  ipAddress?: string | null;
  lastHeartbeat?: string | null;
  status?: string | null;
  typeLabel: string;
  segment: string;
  version?: string | null;
  sensor: SensorRow | null;
};

const COLS = [
  { label: 'Sensor', w: '1.4fr' },
  { label: 'Type', w: '1fr' },
  { label: 'Segment', w: '1fr' },
  { label: 'Assets found', w: '120px', align: 'right' as const },
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
  const [selected, setSelected] = useState<SensorRow | null>(null);

  // Merge the two fleets. Sensors keep their existing shape; device agents have
  // no IP/segment/discovery-count and always render as the "Device agent" type.
  const rows: FleetRow[] = [
    ...(q.data ?? []).map((s): FleetRow => ({
      kind: 'sensor',
      id: s.id,
      name: s.name,
      platform: s.platform,
      ipAddress: s.ip_address,
      lastHeartbeat: s.last_heartbeat,
      status: s.status,
      typeLabel: s.sensor_type || s.profile,
      segment: (s.network_interfaces ?? []).join(', '),
      version: s.version,
      sensor: s,
    })),
    ...(agentsQ.data ?? []).map((a: AgentRow): FleetRow => ({
      kind: 'agent',
      id: a.id,
      // Agents may enroll before the operator-supplied name is set; fall back to
      // a short id so the row is never blank.
      name: a.name || `agent-${a.id.slice(0, 8)}`,
      platform: a.platform,
      ipAddress: null,
      lastHeartbeat: a.last_heartbeat,
      status: a.status,
      typeLabel: 'Device agent',
      segment: '',
      version: a.version,
      sensor: null,
    })),
  ];

  // The list is "loaded/empty" only once both sources have resolved, so an agent
  // that arrives after sensors doesn't flash an empty state. queryNote drives the
  // loading/error/empty messaging off the sensors query (the primary source).
  const bothLoaded = !q.isLoading && !agentsQ.isLoading;
  const note = queryNote(q, bothLoaded && rows.length === 0, {
    thing: 'sensors',
    emptyMessage: 'No sensors or agents are registered for this tenant yet.',
  });

  return (
    <PageWrap title="Sensors & Agents" count={bothLoaded ? rows.length : ''}>
      <PermissionGate permission={TENANT_PERMISSIONS.sensors.manage}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
          <button className="ui-btn accent" onClick={() => setRegisterOpen(true)}>
            <Icon name="plus" size={14} />Register sensor or agent
          </button>
        </div>
      </PermissionGate>

      {note ?? (
        <DTable
          cols={COLS}
          rows={rows}
          rowKey={(r) => r.id}
          onRow={(r) => { if (r.kind === 'sensor' && r.sensor) setSelected(r.sensor); }}
          render={(r) => {
            const on = sensorOnline(r.status);
            return (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 50, flex: 'none', background: on ? 'var(--ok)' : 'var(--danger)' }} />
                  <div style={{ minWidth: 0 }}>
                    <CellMono v={r.name} />
                    <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {[r.platform, r.ipAddress, on ? relTime(r.lastHeartbeat) : null].filter(Boolean).join(' · ')}
                    </div>
                  </div>
                </div>
                <CellTxt v={r.typeLabel} />
                <CellTxt v={r.segment} />
                <CellMono right v={counts[r.id] ?? '—'} />
                <CellMono v={r.version ? 'v' + r.version : '—'} c="var(--app-t3)" />
                <span style={{ textAlign: 'right', fontSize: 11.5, fontWeight: 600, color: on ? 'var(--ok)' : r.status === 'pending' ? 'var(--warn)' : 'var(--danger)' }}>
                  {(r.status || 'unknown').replace('_', ' ')}
                </span>
                <span style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  {/* Delete is wired to the sensor endpoint; device agents are
                      managed via device-interrogation-service, so no delete here. */}
                  {r.kind === 'sensor' ? (
                    <PermissionGate permission={TENANT_PERMISSIONS.sensors.delete} fallback={<span />}>
                      <button
                        className="ui-btn sm ghost"
                        style={{ color: 'var(--danger-text)', flex: 'none', padding: '0 7px' }}
                        title="Delete sensor"
                        onClick={(e) => { e.stopPropagation(); setToDelete({ id: r.id, name: r.name }); }}
                      >
                        <Icon name="x" size={13} />
                      </button>
                    </PermissionGate>
                  ) : <span />}
                </span>
              </>
            );
          }}
        />
      )}

      <PendingRegistrationsSection />

      <RegisterSensorModal open={registerOpen} onClose={() => setRegisterOpen(false)} />
      <DeleteSensorModal open={!!toDelete} sensor={toDelete} onClose={() => setToDelete(null)} />
      {selected && <SensorDetailDrawer sensor={selected} onClose={() => setSelected(null)} />}
    </PageWrap>
  );
}
