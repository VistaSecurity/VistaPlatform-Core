// Fleet data layer. The unified agent estate is two cross-tenant, read-only,
// platform-admin endpoints merged client-side: sensor-manager /admin/sensors
// (standalone + in-cluster platform sensors) and device-interrogation
// /admin/agents (interrogation agents). Each is best-effort (retry:0) so one
// service being down doesn't blank the whole table. Normalized to FleetRow so
// the table is source-agnostic — and so a future operate flow can target rows
// by {kind,id} without a reshape (observe-only today; see the Fleet decision).
import { useQuery } from '@tanstack/react-query';
import type { deviceInterrogationComponents, sensorManagerComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type AdminSensor = sensorManagerComponents['schemas']['AdminSensor'];
export type AdminAgent = deviceInterrogationComponents['schemas']['AdminAgent'];

export interface FleetRow {
  id: string;
  kind: 'sensor' | 'agent';
  tenantId: string;
  name: string;
  typeLabel: string;
  tenant: string;
  version: string;
  status: string;
  heartbeat: string | null;
}

/**
 * Is this `sensors` row the in-cluster DEVICE INTERROGATION agent?
 *
 * The platform registers two rows in `sensors` for every tenant. The discovery
 * one is a sensor; the `device_interrogation` one is the command-driven
 * interrogation agent, in `sensors` only because interrogated assets are
 * attributed to it. It belongs with the agents, as the tenant console files it
 * (frontend-v2 sections/discovery/agent-fleet.ts isPlatformInterrogationAgent).
 *
 * BOTH conditions: platform-managed (server-side is_platform_sensor — the
 * platform marker OR the 'system' tag), so a customer sensor that happens to
 * carry the interrogation profile stays a sensor; and the profile, so the
 * platform discovery sensor is not swept along.
 */
export function isPlatformInterrogationAgent(s: Pick<AdminSensor, 'is_platform_sensor' | 'profile'>): boolean {
  return !!s.is_platform_sensor && (s.profile ?? '').toLowerCase() === 'device_interrogation';
}

export function sensorFleetRow(s: AdminSensor): FleetRow {
  const interrogationAgent = isPlatformInterrogationAgent(s);
  return {
    id: s.id,
    kind: interrogationAgent ? 'agent' : 'sensor',
    tenantId: s.tenant_id,
    name: s.name || s.ip_address || '(unnamed sensor)',
    typeLabel: interrogationAgent
      ? 'Platform Interrogation Agent'
      : s.is_platform_sensor ? 'Platform Sensor' : (s.sensor_type || 'sensor'),
    tenant: s.tenant_name || s.tenant_slug || '—',
    version: s.version || '—',
    // sensor-manager's reaper maintains sensors.status (a silent sensor is
    // flipped to 'offline'), so the stored value is already the live one.
    status: s.status || 'unknown',
    heartbeat: s.last_heartbeat ?? null,
  };
}

export function agentFleetRow(a: AdminAgent): FleetRow {
  return {
    id: a.id,
    kind: 'agent',
    tenantId: a.tenant_id,
    name: a.name || '(unnamed agent)',
    typeLabel: a.profile ? `Agent · ${a.profile}` : 'Interrogation Agent',
    tenant: a.tenant_name || a.tenant_slug || '—',
    version: a.version || '—',
    // device_agents.status is written 'active' at enrollment and never
    // updated, so it cannot show a dead agent. effective_status is derived
    // server-side from last_heartbeat (15-minute window, as the web-ui and the
    // discovery_agent_offline alert use).
    status: a.effective_status || 'unknown',
    heartbeat: a.last_heartbeat ?? null,
  };
}

/** Rows per kind chip, counted from the merged rows so a row's chip and its count agree. */
export function fleetKindCounts(rows: FleetRow[]): { all: number; sensor: number; agent: number } {
  let sensor = 0;
  let agent = 0;
  for (const r of rows) {
    if (r.kind === 'sensor') sensor++;
    else agent++;
  }
  return { all: rows.length, sensor, agent };
}

export function useFleetSensors(scopeId: string | null) {
  return useQuery({
    queryKey: ['platform', 'fleet', 'sensors', scopeId],
    queryFn: async (): Promise<FleetRow[]> => {
      // Narrow server-side so other tenants' sensor rows are never shipped here.
      const { data, error } = await clients.sensors.GET('/admin/sensors', {
        params: { query: scopeId ? { tenant_id: scopeId } : {} },
      });
      if (error || !data) throw new Error('Failed to load sensors');
      return (data.sensors ?? []).map(sensorFleetRow);
    },
    staleTime: 30 * 1000,
    retry: 0,
  });
}

export function useFleetAgents(scopeId: string | null) {
  return useQuery({
    queryKey: ['platform', 'fleet', 'agents', scopeId],
    queryFn: async (): Promise<FleetRow[]> => {
      // Narrow server-side so other tenants' agent rows are never shipped here.
      const { data, error } = await clients.devices.GET('/admin/agents', {
        params: { query: scopeId ? { tenant_id: scopeId } : {} },
      });
      if (error || !data) throw new Error('Failed to load agents');
      return (data.agents ?? []).map(agentFleetRow);
    },
    staleTime: 30 * 1000,
    retry: 0,
  });
}
