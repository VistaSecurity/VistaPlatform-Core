// Fleet data layer. The unified agent estate is two cross-tenant, read-only,
// platform-admin endpoints merged client-side: sensor-manager /admin/sensors
// (standalone + in-cluster platform sensors) and device-interrogation
// /admin/agents (interrogation agents). Each is best-effort (retry:0) so one
// service being down doesn't blank the whole table. Normalized to FleetRow so
// the table is source-agnostic — and so a future operate flow can target rows
// by {kind,id} without a reshape (observe-only today; see the Fleet decision).
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';

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

export function useFleetSensors(scopeId: string | null) {
  return useQuery({
    queryKey: ['platform', 'fleet', 'sensors', scopeId],
    queryFn: async (): Promise<FleetRow[]> => {
      // Narrow server-side so other tenants' sensor rows are never shipped here.
      const { data, error } = await clients.sensors.GET('/admin/sensors', {
        params: { query: scopeId ? { tenant_id: scopeId } : {} },
      });
      if (error || !data) throw new Error('Failed to load sensors');
      return (data.sensors ?? []).map((s) => ({
        id: s.id,
        kind: 'sensor' as const,
        tenantId: s.tenant_id,
        name: s.name || s.ip_address || '(unnamed sensor)',
        typeLabel: s.is_platform_sensor ? 'Platform Sensor' : (s.sensor_type || 'sensor'),
        tenant: s.tenant_name || s.tenant_slug || '—',
        version: s.version || '—',
        status: s.status || 'unknown',
        heartbeat: s.last_heartbeat ?? null,
      }));
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
      return (data.agents ?? []).map((a) => ({
        id: a.id,
        kind: 'agent' as const,
        tenantId: a.tenant_id,
        name: a.name || '(unnamed agent)',
        typeLabel: a.profile ? `Agent · ${a.profile}` : 'Interrogation Agent',
        tenant: a.tenant_name || a.tenant_slug || '—',
        version: a.version || '—',
        status: a.status || 'unknown',
        heartbeat: a.last_heartbeat ?? null,
      }));
    },
    staleTime: 30 * 1000,
    retry: 0,
  });
}
