// Live queries and mutations for control-plane-managed SENSOR settings.
//
// Deliberately a sibling of agent-config-queries.ts rather than a generic one
// parameterised by runtime: the two speak to different services with different
// path shapes, and openapi-typescript's generated clients are separate types.
// A wrapper that took a runtime would have to cast its way past that, which
// trades a small duplication for a lost type check.
//
// Everything downstream IS shared — the display logic in agent-config.ts and
// the panel that renders it — so the part that could drift is the part that
// does not repeat.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import type { ConfigStatus, Setting, SettingValue, VersionInfo } from './agent-config';
import { NeedsConfirmation, problemText, type ConfigChange, type SaveResult } from './agent-config-queries';

export interface SensorConfig {
  settings: Setting[];
  status?: ConfigStatus;
  version?: VersionInfo;
}

export function useSensorConfig(sensorId: string | null) {
  return useQuery({
    queryKey: ['discovery', 'sensor-config', sensorId],
    enabled: Boolean(sensorId),
    queryFn: async (): Promise<SensorConfig> => {
      const { data, error } = await clients.sensors.GET('/sensors/{sensor_id}/desired-config', {
        params: { path: { sensor_id: sensorId as string } },
      });
      if (error || !data) throw new Error('Failed to load the sensor configuration');
      return { settings: data.settings ?? [], status: data.status, version: data.version };
    },
  });
}

export function useSensorFleetDefaults(enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-fleet-defaults'],
    enabled,
    queryFn: async (): Promise<SensorConfig> => {
      const { data, error } = await clients.sensors.GET('/sensors/config/defaults', {});
      if (error || !data) throw new Error('Failed to load the sensor fleet defaults');
      return { settings: data.settings ?? [] };
    },
  });
}

interface SaveVars {
  values: Record<string, SettingValue>;
  confirmed?: boolean;
}

export function useSaveSensorConfig(sensorId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ values, confirmed }: SaveVars): Promise<SaveResult> => {
      const { data, error, response } = await clients.sensors.PUT('/sensors/{sensor_id}/desired-config', {
        params: { path: { sensor_id: sensorId } },
        body: { values, confirmed },
      });
      if (response.status === 409) throw new NeedsConfirmation(confirmationFrom(error));
      if (error || !data) throw new Error(problemText(error) ?? 'Failed to save the configuration');
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-config', sensorId] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensors'] });
    },
  });
}

export function useSaveSensorFleetDefaults() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ values, confirmed }: SaveVars): Promise<SaveResult> => {
      const { data, error, response } = await clients.sensors.PUT('/sensors/config/defaults', {
        body: { values, confirmed },
      });
      if (response.status === 409) throw new NeedsConfirmation(confirmationFrom(error));
      if (error || !data) throw new Error(problemText(error) ?? 'Failed to save the fleet defaults');
      return data;
    },
    onSuccess: () => {
      // Every inheriting sensor's effective settings just changed, so the
      // per-sensor views are stale too, not only the defaults.
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-fleet-defaults'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'sensor-config'] });
    },
  });
}

function confirmationFrom(error: unknown) {
  const raw = (error as { needs_confirming?: unknown } | undefined)?.needs_confirming;
  const needsConfirming = Array.isArray(raw)
    ? raw
        .map((r) => r as { key?: unknown; confirm?: unknown })
        .filter((r) => typeof r.key === 'string' && typeof r.confirm === 'string')
        .map((r) => ({ key: r.key as string, confirm: r.confirm as string }))
    : [];
  return { needsConfirming };
}

export function useSensorConfigHistory(sensorId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'sensor-config-history', sensorId],
    enabled: Boolean(sensorId) && enabled,
    queryFn: async (): Promise<ConfigChange[]> => {
      const { data, error } = await clients.sensors.GET('/sensors/{sensor_id}/desired-config/history', {
        params: { path: { sensor_id: sensorId as string } },
      });
      if (error || !data) throw new Error('Failed to load the change history');
      return (data.changes ?? []) as ConfigChange[];
    },
  });
}
