// Live queries and mutations for control-plane-managed agent settings.
//
// The display logic lives in agent-config.ts and is pure; this file is the wire.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import type { ConfigStatus, Setting, SettingValue, VersionInfo } from './agent-config';

export interface AgentConfig {
  settings: Setting[];
  status?: ConfigStatus;
  version?: VersionInfo;
}

export function useAgentConfig(agentId: string | null) {
  return useQuery({
    queryKey: ['discovery', 'agent-config', agentId],
    enabled: Boolean(agentId),
    queryFn: async (): Promise<AgentConfig> => {
      const { data, error } = await clients.devices.GET('/agents/{id}/config', {
        params: { path: { id: agentId as string } },
      });
      if (error || !data) throw new Error('Failed to load the agent configuration');
      // `version` is NOT optional decoration here: the drawer passes it to the
      // panel and the panel renders the badge from it. Leaving it out made the
      // agent's version badge silently absent while the endpoint served it, the
      // type declared it and a reachability test asserted the prop was passed —
      // the prop was, carrying undefined. Pinning JSX cannot catch a producer
      // that never produces.
      return { settings: (data.settings ?? []), status: data.status, version: data.version };
    },
  });
}

export function useAgentFleetDefaults(enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'agent-fleet-defaults'],
    enabled,
    queryFn: async (): Promise<AgentConfig> => {
      const { data, error } = await clients.devices.GET('/agents/config/defaults', {});
      if (error || !data) throw new Error('Failed to load the fleet defaults');
      return { settings: (data.settings ?? []) };
    },
  });
}

/** What a save reports back: what changed, what was silently raised to a floor,
 *  and what only takes effect on restart. All three are shown — a value the
 *  platform adjusted is exactly the thing an operator would otherwise never
 *  learn. */
export interface SaveResult {
  changed: string[];
  adjusted: string[];
  needs_restart: string[];
}

/** A 409 carrying the settings the server wants acknowledged, with the text
 *  naming what begins to be collected. The server decides this, not the client:
 *  a client that simply never sent the flag must not be able to waive it. */
export interface ConfirmationRequired {
  needsConfirming: { key: string; confirm: string }[];
}

export class NeedsConfirmation extends Error {
  constructor(public readonly required: ConfirmationRequired) {
    super('This change needs to be confirmed');
    this.name = 'NeedsConfirmation';
  }
}

interface SaveVars {
  values: Record<string, SettingValue>;
  confirmed?: boolean;
}

export function useSaveAgentConfig(agentId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ values, confirmed }: SaveVars): Promise<SaveResult> => {
      const { data, error, response } = await clients.devices.PUT('/agents/{id}/config', {
        params: { path: { id: agentId } },
        body: { values, confirmed },
      });
      if (response.status === 409) throw new NeedsConfirmation(confirmationFrom(error));
      if (error || !data) throw new Error(problemText(error) ?? 'Failed to save the configuration');
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'agent-config', agentId] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'device-agents'] });
    },
  });
}

export function useSaveAgentFleetDefaults() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ values, confirmed }: SaveVars): Promise<SaveResult> => {
      const { data, error, response } = await clients.devices.PUT('/agents/config/defaults', {
        body: { values, confirmed },
      });
      if (response.status === 409) throw new NeedsConfirmation(confirmationFrom(error));
      if (error || !data) throw new Error(problemText(error) ?? 'Failed to save the fleet defaults');
      return data;
    },
    onSuccess: () => {
      // Every inheriting agent's effective settings just changed, so the
      // per-agent views are stale too — not only the defaults.
      qc.invalidateQueries({ queryKey: ['discovery', 'agent-fleet-defaults'] });
      qc.invalidateQueries({ queryKey: ['discovery', 'agent-config'] });
    },
  });
}

/** The server's per-setting problems, joined for display. Falls back to
 *  undefined so the caller can use its own wording rather than printing
 *  "[object Object]". */
export function problemText(error: unknown): string | undefined {
  const problems = (error as { problems?: unknown } | undefined)?.problems;
  if (Array.isArray(problems) && problems.length > 0) return problems.join('; ');
  const message = (error as { error?: unknown } | undefined)?.error;
  return typeof message === 'string' ? message : undefined;
}

function confirmationFrom(error: unknown): ConfirmationRequired {
  const raw = (error as { needs_confirming?: unknown } | undefined)?.needs_confirming;
  const needsConfirming = Array.isArray(raw)
    ? raw
        .map((r) => r as { key?: unknown; confirm?: unknown })
        .filter((r) => typeof r.key === 'string' && typeof r.confirm === 'string')
        .map((r) => ({ key: r.key as string, confirm: r.confirm as string }))
    : [];
  return { needsConfirming };
}

/** Ask one agent to restart at its next check-in.
 *
 *  The response carries the platform's own note about what "restart" means for
 *  a device nothing supervises, and the caller shows it rather than inventing
 *  its own wording — one source of truth for the caveat that matters. */
export function useRequestAgentRestart(agentId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (): Promise<{ restart_requested_at: string; note: string }> => {
      const { data, error } = await clients.devices.POST('/agents/{id}/restart', {
        params: { path: { id: agentId } },
      });
      if (error || !data) throw new Error(problemText(error) ?? 'Could not request a restart');
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'agent-config', agentId] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'device-agents'] });
    },
  });
}

/** One recorded configuration change, as the history endpoints return it. */
export interface ConfigChange {
  changed_at: string;
  changed_by: string;
  scope: string;
  keys: string[];
  values_before: Record<string, unknown>;
  values_after: Record<string, unknown>;
}

export function useAgentConfigHistory(agentId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'agent-config-history', agentId],
    enabled: Boolean(agentId) && enabled,
    queryFn: async (): Promise<ConfigChange[]> => {
      const { data, error } = await clients.devices.GET('/agents/{id}/config/history', {
        params: { path: { id: agentId as string } },
      });
      if (error || !data) throw new Error('Failed to load the change history');
      return (data.changes ?? []) as ConfigChange[];
    },
  });
}
