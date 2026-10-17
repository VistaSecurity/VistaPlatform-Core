// Query hooks for an asset's port components (DCIM BUILD_PLAN row 3.1;
// asset-inventory ADR-0010 D3): console ports, console server ports, front
// ports, rear ports and device bays. Power ports and outlets have an API and no
// UI (D9).
//
// The five kinds share one request shape, so the calls go through one loosely
// typed facade keyed by the route segment; PORT_PATHS is `satisfies` the
// generated client's path keys, so a path that leaves the spec fails typecheck.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError, substrateKeys } from './substrate-queries';

export type ConsolePort = components['schemas']['ConsolePort'];
export type ConsoleServerPort = components['schemas']['ConsoleServerPort'];
export type FrontPort = components['schemas']['FrontPort'];
export type RearPort = components['schemas']['RearPort'];
export type DeviceBay = components['schemas']['DeviceBay'];
export type ApplyDeviceTypeResult = components['schemas']['ApplyDeviceTypeResult'];
export type AssetHardware = components['schemas']['AssetHardware'];

export const PORT_KINDS = ['console-ports', 'console-server-ports', 'front-ports', 'rear-ports', 'device-bays'] as const;
export type PortKind = (typeof PORT_KINDS)[number];

/** Row type per kind. */
export interface PortRows {
  'console-ports': ConsolePort;
  'console-server-ports': ConsoleServerPort;
  'front-ports': FrontPort;
  'rear-ports': RearPort;
  'device-bays': DeviceBay;
}
export type PortRow = PortRows[PortKind];

/** The object kind (vocabulary key) each route records its changes under. */
export const PORT_OBJECT_KIND = {
  'console-ports': 'console_port',
  'console-server-ports': 'console_server_port',
  'front-ports': 'front_port',
  'rear-ports': 'rear_port',
  'device-bays': 'device_bay',
} as const satisfies Record<PortKind, string>;

// Compile-time guard: every path used below is a path of the generated client.
export const PORT_PATHS = [
  '/dcim/assets/{id}/console-ports', '/dcim/assets/{id}/console-server-ports', '/dcim/assets/{id}/front-ports',
  '/dcim/assets/{id}/rear-ports', '/dcim/assets/{id}/device-bays',
  '/dcim/console-ports/{id}', '/dcim/console-server-ports/{id}', '/dcim/front-ports/{id}',
  '/dcim/rear-ports/{id}', '/dcim/device-bays/{id}',
  '/dcim/assets/{id}/hardware', '/dcim/assets/{id}/device-type',
] as const satisfies readonly (keyof inventoryPaths)[];

interface Reply { data?: unknown; error?: unknown }
interface Loose {
  GET: (path: string, init?: object) => Promise<Reply>;
  POST: (path: string, init?: object) => Promise<Reply>;
  PATCH: (path: string, init?: object) => Promise<Reply>;
  DELETE: (path: string, init?: object) => Promise<Reply>;
}
const api = (): Loose => clients.inventory as unknown as Loose;

/** The tab lists an asset's components of a kind on one page. */
export const PORTS_PAGE_SIZE = 1000;

export const portKeys = {
  list: (assetId: string, kind: PortKind) => ['dcim-ports', assetId, kind] as const,
  asset: (assetId: string) => ['dcim-ports', assetId] as const,
  hardware: (assetId: string) => ['dcim-hardware', assetId] as const,
};

export class PortWriteError extends Error {}

export interface PortPage<K extends PortKind> { rows: PortRows[K][]; total: number }

export function useAssetPorts<K extends PortKind>(assetId: string | undefined, kind: K) {
  return useQuery({
    queryKey: portKeys.list(assetId ?? '', kind),
    enabled: !!assetId,
    queryFn: async (): Promise<PortPage<K>> => {
      const { data, error } = await api().GET(`/dcim/assets/{id}/${kind}`, {
        params: { path: { id: assetId! }, query: { limit: PORTS_PAGE_SIZE } },
      });
      const env = data as { data?: PortRows[K][]; pagination?: { total?: number } } | undefined;
      if (error || !env) throw new Error(substrateError(error, `Failed to load ${kind.replace(/-/g, ' ')}`));
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

function useInvalidate(assetId: string, kind: PortKind) {
  const qc = useQueryClient();
  return (id?: string) => {
    // A front port's mapping reads the rear ports and a rear port's counts read
    // the front ports, so a write refreshes the whole tab.
    void qc.invalidateQueries({ queryKey: portKeys.asset(assetId) });
    if (id) void qc.invalidateQueries({ queryKey: substrateKeys.changes(PORT_OBJECT_KIND[kind], id) });
  };
}

export type PortBody = Record<string, unknown>;

export function useCreatePort(assetId: string, kind: PortKind) {
  const invalidate = useInvalidate(assetId, kind);
  return useMutation({
    mutationFn: async (body: PortBody): Promise<PortRow> => {
      const { data, error } = await api().POST(`/dcim/assets/{id}/${kind}`, { params: { path: { id: assetId } }, body });
      const env = data as { data?: PortRow } | undefined;
      if (error || !env?.data) throw new PortWriteError(substrateError(error, 'Failed to add'));
      return env.data;
    },
    onSuccess: (r) => {
      toast.success(`Added ${r.name}`);
      invalidate(r.id);
    },
  });
}

export function usePatchPort(assetId: string, kind: PortKind) {
  const invalidate = useInvalidate(assetId, kind);
  return useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: PortBody }): Promise<PortRow> => {
      const { data, error } = await api().PATCH(`/dcim/${kind}/{id}`, { params: { path: { id } }, body: patch });
      const env = data as { data?: PortRow } | undefined;
      if (error || !env?.data) throw new PortWriteError(substrateError(error, 'Failed to save'));
      return env.data;
    },
    onSuccess: (r) => {
      toast.success(`Saved ${r.name}`);
      invalidate(r.id);
    },
  });
}

export function useDeletePort(assetId: string, kind: PortKind) {
  const invalidate = useInvalidate(assetId, kind);
  return useMutation({
    mutationFn: async (r: PortRow): Promise<PortRow> => {
      const { error } = await api().DELETE(`/dcim/${kind}/{id}`, { params: { path: { id: r.id } } });
      if (error) throw new PortWriteError(substrateError(error, 'Failed to delete'));
      return r;
    },
    onSuccess: (r) => {
      toast.success(`Deleted ${r.name}`);
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete'),
  });
}

/** The asset's catalogue view; only its device type matters here. */
export function useAssetHardware(assetId: string | undefined) {
  return useQuery({
    queryKey: portKeys.hardware(assetId ?? ''),
    enabled: !!assetId,
    queryFn: async (): Promise<AssetHardware> => {
      const { data, error } = await api().GET('/dcim/assets/{id}/hardware', { params: { path: { id: assetId! } } });
      const env = data as { data?: AssetHardware } | undefined;
      if (error || !env?.data) throw new Error(substrateError(error, 'Failed to load the asset\'s device type'));
      return env.data;
    },
  });
}

/** Re-applies the asset's device type, instantiating every template kind. */
export function useApplyTemplates(assetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (deviceTypeId: string): Promise<ApplyDeviceTypeResult> => {
      const { data, error } = await api().POST('/dcim/assets/{id}/device-type', {
        params: { path: { id: assetId } },
        body: { device_type_id: deviceTypeId },
      });
      const env = data as { data?: ApplyDeviceTypeResult } | undefined;
      if (error || !env?.data) throw new PortWriteError(substrateError(error, 'Failed to apply the device type\'s templates'));
      return env.data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: portKeys.asset(assetId) });
      void qc.invalidateQueries({ queryKey: ['dcim-interfaces', assetId] });
    },
  });
}

/** One line per kind of what an apply did, for the result panel. */
export function applySummary(r: ApplyDeviceTypeResult): { label: string; created: number; updated: number; unchanged: number; removed: number; skipped: string[] }[] {
  const rows = [{ label: 'Interfaces', ...r.interfaces }];
  const names: Record<string, string> = {
    'rear-ports': 'Rear ports', 'front-ports': 'Front ports', 'console-ports': 'Console ports',
    'console-server-ports': 'Console server ports', 'device-bays': 'Device bays', 'power-ports': 'Power ports',
    'power-outlets': 'Power outlets', 'module-bays': 'Module bays',
  };
  for (const [route, label] of Object.entries(names)) {
    const k = r.components[route];
    if (k) rows.push({ label, ...k });
  }
  return rows;
}
