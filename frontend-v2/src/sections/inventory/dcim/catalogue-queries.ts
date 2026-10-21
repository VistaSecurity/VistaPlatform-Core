// Query hooks for the device catalogue (DCIM BUILD_PLAN row 2.2; ADR-0010 D4):
// Settings → Device Types / Manufacturers / Device Roles / Platforms (OS), the
// asset form's hardware fields and the asset page's Hardware card. Every path is
// in the inventory-service spec (`/dcim/...`) and goes through the generated
// client.
//
// The five catalogue objects (and the nine template kinds) share one CRUD shape
// on the server, so the hooks are generic over the route segment, as IPAM's are.
// A row with tenant_id null is platform-seeded: listed, never editable.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { ipamError } from '../ipam/ipam-queries';
import { interfaceKeys } from './interface-queries';

type S = components['schemas'];
export type Manufacturer = S['Manufacturer'];
export type DeviceType = S['DeviceType'];
export type ModuleType = S['ModuleType'];
export type DeviceRole = S['DeviceRole'];
export type Platform = S['Platform'];
export type AssetHardware = S['AssetHardware'];
export type AssetCommercial = S['AssetCommercial'];
export type AssetLifecycle = S['AssetLifecycle'];
export type CatalogueEOS = S['CatalogueEOS'];
export type EOSDate = S['EOSDate'];
export type EOLCatalogueRef = S['EOLCatalogueRef'];
export type ApplyDeviceTypeResult = S['ApplyDeviceTypeResult'];
export type ImportedDeviceType = S['ImportedDeviceType'];

/** Row type per catalogue route. */
export interface CatalogueRows {
  manufacturers: Manufacturer;
  'device-types': DeviceType;
  'module-types': ModuleType;
  'device-roles': DeviceRole;
  platforms: Platform;
}
export type CatalogueRoute = keyof CatalogueRows;

/** Row type per template kind. */
export interface TemplateRows {
  'interface-templates': S['InterfaceTemplate'];
  'console-port-templates': S['ConsolePortTemplate'];
  'console-server-port-templates': S['ConsoleServerPortTemplate'];
  'front-port-templates': S['FrontPortTemplate'];
  'rear-port-templates': S['RearPortTemplate'];
  'module-bay-templates': S['ModuleBayTemplate'];
  'device-bay-templates': S['DeviceBayTemplate'];
  'power-port-templates': S['PowerPortTemplate'];
  'power-outlet-templates': S['PowerOutletTemplate'];
}
export type TemplateKind = keyof TemplateRows;

/** The template kinds, in the order the detail view's tabs show them. */
export const TEMPLATE_KINDS: { kind: TemplateKind; label: string }[] = [
  { kind: 'interface-templates', label: 'Interfaces' },
  { kind: 'console-port-templates', label: 'Console ports' },
  { kind: 'console-server-port-templates', label: 'Console server ports' },
  { kind: 'front-port-templates', label: 'Front ports' },
  { kind: 'rear-port-templates', label: 'Rear ports' },
  { kind: 'module-bay-templates', label: 'Module bays' },
  { kind: 'device-bay-templates', label: 'Device bays' },
  { kind: 'power-port-templates', label: 'Power ports' },
  { kind: 'power-outlet-templates', label: 'Power outlets' },
];

/** A platform-seeded row (shipped with the product; read-only to a tenant). */
export const isPlatformRow = (row: { tenant_id?: string | null }) => row.tenant_id == null;

/** "1U", "0.5U", or "Not rack-mounted" for 0. */
export function uHeightText(u: number | string | null | undefined): string {
  const n = typeof u === 'string' ? Number(u) : u;
  if (n == null || !Number.isFinite(n)) return '—';
  if (n === 0) return 'Not rack-mounted';
  return `${n}U`;
}

// openapi-fetch types each literal path; the generic hooks pick the path at run
// time from a closed union, so they see the client through this narrower view.
interface LooseClient {
  GET(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  POST(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  PATCH(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  DELETE(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
}
const inv = () => clients.inventory as unknown as LooseClient;

export const catalogueKeys = {
  all: ['dcim-catalogue'] as const,
  list: (route: CatalogueRoute, query: Record<string, string | number>) => ['dcim-catalogue', 'list', route, query] as const,
  one: (route: CatalogueRoute, id: string) => ['dcim-catalogue', 'one', route, id] as const,
  templates: (parent: string, kind: TemplateKind) => ['dcim-catalogue', 'templates', parent, kind] as const,
  hardware: (asset: string) => ['dcim-hardware', asset] as const,
  eol: (kind: string) => ['dcim-eol-catalogue', kind] as const,
};

export interface CataloguePage<T> { rows: T[]; total: number }

/** One page of a catalogue list; `query` holds the server's filters. */
export function useCatalogueList<R extends CatalogueRoute>(
  route: R,
  query: Record<string, string | number> = {},
  opts: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: catalogueKeys.list(route, query),
    enabled: opts.enabled ?? true,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }): Promise<CataloguePage<CatalogueRows[R]>> => {
      const { data, error } = await inv().GET(`/dcim/${route}`, { signal, params: { query: { limit: 200, ...query } } });
      if (error || !data) throw new Error(ipamError(error, `Failed to load ${route.replace('-', ' ')}`));
      const env = data as { data?: CatalogueRows[R][]; pagination?: { total?: number } };
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

/** Create, edit or delete a catalogue object; every catalogue read is refetched. */
export function useCatalogueWrite<R extends CatalogueRoute>(route: R) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: catalogueKeys.all });
  const create = useMutation({
    mutationFn: async (body: Record<string, unknown>): Promise<CatalogueRows[R]> => {
      const { data, error } = await inv().POST(`/dcim/${route}`, { body });
      if (error || !data) throw new Error(ipamError(error, 'Could not create it'));
      return (data as { data: CatalogueRows[R] }).data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }): Promise<CatalogueRows[R]> => {
      const { data, error } = await inv().PATCH(`/dcim/${route}/{id}`, { params: { path: { id } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save it'));
      return (data as { data: CatalogueRows[R] }).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await inv().DELETE(`/dcim/${route}/{id}`, { params: { path: { id } } });
      if (error) throw new Error(ipamError(error, 'Could not delete it'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

/** A device type's templates of one kind (all of them: a chassis has hundreds at most). */
export function useTemplates<K extends TemplateKind>(deviceTypeId: string | null, kind: K, enabled = true) {
  return useQuery({
    queryKey: catalogueKeys.templates(deviceTypeId ?? '', kind),
    enabled: !!deviceTypeId && enabled,
    queryFn: async ({ signal }): Promise<TemplateRows[K][]> => {
      const { data, error } = await inv().GET(`/dcim/device-types/{id}/${kind}`, {
        signal, params: { path: { id: deviceTypeId }, query: { limit: 1000 } },
      });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the templates'));
      return (data as { data?: TemplateRows[K][] }).data ?? [];
    },
  });
}

/** Create, edit or delete a template of the tenant's own device type. */
export function useTemplateWrite(deviceTypeId: string, kind: TemplateKind) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: catalogueKeys.all });
  const base = `/dcim/device-types/{id}/${kind}`;
  const create = useMutation({
    mutationFn: async (body: Record<string, unknown>) => {
      const { data, error } = await inv().POST(base, { params: { path: { id: deviceTypeId } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not create the template'));
      return (data as { data: { id: string } }).data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }) => {
      const { data, error } = await inv().PATCH(`${base}/{template_id}`, { params: { path: { id: deviceTypeId, template_id: id } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save the template'));
      return (data as { data: { id: string } }).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await inv().DELETE(`${base}/{template_id}`, { params: { path: { id: deviceTypeId, template_id: id } } });
      if (error) throw new Error(ipamError(error, 'Could not delete the template'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

/** POST /dcim/device-types/import: library YAML → the tenant's own types. */
export function useImportDeviceTypes() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (yaml: string): Promise<ImportedDeviceType[]> => {
      const { data, error } = await clients.inventory.POST('/dcim/device-types/import', { body: { yaml } });
      if (error || !data) throw new Error(ipamError(error, 'The import failed'));
      return data.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: catalogueKeys.all }),
  });
}

/** An asset's hardware view (device type, manufacturer, role, platform, serial, asset tag). */
export function useAssetHardware(assetId: string | null | undefined) {
  return useQuery({
    queryKey: catalogueKeys.hardware(assetId ?? ''),
    enabled: !!assetId,
    queryFn: async ({ signal }): Promise<AssetHardware> => {
      const { data, error } = await clients.inventory.GET('/dcim/assets/{id}/hardware', { signal, params: { path: { id: assetId! } } });
      if (error || !data) throw new Error(ipamError(error, "Failed to load the asset's hardware"));
      return data.data;
    },
  });
}

export type HardwarePatch = S['AssetHardwareUpdateInput'];

/** PATCH /dcim/assets/{id}/hardware. */
export async function patchAssetHardware(assetId: string, body: HardwarePatch): Promise<AssetHardware> {
  const { data, error } = await clients.inventory.PATCH('/dcim/assets/{id}/hardware', { params: { path: { id: assetId } }, body });
  if (error || !data) throw new Error(ipamError(error, "Could not save the asset's hardware"));
  return data.data;
}

/**
 * Write an asset's commercial lifecycle columns (DCIM gap 4) through the
 * hardware PATCH; the Hardware view is replaced with the server's answer and
 * the asset reads (list, page) refetch, since they carry the same columns.
 */
export function usePatchAssetLifecycle(assetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: HardwarePatch) => patchAssetHardware(assetId, body),
    onSuccess: (hw) => {
      qc.setQueryData(catalogueKeys.hardware(assetId), hw);
      void qc.invalidateQueries({ queryKey: ['asset-detail', assetId] });
      void qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });
}

/** End-of-life catalogue entries a device type (hardware) or platform (os) may link to. */
export function useEOLCatalogue(kind: 'hardware' | 'os', enabled = true) {
  return useQuery({
    queryKey: catalogueKeys.eol(kind),
    enabled,
    staleTime: 5 * 60_000,
    queryFn: async ({ signal }): Promise<EOLCatalogueRef[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/eol-catalogue', { signal, params: { query: { product_kind: kind, limit: 1000 } } });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the end-of-life catalogue'));
      return data.data;
    },
  });
}

/** An end-of-life catalogue entry as one line: "Cisco Catalyst 9300 · 1 (support ends". */
export function eolEntryLabel(e: EOLCatalogueRef): string {
  const name = [e.vendor, e.product].filter(Boolean).join(' ');
  return `${name} · ${e.cycle}${e.eol_date ? ` (support ends ${e.eol_date})` : ''}`;
}

/** "Apply templates": assign the type and instantiate its interfaces. */
export function useApplyDeviceType(assetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (deviceTypeId: string): Promise<ApplyDeviceTypeResult> => {
      const { data, error } = await clients.inventory.POST('/dcim/assets/{id}/device-type', {
        params: { path: { id: assetId } }, body: { device_type_id: deviceTypeId },
      });
      if (error || !data) throw new Error(ipamError(error, 'Could not apply the templates'));
      return data.data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: catalogueKeys.hardware(assetId) });
      // The Interfaces tab shows what the apply created and filled.
      void qc.invalidateQueries({ queryKey: interfaceKeys.assetAll(assetId) });
      void qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });
}
