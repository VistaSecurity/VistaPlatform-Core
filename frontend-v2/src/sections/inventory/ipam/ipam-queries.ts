// Query hooks for IPAM (asset-inventory ADR-0010 D3; DCIM BUILD_PLAN row 1.3):
// the Inventory → Networks and VLANs lenses and Settings → IPAM. Every path is
// in the inventory-service spec (`/ipam/...`) and goes through the generated
// client.
//
// Thirteen objects share one CRUD shape on the server, so the list / create /
// update / delete hooks here are generic over the route segment. The route is
// a closed union, and each one's row type comes from the contract.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { errorMessage } from '../../../lib/api-result';

type S = components['schemas'];
export type Prefix = S['Prefix'];
export type PrefixDetail = S['PrefixDetail'];
export type PrefixTreeNode = S['PrefixTreeNode'];
export type IpAddress = S['IpAddress'];
export type IpRange = S['IpRange'];
export type Vrf = S['Vrf'];
export type Vlan = S['Vlan'];
export type VlanGroup = S['VlanGroup'];
export type PrefixRole = S['PrefixRole'];
export type Rir = S['Rir'];
export type Aggregate = S['Aggregate'];
export type Asn = S['Asn'];
export type IpamFindResult = S['IpamFindResult'];
export type WirelessLanGroup = S['WirelessLanGroup'];
export type WirelessLan = S['WirelessLan'];
export type WirelessLink = S['WirelessLink'];

/** Row type per route segment. */
export interface IpamRows {
  rirs: Rir;
  aggregates: Aggregate;
  vrfs: Vrf;
  'route-targets': S['RouteTarget'];
  'prefix-roles': PrefixRole;
  prefixes: Prefix;
  'ip-ranges': IpRange;
  'ip-addresses': IpAddress;
  'vlan-groups': VlanGroup;
  vlans: Vlan;
  'fhrp-groups': S['FhrpGroup'];
  'fhrp-group-assignments': S['FhrpGroupAssignment'];
  asns: Asn;
  // Wireless (DCIM row 4.4) is served by the same object engine under
  // /wireless/..., so the same hooks and dialogs edit it.
  'wireless-lan-groups': WirelessLanGroup;
  'wireless-lans': WirelessLan;
  'wireless-links': WirelessLink;
}
export type IpamRoute = keyof IpamRows;

const WIRELESS_ROUTES: readonly IpamRoute[] = ['wireless-lan-groups', 'wireless-lans', 'wireless-links'];

/** The object's path under the inventory-service spec: `/ipam/<route>`, or
 *  `/wireless/<route>` for the wireless objects. */
export function objectPath(route: IpamRoute): string {
  return `${WIRELESS_ROUTES.includes(route) ? '/wireless' : '/ipam'}/${route}`;
}

/** The global table's VRF selector value (`vrf_id IS NULL`). */
export const GLOBAL_VRF = 'global';

// openapi-fetch types each literal path; the generic hooks pick the path at
// run time from a closed union, so they see the client through this narrower
// view. The paths are still the spec's, and the row types still the contract's.
interface LooseClient {
  GET(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  POST(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  PATCH(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  DELETE(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown; response?: Response }>;
}
const inv = () => clients.inventory as unknown as LooseClient;

/** The server's reason, from the ADR-0002 envelope. */
export function ipamError(error: unknown, fallback: string): string {
  if (error && typeof error === 'object') {
    const inner = (error as { error?: unknown }).error;
    if (inner && typeof inner === 'object') {
      const m = (inner as { message?: unknown }).message;
      if (typeof m === 'string' && m.trim()) return m.trim();
    }
  }
  return errorMessage(error) ?? fallback;
}

export const ipamKeys = {
  all: ['ipam'] as const,
  list: (route: IpamRoute, query: Record<string, string | number>) => ['ipam', 'list', route, query] as const,
  tree: (vrf: string) => ['ipam', 'tree', vrf] as const,
  prefix: (id: string, length: number) => ['ipam', 'prefix', id, length] as const,
  find: (address: string, vrf: string) => ['ipam', 'find', address, vrf] as const,
};

export interface IpamPage<T> { rows: T[]; total: number }

/** One page of an IPAM object list. `query` holds the server's filters. */
export function useIpamList<R extends IpamRoute>(
  route: R,
  query: Record<string, string | number> = {},
  opts: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: ipamKeys.list(route, query),
    enabled: opts.enabled ?? true,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }): Promise<IpamPage<IpamRows[R]>> => {
      const { data, error } = await inv().GET(objectPath(route), { signal, params: { query: { limit: 200, ...query } } });
      if (error || !data) throw new Error(ipamError(error, `Failed to load ${route.replace('-', ' ')}`));
      const env = data as { data?: IpamRows[R][]; pagination?: { total?: number } };
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

/** One VRF's prefix tree (`vrf` = a VRF id or GLOBAL_VRF). */
export function usePrefixTree(vrf: string) {
  return useQuery({
    queryKey: ipamKeys.tree(vrf),
    queryFn: async ({ signal }): Promise<{ nodes: PrefixTreeNode[]; total: number }> => {
      const { data, error } = await clients.inventory.GET('/ipam/prefixes/tree', { signal, params: { query: { vrf } } });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load prefixes'));
      return { nodes: data.data ?? [], total: data.total ?? 0 };
    },
  });
}

/** A prefix with its computed parts. `length` asks for free prefixes of /n. */
export function usePrefixDetail(id: string | null, length = 0) {
  return useQuery({
    queryKey: ipamKeys.prefix(id ?? '', length),
    enabled: !!id,
    queryFn: async ({ signal }): Promise<PrefixDetail> => {
      const { data, error } = await clients.inventory.GET('/ipam/prefixes/{id}', {
        signal, params: { path: { id: id! }, query: { limit: 20, ...(length ? { length } : {}) } },
      });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the prefix'));
      return data.data;
    },
  });
}

/** Where an address lives, in one VRF or (vrf empty) all of them. */
export function useIpamFind(address: string, vrf: string) {
  return useQuery({
    queryKey: ipamKeys.find(address, vrf),
    enabled: address.trim() !== '',
    retry: false,
    queryFn: async ({ signal }): Promise<IpamFindResult[]> => {
      const { data, error } = await clients.inventory.GET('/ipam/find', {
        signal, params: { query: { address: address.trim(), ...(vrf ? { vrf } : {}) } },
      });
      if (error || !data) throw new Error(ipamError(error, 'Failed to look the address up'));
      return data.data ?? [];
    },
  });
}

/** Create, edit or delete any IPAM object; every IPAM read is refetched. */
export function useIpamWrite<R extends IpamRoute>(route: R) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: ipamKeys.all });
  const create = useMutation({
    mutationFn: async (body: Record<string, unknown>): Promise<IpamRows[R]> => {
      const { data, error } = await inv().POST(objectPath(route), { body });
      if (error || !data) throw new Error(ipamError(error, 'Could not create it'));
      return (data as { data: IpamRows[R] }).data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }): Promise<IpamRows[R]> => {
      const { data, error } = await inv().PATCH(`${objectPath(route)}/{id}`, { params: { path: { id } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save it'));
      return (data as { data: IpamRows[R] }).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await inv().DELETE(`${objectPath(route)}/{id}`, { params: { path: { id } } });
      if (error) throw new Error(ipamError(error, 'Could not delete it'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

/** Empty strings become null and untouched fields are left out, so a PATCH
 *  says only what the person changed. */
export function cleanBody(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    out[k] = typeof v === 'string' && v.trim() === '' ? null : v;
  }
  return out;
}

/** Utilisation as words: never blank — an empty prefix is 0 % of its size. */
export function utilizationText(pct: number | undefined | null): string {
  const n = typeof pct === 'number' && Number.isFinite(pct) ? pct : 0;
  return `${n % 1 === 0 ? n.toFixed(0) : n.toFixed(1)}%`;
}

export const PREFIX_STATUS_LABEL: Record<Prefix['operational_status'], string> = {
  container: 'Container', active: 'Active', reserved: 'Reserved', deprecated: 'Deprecated',
};
export const IP_STATUS_LABEL: Record<IpAddress['operational_status'], string> = {
  active: 'Active', reserved: 'Reserved', deprecated: 'Deprecated', dhcp: 'DHCP', slaac: 'SLAAC',
};
export const LIFECYCLE_LABEL: Record<Prefix['status'], string> = {
  pending: 'Pending approval', active: 'Approved', rejected: 'Rejected', stale: 'Stale', archived: 'Archived',
};
