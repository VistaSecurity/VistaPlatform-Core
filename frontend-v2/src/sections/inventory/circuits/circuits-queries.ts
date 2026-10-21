// Query hooks for circuits (asset-inventory ADR-0010 D8; DCIM BUILD_PLAN row
// 4.1): the Inventory → Circuits lens and Settings → Circuit Providers. Every
// path is in the inventory-service spec (`/circuits/...`) and goes through the
// generated client.
//
// Eleven objects share one CRUD shape on the server (the IPAM object engine), so
// the hooks are generic over the route segment, as IPAM's are. The route is a
// closed union, and each one's row type comes from the contract.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { ipamError } from '../ipam/ipam-queries';

type S = components['schemas'];
export type Provider = S['Provider'];
export type ProviderAccount = S['ProviderAccount'];
export type ProviderNetwork = S['ProviderNetwork'];
export type CircuitType = S['CircuitType'];
export type Circuit = S['Circuit'];
export type CircuitTermination = S['CircuitTermination'];
export type CircuitTerminationSummary = S['CircuitTerminationSummary'];
export type CircuitGroup = S['CircuitGroup'];
// DCIM gap 10: virtual circuits (NetBox 4.2).
export type VirtualCircuitType = S['VirtualCircuitType'];
export type VirtualCircuit = S['VirtualCircuit'];
export type VirtualCircuitTermination = S['VirtualCircuitTermination'];
export type VirtualCircuitTerminationSummary = S['VirtualCircuitTerminationSummary'];

/** Row type per route segment. */
export interface CircuitRows {
  providers: Provider;
  'provider-accounts': ProviderAccount;
  'provider-networks': ProviderNetwork;
  'circuit-types': CircuitType;
  circuits: Circuit;
  'circuit-terminations': CircuitTermination;
  'circuit-groups': CircuitGroup;
  'circuit-group-assignments': S['CircuitGroupAssignment'];
  'virtual-circuit-types': VirtualCircuitType;
  'virtual-circuits': VirtualCircuit;
  'virtual-circuit-terminations': VirtualCircuitTermination;
}
export type CircuitRoute = keyof CircuitRows;

// openapi-fetch types each literal path; the generic hooks pick the path at run
// time from a closed union (see ipam-queries.ts).
interface LooseClient {
  GET(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  POST(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  PATCH(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  DELETE(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
}
const inv = () => clients.inventory as unknown as LooseClient;

export const circuitKeys = {
  all: ['circuits'] as const,
  list: (route: CircuitRoute, query: Record<string, string | number>) => ['circuits', 'list', route, query] as const,
};

export interface CircuitPage<T> { rows: T[]; total: number }

/** One page of a circuit object list. `query` holds the server's filters. */
export function useCircuitList<R extends CircuitRoute>(
  route: R,
  query: Record<string, string | number> = {},
  opts: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: circuitKeys.list(route, query),
    enabled: opts.enabled ?? true,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }): Promise<CircuitPage<CircuitRows[R]>> => {
      const { data, error } = await inv().GET(`/circuits/${route}`, { signal, params: { query: { limit: 200, ...query } } });
      if (error || !data) throw new Error(ipamError(error, `Failed to load ${route.replace(/-/g, ' ')}`));
      const env = data as { data?: CircuitRows[R][]; pagination?: { total?: number } };
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

/** Create, edit or delete any circuit object; every circuit read is refetched. */
export function useCircuitWrite<R extends CircuitRoute>(route: R) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: circuitKeys.all });
  const create = useMutation({
    mutationFn: async (body: Record<string, unknown>): Promise<CircuitRows[R]> => {
      const { data, error } = await inv().POST(`/circuits/${route}`, { body });
      if (error || !data) throw new Error(ipamError(error, 'Could not create it'));
      return (data as { data: CircuitRows[R] }).data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }): Promise<CircuitRows[R]> => {
      const { data, error } = await inv().PATCH(`/circuits/${route}/{id}`, { params: { path: { id } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save it'));
      return (data as { data: CircuitRows[R] }).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await inv().DELETE(`/circuits/${route}/{id}`, { params: { path: { id } } });
      if (error) throw new Error(ipamError(error, 'Could not delete it'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

export const CIRCUIT_STATUS_LABEL: Record<Circuit['operational_status'], string> = {
  planned: 'Planned', provisioning: 'Provisioning', active: 'Active', offline: 'Offline',
  deprovisioning: 'Deprovisioning', decommissioned: 'Decommissioned',
};

export const CIRCUIT_STATUS_OPTIONS = (Object.keys(CIRCUIT_STATUS_LABEL) as Circuit['operational_status'][])
  .map((value) => ({ value, label: CIRCUIT_STATUS_LABEL[value] }));

/** A virtual circuit termination's role (NetBox VirtualCircuitTerminationRoleChoices). */
export const VC_ROLE_LABEL: Record<VirtualCircuitTermination['role'], string> = { peer: 'Peer', hub: 'Hub', spoke: 'Spoke' };
export const VC_ROLE_OPTIONS = (Object.keys(VC_ROLE_LABEL) as VirtualCircuitTermination['role'][])
  .map((value) => ({ value, label: VC_ROLE_LABEL[value] }));

/** What a termination may land on, with the label the editor shows. Sites,
 *  regions and site groups arrive with the sites row; the server refuses a
 *  kind whose table does not exist yet, so the editor offers what exists. */
export const TERMINATION_KIND_LABEL: Record<NonNullable<CircuitTermination['termination_kind']>, string> = {
  site: 'Site', location: 'Location', region: 'Region', site_group: 'Site group', provider_network: 'Provider network',
};

/** A rate in kbps as people say it: 100 Mbps, 10 Gbps. Unknown is "—", never 0. */
export function rateText(kbps: number | null | undefined): string {
  if (kbps === null || kbps === undefined) return '—';
  if (kbps >= 1_000_000 && kbps % 1_000_000 === 0) return `${kbps / 1_000_000} Gbps`;
  if (kbps >= 1_000) return `${Number.isInteger(kbps / 1_000) ? kbps / 1_000 : (kbps / 1_000).toFixed(1)} Mbps`;
  return `${kbps} kbps`;
}

/** One end of a circuit as the list shows it: "Provider network · Lumen core". */
export function terminationText(t: CircuitTerminationSummary | undefined): string {
  if (!t) return '—';
  if (!t.termination_kind) return 'Not connected';
  const kind = TERMINATION_KIND_LABEL[t.termination_kind];
  return t.termination_name ? `${t.termination_name}` : `${kind} (not visible)`;
}
