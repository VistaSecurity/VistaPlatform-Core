// Single-object reads for the object pages (DCIM gap 7) that no lens hook
// already makes: a VLAN, a circuit and an interface by id. Prefix and cable
// reuse `usePrefixDetail` / `useCable`. Every path is in the inventory-service
// spec; a 404 is surfaced as `NOT_FOUND` so a page can say "no longer exists".
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../../lib/clients';
import { ipamError, type Vlan } from '../ipam/ipam-queries';
import type { Circuit, CircuitTermination } from '../circuits/circuits-queries';
import type { Interface } from '../dcim/interface-queries';

export const NOT_FOUND = 'not-found';
export const isNotFound = (e: unknown): boolean => e instanceof Error && e.message === NOT_FOUND;

interface LooseClient {
  GET(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown; response?: { status?: number } }>;
}
const inv = () => clients.inventory as unknown as LooseClient;

async function getOne<T>(path: string, id: string, what: string): Promise<T> {
  const { data, error, response } = await inv().GET(path, { params: { path: { id } } });
  if (response?.status === 404) throw new Error(NOT_FOUND);
  const row = (data as { data?: T } | undefined)?.data;
  if (error || !row) throw new Error(ipamError(error, `Failed to load the ${what}`));
  return row;
}

export const objectKeys = {
  vlan: (id: string) => ['object-page', 'vlan', id] as const,
  circuit: (id: string) => ['object-page', 'circuit', id] as const,
  interface: (id: string) => ['object-page', 'interface', id] as const,
  vlanInterfaces: (id: string) => ['object-page', 'vlan-interfaces', id] as const,
  interfaceIps: (id: string) => ['object-page', 'interface-ips', id] as const,
};

export function useVlanById(id: string | undefined) {
  return useQuery({ queryKey: objectKeys.vlan(id ?? ''), enabled: !!id, queryFn: () => getOne<Vlan>('/ipam/vlans/{id}', id!, 'VLAN') });
}

export type CircuitDetailRow = Circuit & { provider_name?: string; type_name?: string };
export function useCircuitById(id: string | undefined) {
  return useQuery({ queryKey: objectKeys.circuit(id ?? ''), enabled: !!id, queryFn: () => getOne<CircuitDetailRow>('/circuits/circuits/{id}', id!, 'circuit') });
}

export function useInterfaceById(id: string | undefined) {
  return useQuery({ queryKey: objectKeys.interface(id ?? ''), enabled: !!id, queryFn: () => getOne<Interface>('/dcim/interfaces/{id}', id!, 'interface') });
}

/** The interfaces carrying a VLAN, untagged or tagged, across every asset. */
export function useVlanInterfaces(vlanId: string | undefined) {
  return useQuery({
    queryKey: objectKeys.vlanInterfaces(vlanId ?? ''),
    enabled: !!vlanId,
    queryFn: async (): Promise<{ rows: Interface[]; total: number }> => {
      const { data, error } = await inv().GET('/dcim/interfaces', { params: { query: { vlan: vlanId, limit: 200 } } });
      const env = data as { data?: Interface[]; pagination?: { total?: number } } | undefined;
      if (error || !env) throw new Error(ipamError(error, 'Failed to load the interfaces'));
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

export interface InterfaceIp { id: string; address: string; operational_status?: string; dns_name?: string | null }
/** The addresses assigned to one interface. */
export function useInterfaceAddresses(interfaceId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: objectKeys.interfaceIps(interfaceId ?? ''),
    enabled: !!interfaceId && enabled,
    queryFn: async (): Promise<InterfaceIp[]> => {
      const { data, error } = await inv().GET('/ipam/ip-addresses', { params: { query: { assigned_kind: 'interface', assigned_id: interfaceId, limit: 200 } } });
      const env = data as { data?: InterfaceIp[] } | undefined;
      if (error || !env) throw new Error(ipamError(error, 'Failed to load the addresses'));
      return env.data ?? [];
    },
  });
}

export type { CircuitTermination };
