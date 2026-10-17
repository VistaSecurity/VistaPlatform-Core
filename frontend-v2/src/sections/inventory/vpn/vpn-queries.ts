// Query hooks for the VPN objects (DCIM BUILD_PLAN row 4.3; ADR-0010 D8):
// Inventory → Tunnels and Settings → VPN Policies. Every path is in the
// inventory-service spec (`/vpn/...`) and goes through the generated client.
// The ten objects share the IPAM object engine's CRUD shape, so the shared
// object editors (ObjectFormModal) write through useVpnWrite.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { riskLevelFromScore } from '@vistasecurity/primitives/ratings';
import { clients } from '../../../lib/clients';
import { ipamError } from '../ipam/ipam-queries';

type S = components['schemas'];
export type Tunnel = S['Tunnel'];
export type TunnelGroup = S['TunnelGroup'];
export type IkeProposal = S['IkeProposal'];
export type IkePolicy = S['IkePolicy'];
export type IpsecProposal = S['IpsecProposal'];
export type IpsecPolicy = S['IpsecPolicy'];
export type IpsecProfile = S['IpsecProfile'];
export type VpnAlgorithmAssessment = S['VpnAlgorithmAssessment'];

/** Row type per route segment. */
export interface VpnRows {
  'tunnel-groups': TunnelGroup;
  tunnels: Tunnel;
  'tunnel-terminations': S['TunnelTermination'];
  'ike-proposals': IkeProposal;
  'ike-policies': IkePolicy;
  'ipsec-proposals': IpsecProposal;
  'ipsec-policies': IpsecPolicy;
  'ipsec-profiles': IpsecProfile;
  l2vpns: S['L2vpn'];
  'l2vpn-terminations': S['L2vpnTermination'];
}
export type VpnRoute = keyof VpnRows;

interface LooseClient {
  GET(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  POST(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  PATCH(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  DELETE(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
}
const inv = () => clients.inventory as unknown as LooseClient;

export const vpnKeys = {
  all: ['vpn'] as const,
  list: (route: VpnRoute, query: Record<string, string | number>) => ['vpn', 'list', route, query] as const,
};

/** One page of a VPN object list. */
export function useVpnList<R extends VpnRoute>(route: R, query: Record<string, string | number> = {}) {
  return useQuery({
    queryKey: vpnKeys.list(route, query),
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }): Promise<{ rows: VpnRows[R][]; total: number }> => {
      const { data, error } = await inv().GET(`/vpn/${route}`, { signal, params: { query: { limit: 200, ...query } } });
      if (error || !data) throw new Error(ipamError(error, `Failed to load ${route.replace(/-/g, ' ')}`));
      const env = data as { data?: VpnRows[R][]; pagination?: { total?: number } };
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

/** Create, edit or delete any VPN object; every VPN read is refetched. The
 *  ObjectWrite shape the shared object editors (ipam-ui) write through. */
export function useVpnWrite<R extends VpnRoute>(route: R) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: vpnKeys.all });
  const create = useMutation({
    mutationFn: async (body: Record<string, unknown>): Promise<VpnRows[R]> => {
      const { data, error } = await inv().POST(`/vpn/${route}`, { body });
      if (error || !data) throw new Error(ipamError(error, 'Could not create it'));
      return (data as { data: VpnRows[R] }).data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }): Promise<VpnRows[R]> => {
      const { data, error } = await inv().PATCH(`/vpn/${route}/{id}`, { params: { path: { id } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save it'));
      return (data as { data: VpnRows[R] }).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await inv().DELETE(`/vpn/${route}/{id}`, { params: { path: { id } } });
      if (error) throw new Error(ipamError(error, 'Could not delete it'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

export const ENCAPSULATION_LABEL: Record<Tunnel['encapsulation'], string> = {
  'ipsec-transport': 'IPsec (transport)', 'ipsec-tunnel': 'IPsec (tunnel)', 'ip-ip': 'IP-in-IP', gre: 'GRE',
  wireguard: 'WireGuard', l2tp: 'L2TP', pptp: 'PPTP', openvpn: 'OpenVPN',
};

export const PQC_LABEL: Record<Tunnel['pqc_status'], string> = {
  needs_migration: 'Needs PQC migration', pqc_ready: 'PQC ready', symmetric_safe: 'Symmetric only', unclassified: 'Not classified',
};

/** The band of a catalogue risk score, or null when nothing scored it —
 *  unassessed is never shown as Informational. */
export function riskBand(score: number | null | undefined): string | null {
  return typeof score === 'number' && Number.isFinite(score) ? riskLevelFromScore(score) : null;
}
