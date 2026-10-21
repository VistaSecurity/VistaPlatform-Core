// Query hooks for spares, stock and RMA (DCIM gap 8). A spare is an inventory
// item on no asset — at a stock location with a quantity and a stock state —
// so the stock list is /dcim/inventory-items?asset_id=null; the transitions
// (install, remove to stock, open an RMA) and the RMA cases are their own
// routes. Every write invalidates both the stock and the asset hardware lists,
// since an item crosses between them.
//
// SPARES_PATHS `satisfies` the generated client's path keys, so a path that
// leaves the spec fails typecheck.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError } from '../dcim/substrate-queries';
import { hardwareKeys, type InventoryItem } from '../dcim/hardware-queries';

export type RmaCase = components['schemas']['RmaCase'];
export type SpareResult = components['schemas']['SpareResult'];
export type StockState = InventoryItem['stock_state'];
export type RmaCaseState = RmaCase['state'];

export const SPARES_PATHS = [
  '/dcim/inventory-items', '/dcim/inventory-items/{id}', '/dcim/inventory-items/{id}/install',
  '/dcim/inventory-items/{id}/remove', '/dcim/inventory-items/{id}/rma', '/dcim/rma-cases', '/dcim/rma-cases/{id}',
] as const satisfies readonly (keyof inventoryPaths)[];

export const STOCK_STATE_LABELS: Record<StockState, string> = {
  installed: 'Installed', in_stock: 'In stock', reserved: 'Reserved', rma: 'Out for RMA', retired: 'Retired',
};
export const RMA_STATE_LABELS: Record<RmaCaseState, string> = {
  open: 'Open', shipped: 'Shipped', received: 'Replacement received', closed: 'Closed',
};
/** The next steps a case can take from each state (closed is final). */
export const RMA_NEXT: Record<RmaCaseState, RmaCaseState[]> = {
  open: ['shipped', 'received', 'closed'],
  shipped: ['received', 'closed'],
  received: ['shipped', 'closed'],
  closed: [],
};

interface Reply { data?: unknown; error?: unknown }
interface Loose {
  GET: (path: string, init?: object) => Promise<Reply>;
  POST: (path: string, init?: object) => Promise<Reply>;
  PATCH: (path: string, init?: object) => Promise<Reply>;
}
const api = (): Loose => clients.inventory as unknown as Loose;

export const SPARES_PAGE_SIZE = 500;

export const sparesKeys = {
  all: ['dcim-spares'] as const,
  stock: (f: SpareFilters) => ['dcim-spares', 'stock', f.siteId ?? '', f.state ?? ''] as const,
  cases: (open: boolean | null) => ['dcim-spares', 'rma-cases', open === null ? 'all' : String(open)] as const,
};

export class SpareWriteError extends Error {}

export interface SpareFilters { siteId?: string; state?: StockState | '' }

/** The spares: items on no asset, optionally at one site's locations or in one state. */
export function useSpares(f: SpareFilters = {}) {
  return useQuery({
    queryKey: sparesKeys.stock(f),
    queryFn: async (): Promise<InventoryItem[]> => {
      const query: Record<string, unknown> = { limit: SPARES_PAGE_SIZE, asset_id: 'null' };
      if (f.siteId) query.site_id = f.siteId;
      if (f.state) query.stock_state = f.state;
      const { data, error } = await api().GET('/dcim/inventory-items', { params: { query } });
      const env = data as { data?: InventoryItem[] } | undefined;
      if (error || !env) throw new Error(substrateError(error, 'Failed to load the spares'));
      return env.data ?? [];
    },
  });
}

/** RMA cases: open (not closed), closed, or all. */
export function useRmaCases(open: boolean | null = true) {
  return useQuery({
    queryKey: sparesKeys.cases(open),
    queryFn: async (): Promise<RmaCase[]> => {
      const query: Record<string, unknown> = { limit: SPARES_PAGE_SIZE };
      if (open !== null) query.open = String(open);
      const { data, error } = await api().GET('/dcim/rma-cases', { params: { query } });
      const env = data as { data?: RmaCase[] } | undefined;
      if (error || !env) throw new Error(substrateError(error, 'Failed to load the RMA cases'));
      return env.data ?? [];
    },
  });
}

/** One inventory item (an RMA case's unit), wherever it is. */
export function useInventoryItem(id: string | undefined) {
  return useQuery({
    queryKey: [...sparesKeys.all, 'item', id ?? ''],
    enabled: !!id,
    queryFn: async (): Promise<InventoryItem> => {
      const { data, error } = await api().GET('/dcim/inventory-items/{id}', { params: { path: { id } } });
      const env = data as { data?: InventoryItem } | undefined;
      if (error || !env?.data) throw new Error(substrateError(error, 'Failed to load the item'));
      return env.data;
    },
    staleTime: 30_000,
  });
}

function useInvalidateSpares() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: sparesKeys.all });
    void qc.invalidateQueries({ queryKey: ['dcim-hardware-objects'] });
  };
}

export interface SpareCreateInput {
  name: string;
  location_id: string;
  quantity: number;
  part_id?: string | null;
  serial?: string | null;
  manufacturer_id?: string | null;
  role_id?: string | null;
  stock_state?: 'in_stock' | 'reserved';
  description?: string | null;
}

export function useCreateSpare() {
  const invalidate = useInvalidateSpares();
  return useMutation({
    mutationFn: async (body: SpareCreateInput): Promise<InventoryItem> => {
      const { data, error } = await api().POST('/dcim/inventory-items', { body });
      const env = data as { data?: InventoryItem } | undefined;
      if (error || !env?.data) throw new SpareWriteError(substrateError(error, 'Failed to add the spare'));
      return env.data;
    },
    onSuccess: () => { toast.success('Spare added'); invalidate(); },
  });
}

/** PATCH a spare: reserve, un-reserve, retire, move shelves, recount. */
export function usePatchSpare() {
  const invalidate = useInvalidateSpares();
  return useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: Partial<Pick<InventoryItem, 'stock_state' | 'location_id' | 'quantity'>> }): Promise<InventoryItem> => {
      const { data, error } = await api().PATCH('/dcim/inventory-items/{id}', { params: { path: { id } }, body: patch });
      const env = data as { data?: InventoryItem } | undefined;
      if (error || !env?.data) throw new SpareWriteError(substrateError(error, 'Failed to update the spare'));
      return env.data;
    },
    onSuccess: () => invalidate(),
  });
}

export interface SpareInstallInput { asset_id: string; name?: string; quantity?: number }

export function useInstallSpare() {
  const invalidate = useInvalidateSpares();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: SpareInstallInput }): Promise<SpareResult> => {
      const { data, error } = await api().POST('/dcim/inventory-items/{id}/install', { params: { path: { id } }, body });
      const env = data as { data?: SpareResult } | undefined;
      if (error || !env?.data) throw new SpareWriteError(substrateError(error, 'Failed to install the spare'));
      return env.data;
    },
    onSuccess: () => { toast.success('Installed'); invalidate(); },
  });
}

export interface RemoveToStockInput { location_id: string; name?: string; stock_state?: 'in_stock' | 'reserved' }

export function useRemoveToStock(assetId?: string) {
  const invalidate = useInvalidateSpares();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: RemoveToStockInput }): Promise<SpareResult> => {
      const { data, error } = await api().POST('/dcim/inventory-items/{id}/remove', { params: { path: { id } }, body });
      const env = data as { data?: SpareResult } | undefined;
      if (error || !env?.data) throw new SpareWriteError(substrateError(error, 'Failed to remove the item to stock'));
      return env.data;
    },
    onSuccess: () => {
      toast.success('Moved to stock');
      invalidate();
      if (assetId) void qc.invalidateQueries({ queryKey: hardwareKeys.asset(assetId) });
    },
  });
}

export interface OpenRmaInput { vendor?: string; case_number?: string; notes?: string; location_id?: string | null }

export function useOpenRma(assetId?: string) {
  const invalidate = useInvalidateSpares();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: OpenRmaInput }): Promise<SpareResult> => {
      const { data, error } = await api().POST('/dcim/inventory-items/{id}/rma', { params: { path: { id } }, body });
      const env = data as { data?: SpareResult } | undefined;
      if (error || !env?.data) throw new SpareWriteError(substrateError(error, 'Failed to open the RMA case'));
      return env.data;
    },
    onSuccess: () => {
      toast.success('RMA case opened');
      invalidate();
      if (assetId) void qc.invalidateQueries({ queryKey: hardwareKeys.asset(assetId) });
    },
  });
}

export function useUpdateRmaCase() {
  const invalidate = useInvalidateSpares();
  return useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: Partial<Pick<RmaCase, 'state' | 'vendor' | 'case_number' | 'notes' | 'replacement_location_id'>> }): Promise<RmaCase> => {
      const { data, error } = await api().PATCH('/dcim/rma-cases/{id}', { params: { path: { id } }, body: patch });
      const env = data as { data?: RmaCase } | undefined;
      if (error || !env?.data) throw new SpareWriteError(substrateError(error, 'Failed to update the RMA case'));
      return env.data;
    },
    onSuccess: () => invalidate(),
  });
}

/** Units across rows (a box of 12 optics is one row of 12). */
export function unitCount(items: readonly InventoryItem[]): number {
  return items.reduce((n, i) => n + (i.quantity ?? 1), 0);
}
