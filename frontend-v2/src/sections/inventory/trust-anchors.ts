// Trust-anchor API helpers shared by Settings → Policies → Trusted CAs and the
// certificate drawer's Trust section. Both write the SAME store, so they
// share the query keys, the error wording and what a write invalidates: a
// decision made in the drawer must show up on the settings page and vice versa.
import { useQuery, type QueryClient } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type TrustAnchor = inventoryComponents['schemas']['TrustAnchor'];
export type TrustAnchorCertificate = inventoryComponents['schemas']['TrustAnchorCertificate'];
export type TrustDecision = TrustAnchor['decision'];
export type PublicRootsInfo = inventoryComponents['schemas']['PublicRootsInfo'];

export const TRUST_ANCHORS_KEY = ['trust-anchors'] as const;
export const PUBLIC_ROOTS_KEY = ['trust-anchors', 'public-roots'] as const;

/** Same limit the server enforces on `note`. */
export const TRUST_NOTE_MAX = 1000;

export const NO_TRUST_PERMISSION = "You don't have permission to change trust";

/**
 * A refused trust write, carrying the HTTP status so a caller can tell a 409
 * (a decision already exists — the server's `error` names it) from a 403.
 */
export class TrustWriteError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'TrustWriteError';
    this.status = status;
  }
}

function serverMessage(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'error' in error) {
    const e = (error as { error?: unknown }).error;
    if (typeof e === 'string' && e.trim()) return e;
  }
  return null;
}

/** Turns a failed openapi-fetch result into the one line the UI shows. */
export function trustWriteError(status: number, error: unknown, fallback: string): TrustWriteError {
  if (status === 403) return new TrustWriteError(403, NO_TRUST_PERMISSION);
  return new TrustWriteError(status, serverMessage(error) ?? fallback);
}

export function useTrustAnchors(enabled = true) {
  return useQuery({
    queryKey: TRUST_ANCHORS_KEY,
    enabled,
    queryFn: async (): Promise<TrustAnchor[]> => {
      const { data, error } = await clients.inventory.GET('/trust-anchors');
      if (error || !data) throw new Error('Failed to load trust decisions');
      return data.anchors ?? [];
    },
  });
}

export function usePublicRoots() {
  return useQuery({
    queryKey: PUBLIC_ROOTS_KEY,
    queryFn: async (): Promise<PublicRootsInfo> => {
      const { data, error } = await clients.inventory.GET('/trust-anchors/public-roots');
      if (error || !data) throw new Error('Failed to load the public root bundle');
      return data;
    },
    staleTime: 60 * 60_000, // changes once per release
  });
}

export async function createTrustAnchor(body: inventoryComponents['schemas']['TrustAnchorCreateRequest']): Promise<TrustAnchor> {
  const { data, error, response } = await clients.inventory.POST('/trust-anchors', { body });
  if (error || !response.ok || !data) throw trustWriteError(response.status, error, 'Could not record the decision');
  return data;
}

export async function updateTrustAnchor(id: string, body: inventoryComponents['schemas']['TrustAnchorUpdateRequest']): Promise<TrustAnchor> {
  const { data, error, response } = await clients.inventory.PUT('/trust-anchors/{id}', { params: { path: { id } }, body });
  if (error || !response.ok || !data) throw trustWriteError(response.status, error, 'Could not change the decision');
  return data;
}

export async function deleteTrustAnchor(id: string): Promise<void> {
  const { error, response } = await clients.inventory.DELETE('/trust-anchors/{id}', { params: { path: { id } } });
  if (error || !response.ok) throw trustWriteError(response.status, error, 'Could not remove the decision');
}

/**
 * Everything a trust decision can change. The server re-evaluates every
 * certificate chaining to the CA synchronously, so the drawer's chip, the
 * chain, the lens lists and the decisions table are all stale after a write.
 */
export function invalidateTrust(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: TRUST_ANCHORS_KEY });
  void qc.invalidateQueries({ queryKey: ['cert-detail'] });
  void qc.invalidateQueries({ queryKey: ['cert-chain'] });
  void qc.invalidateQueries({ queryKey: ['inventory', 'certs'] });
}

function cnOf(dn: string | undefined): string | null {
  if (!dn) return null;
  const m = dn.match(/(?:^|,)\s*CN=([^,]+)/);
  return m ? m[1] : null;
}

/** How a CA is named in the UI: common name, else the subject's CN, else the DN. */
export function caName(c: { common_name?: string | null; subject_dn?: string | null } | null | undefined): string {
  if (!c) return '—';
  // Empty strings count as absent here, which is why this is not a `??` chain.
  const first = [c.common_name, cnOf(c.subject_dn ?? undefined), c.subject_dn].find((v) => typeof v === 'string' && v.trim() !== '');
  return first ?? '—';
}

/** "AB:CD:…:EF"-style fingerprints shortened for a table cell. */
export function shortFingerprint(fp: string | null | undefined): string {
  if (!fp) return '—';
  const clean = fp.trim();
  return clean.length > 23 ? `${clean.slice(0, 11)}…${clean.slice(-8)}` : clean;
}

const PEM_MARKER = '-----BEGIN CERTIFICATE-----';

/** null when the text can be sent; otherwise why not. */
export function pemProblem(text: string): string | null {
  if (!text.trim()) return 'Paste a CA certificate or choose a file.';
  if (!text.includes(PEM_MARKER)) return `That is not a PEM certificate — it must contain ${PEM_MARKER}.`;
  return null;
}
