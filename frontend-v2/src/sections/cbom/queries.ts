// Live queries + mutations for the CBOM section. Everything talks to the typed
// cbom-service client (lib/clients.ts) — no hand-written fetches. The cbom-service
// schemas are the root `components` export of the contract package (see ADR-0001).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import type { components } from '@vistasecurity/api-contract';

export type CBOMArtifact = components['schemas']['CBOMArtifact'];
export type Scope = components['schemas']['Scope'];
export type DiffResult = components['schemas']['DiffResult'];
export type DiffChange = components['schemas']['DiffChange'];
export type VerifyResponse = components['schemas']['VerifyResponse'];
export type Layer = components['schemas']['Layer'];

/** Display name for an artifact — its given name, or "<scope> — <date>". */
export function artifactName(a: CBOMArtifact): string {
  if (a.name && a.name.trim()) return a.name;
  return `${a.scope_name_snapshot} — ${a.generated_at.slice(0, 10)}`;
}

/** The tenant's artifacts, newest first (server orders by generated_at DESC).
 *  Core route — `enabled` exists only so a gated page (Compare) can avoid a
 *  pointless fetch it will never render. */
export function useArtifacts(scopeId?: string, enabled = true) {
  return useQuery({
    queryKey: ['cbom', 'artifacts', scopeId ?? 'all'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.cbom.GET('/cbom/artifacts', {
        params: { query: scopeId ? { scope_id: scopeId } : {} },
      });
      if (error || !data) throw new Error('Failed to load CBOM artifacts');
      return data.artifacts ?? [];
    },
    staleTime: 30_000,
  });
}

/** A single artifact's full metadata (hash, signature, provenance, layers). */
export function useArtifact(id: string | undefined) {
  return useQuery({
    queryKey: ['cbom', 'artifact', id],
    enabled: !!id,
    queryFn: async () => {
      const { data, error } = await clients.cbom.GET('/cbom/artifacts/{id}', { params: { path: { id: id! } } });
      if (error || !data) throw new Error('Failed to load artifact');
      return data;
    },
  });
}

/** Tenant scopes — the boundary picker for generation. Seeds system defaults. */
export function useScopes() {
  return useQuery({
    queryKey: ['cbom', 'scopes'],
    queryFn: async () => {
      const { data, error } = await clients.cbom.GET('/scopes', {});
      if (error || !data) throw new Error('Failed to load scopes');
      return data.scopes ?? [];
    },
    staleTime: 60_000,
  });
}

/** Generate a new immutable artifact from a scope. Server defaults sign +
 *  include_attestation to true (audit-ready by default). */
export function useGenerate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { scope_id: string; name?: string }) => {
      const { data, error } = await clients.cbom.POST('/cbom/generate', { body });
      if (error || !data) throw new Error(error?.error ?? 'CBOM generation failed');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cbom', 'artifacts'] }),
  });
}

/** Soft-delete an artifact. 204 No Content → gate on response.ok, not error
 *  (openapi-fetch returns a falsy error on an empty body). */
export function useDeleteArtifact() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.cbom.DELETE('/cbom/artifacts/{id}', { params: { path: { id } } });
      if (!response.ok) throw new Error(error?.error ?? 'Delete failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cbom', 'artifacts'] }),
  });
}

/** Recompute hash (and signature, if signed) for tamper-evidence. */
export function useVerify() {
  return useMutation({
    mutationFn: async (id: string): Promise<VerifyResponse> => {
      const { data, error } = await clients.cbom.POST('/cbom/artifacts/{id}/verify', { params: { path: { id } } });
      if (error || !data) throw new Error('Verification failed');
      return data;
    },
  });
}

/**
 * Deterministic diff of two artifacts (URL form → deep-linkable).
 *
 * `/cbom/compare/**` lives in cbom-service/ee/diff — a Core build never mounts
 * it. Callers pass the resolved `cbom_signing` entitlement so the request is
 * skipped rather than fired-and-404'd.
 */
export function useCompare(base?: string, head?: string, entitled = true) {
  return useQuery({
    queryKey: ['cbom', 'compare', base, head],
    enabled: entitled && !!base && !!head && base !== head,
    queryFn: async () => {
      const { data, error } = await clients.cbom.GET('/cbom/compare/{base}/{head}', {
        params: { path: { base: base!, head: head! } },
      });
      if (error || !data) throw new Error(error?.error ?? 'Comparison failed');
      return data;
    },
  });
}

/** Download the canonical CycloneDX 1.6 bytes and save them client-side.
 *  Uses parseAs:'blob' so a 302 to a presigned URL (object-stored artifacts)
 *  and an inline byte stream (dev) are handled the same way. SPDX/PDF are
 *  not yet wired server-side, so only CycloneDX is offered. */
export async function downloadArtifact(a: CBOMArtifact): Promise<void> {
  const { data, response } = await clients.cbom.GET('/cbom/artifacts/{id}/download', {
    params: { path: { id: a.id }, query: { format: 'cyclonedx' } },
    parseAs: 'blob',
  });
  if (!response.ok || !data) throw new Error('Download failed');
  const blob = data as unknown as Blob;
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const base = (a.name?.trim() || a.scope_name_snapshot || 'cbom').replace(/[^\w.-]+/g, '_');
  link.href = url;
  link.download = `${base}.cyclonedx.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
