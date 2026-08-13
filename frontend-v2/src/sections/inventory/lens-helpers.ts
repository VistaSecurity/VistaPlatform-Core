// Pure display-derivation helpers for the Inventory lenses, split out of
// inventory-page.tsx so they can be unit-tested directly (mirrors
// sections/dashboard/dashboard-metrics.ts). No React, no network — every
// function here takes plain data and returns plain data.
import { levelFromScore } from '../../components/ui';
import type { CryptoConfig } from './drawers';

// ---- Network lens: display-time CIDR match (#M-11) -----------------------
// Segments are matched to assets at INGEST time
// (services/inventory-service NetworkSegmentService.EnrichAssetByID, called
// from asset create/update) and the result is persisted to
// network_assets.network_segment_id — but a segment created AFTER an asset
// already exists never retroactively re-matches that asset, so
// `network_segment_name` stays null even though the asset's IP is visibly
// inside the segment's CIDR. Retroactively re-materializing
// network_segment_id for every existing asset whenever a segment is
// created/edited is a backend/product decision (it would also need to
// interact with auto_approve_discoveries rules keyed by network_segment_id)
// — out of scope here. This is the conservative fix: match at display time,
// grouping-only, so "Unsegmented" only holds assets that truly match no
// known segment.
export function ipv4ToInt(ip: string): number | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  if (!base || Number.isNaN(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt == null || baseInt == null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}
// Only `cidr`-type segments are matched here — `ip_range`/`domain` display-time
// matching is not implemented (open question, see PR description).
export function segmentForAsset(ip: string | null | undefined, segs: { name: string; segment_type?: string; value?: string }[]): string | null {
  if (!ip) return null;
  for (const seg of segs) {
    if (seg.segment_type === 'cidr' && seg.value && ipInCidr(ip, seg.value)) return seg.name;
  }
  return null;
}

// ---- Connections lens: raw-value cleanup (#L-1) ---------------------------
// Connection rows render raw source/dest IPs, which come back from the
// `inet`-typed source_ip/dest_ip columns and can carry an explicit host
// netmask suffix (/32 for IPv4, /128 for IPv6) baked into stored/ingested
// values ("192.0.2.173/32", "203.0.113.149/32:443"). Strip it for
// display — it's never meaningful for a single host address.
export function stripInetMask(v?: string | null): string | undefined {
  if (!v) return v ?? undefined;
  return v.replace(/\/(32|128)$/, '');
}
// A handful of already-ingested QUIC connections carry `protocol_version`
// values like "QUIC v1 ()" — a sensor bug (fixed in
// sensor/internal/capture/quic_parser.go) unconditionally appended
// " (<tls version>)" even when no TLS version was resolved. New discoveries
// won't reproduce this, but existing rows still have the baked-in empty
// parens, so strip it at display time too.
export function stripEmptyParens(v?: string | null): string | undefined {
  if (!v) return v ?? undefined;
  return v.replace(/\s*\(\s*\)\s*$/, '');
}

// ---- Configuration lens: strength grouping (#M-4) --------------------------
export type Strength = 'Weak' | 'Acceptable' | 'Strong' | 'Not assessed';
export const STRENGTH_META: Record<Strength, { color: string; icon: string }> = {
  Weak: { color: 'var(--danger)', icon: 'shield-x' },
  Acceptable: { color: 'var(--warn)', icon: 'shield' },
  Strong: { color: 'var(--ok)', icon: 'shield-check' },
  'Not assessed': { color: 'var(--app-t3)', icon: 'help-circle' },
};
export function strengthOfLevel(level: string): Exclude<Strength, 'Not assessed'> {
  const l = level.toLowerCase();
  if (l === 'critical' || l === 'high') return 'Weak';
  if (l === 'medium') return 'Acceptable';
  return 'Strong';
}
// A config with no resolved risk_score never went through the catalogue —
// score 0/null means NOT ASSESSED, not "safe" (see CLAUDE.md crypto-assessment
// source-of-truth section). levelFromScore(0) → 'Informational' →
// strengthOfLevel → 'Strong' used to fold these into the "Strong
// configurations" group alongside genuinely-assessed strong configs.
export function configStrength(c: CryptoConfig): Strength {
  const raw = (c as unknown as Record<string, unknown>).risk_score;
  if (typeof raw !== 'number' || raw === 0) return 'Not assessed';
  return strengthOfLevel(levelFromScore(raw));
}
export const ENV_OPTS = ['All', 'Production', 'Staging', 'Development', 'Test'];
export const RISK_OPTS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Informational'];
export const STRENGTH_OPTS = ['All', 'Weak', 'Acceptable', 'Strong', 'Not assessed'];

// ---- Keys lens: Algorithm cell fallback (#L-8) -----------------------------
// algorithm_ref (the joined catalogue algorithm name) is null for keys the
// catalogue hasn't resolved — e.g. a CA key extracted straight from a
// certificate. Falling back to key_type (the key's algorithm FAMILY, e.g.
// "ECDSA") keeps the Algorithm cell from silently dropping to just the size
// ("256-bit") while the row title still shows "ECDSA · 256-bit".
export function keyAlgorithmLabel(algorithmRef: string | null | undefined, keyType: string | null | undefined, sizeLabel: string): string {
  return [algorithmRef || keyType, sizeLabel].filter(Boolean).join(' · ') || '—';
}
