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

// ---- Infrastructure lens: Tier-1 row segments ------------------------------
// The Infrastructure row is a DENSE table row, not a card: eight segments that
// each answer one question at a glance (INVENTORY_LENS_ARCHITECTURE.md, Tier 1).
// Every derivation below is pure so it can be tested against the case that
// motivated this work — a sensor-discovered asset where hostname, asset_type,
// operating_system, environment, segment and service are ALL null.
//
// The governing rule for those: a field the service does not know renders as an
// explicit absence ('—' / nothing), never as a confident-looking value. That is
// the same honesty the score-0 convention demands (see CLAUDE.md, "The
// catalogue drives risk scoring": score 0 means NOT ASSESSED, not "safe").

/** Minimal read-only shape the row derivations need. Deliberately not `Asset`
 *  so these stay testable with plain literals. */
export interface InfraRowAsset {
  hostname?: string | null;
  ip_address?: string | null;
  port?: number | null;
  asset_type?: string | null;
  operating_system?: string | null;
  environment?: string | null;
  network_segment_name?: string | null;
  business_unit?: string | null;
  site?: string | null;
  region?: string | null;
  service_name?: string | null;
  service_version?: string | null;
  asset_status?: string | null;
  stale_status?: string | null;
  last_seen_at?: string | null;
  risk_score?: unknown;
  risk_level?: string | null;
  certificate_count?: unknown;
  crypto_implementation_count?: unknown;
  protocol_summary?: { protocol: string; count: number; max_risk_score: number }[] | null;
}

const clean = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** Identity segment: what this thing IS. Hostname when known, otherwise the
 *  address — never a fabricated placeholder. The sub-line carries the address
 *  (when the title took the hostname) plus type/OS, and is EMPTY when none of
 *  those are known rather than repeating the title. */
export function assetIdentity(a: InfraRowAsset): { primary: string; secondary: string } {
  const host = clean(a.hostname);
  const ip = stripInetMask(clean(a.ip_address)) ?? '';
  const addr = ip ? (a.port ? `${ip}:${a.port}` : ip) : '';
  const primary = host || addr || '—';
  const secondary = [host && addr ? addr : '', clean(a.asset_type), clean(a.operating_system)]
    .filter(Boolean).join(' · ');
  return { primary, secondary };
}

/** Location segment: environment badge + where it lives. Returns null for the
 *  path when nothing is known — the cell then shows '—', which reads as
 *  "unknown", not as "no segment". */
export function assetLocation(a: InfraRowAsset): { environment: string | null; path: string | null } {
  const geo = [clean(a.site), clean(a.region)].filter(Boolean).join('/');
  const path = [clean(a.network_segment_name) || clean(a.business_unit), geo].filter(Boolean).join(' · ');
  return { environment: clean(a.environment) || null, path: path || null };
}

/** Service segment. A version with no service name is not a service, so both
 *  collapse to null together rather than rendering a bare "v1.2.3". */
export function assetService(a: InfraRowAsset): { name: string | null; version: string | null } {
  const name = clean(a.service_name);
  if (!name) return { name: null, version: null };
  const version = clean(a.service_version);
  return { name, version: version ? `v${version.replace(/^v/i, '')}` : null };
}

/** Risk segment. `assessed` is the load-bearing flag: a score of 0 means the
 *  asset resolved NOTHING against the algorithms catalogue and no size rule
 *  fired. It must not be presented as a low-risk result. */
export interface AssetRisk { score: number; level: string; assessed: boolean; label: string; title: string }
export function assetRisk(a: InfraRowAsset): AssetRisk {
  const score = typeof a.risk_score === 'number' && Number.isFinite(a.risk_score) ? a.risk_score : 0;
  const assessed = score > 0;
  const level = assessed ? (clean(a.risk_level) || levelFromScore(score)) : 'Informational';
  return {
    score,
    level,
    assessed,
    label: assessed ? String(score) : '—',
    title: assessed
      ? `Risk score ${score} · ${level}`
      : 'Not assessed — nothing on this asset resolved against the algorithm catalogue',
  };
}

/** Crypto summary: protocol badges + the configuration count.
 *
 *  Badges come from the LIST payload's `protocol_summary` — deliberately NOT
 *  from the per-asset child query, which is lazy-loaded on expand. Firing that
 *  query for every visible row would be a 50-request waterfall per page.
 *
 *  A badge's tone follows the worst score seen for that protocol, banded with
 *  the SAME ladder as everything else (levelFromScore); `assessed: false`
 *  (max_risk_score 0) stays neutral instead of claiming "Informational". */
export interface ProtocolBadge { label: string; count: number; level: string; assessed: boolean; title: string }
export function protocolBadges(a: InfraRowAsset, max = 3): { badges: ProtocolBadge[]; overflow: number } {
  const rows = Array.isArray(a.protocol_summary) ? a.protocol_summary : [];
  const badges = rows
    .filter((p) => clean(p.protocol))
    .map((p) => {
      const score = typeof p.max_risk_score === 'number' ? p.max_risk_score : 0;
      const assessed = score > 0;
      const label = clean(p.protocol);
      const n = typeof p.count === 'number' ? p.count : 0;
      return {
        label,
        count: n,
        level: assessed ? levelFromScore(score) : 'Informational',
        assessed,
        title: assessed
          ? `${label}: ${n} configuration${n === 1 ? '' : 's'}, worst risk ${score} (${levelFromScore(score)})`
          : `${label}: ${n} configuration${n === 1 ? '' : 's'}, not assessed`,
      };
    });
  return { badges: badges.slice(0, max), overflow: Math.max(0, badges.length - max) };
}

/** "N cfg" count. Returns null when the field is absent (an older service that
 *  doesn't send it) so the row omits the count rather than asserting zero. */
export function configCount(a: InfraRowAsset): number | null {
  return typeof a.crypto_implementation_count === 'number' ? a.crypto_implementation_count : null;
}

/** Certificate count. 0 IS a known fact here (the list query always counts), so
 *  unlike the config count this renders as a real zero. */
export function certCount(a: InfraRowAsset): number {
  return typeof a.certificate_count === 'number' ? a.certificate_count : 0;
}

/** Status segment: only ABNORMAL states earn a badge. `monitoring` is the
 *  steady state — badging it would add noise to every row and bury the
 *  pending/archived rows the badge exists to surface. */
export function assetStatusBadge(a: InfraRowAsset): { text: string; tone: string } | null {
  const stale = clean(a.stale_status);
  if (stale === 'archived') return { text: 'archived', tone: 'var(--neutral)' };
  const status = clean(a.asset_status);
  if (status === 'pending_approval') return { text: 'pending', tone: 'var(--warn)' };
  if (status && status !== 'monitoring') return { text: status.replace(/_/g, ' '), tone: 'var(--warn-strong)' };
  if (stale === 'warning') return { text: 'stale', tone: 'var(--warn)' };
  return null;
}

/** Relative "last seen". Coarser than an exact timestamp on purpose — the row
 *  answers "recently or not", the drawer answers "exactly when". */
export function relativeTime(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  // Go's zero time ("0001-01-01T00:00:00Z") reaches the UI as a real date on
  // rows that were never actually seen. Rendering it as "24237mo ago" would be
  // a confident answer to a question we can't answer — say '—' instead.
  if (!Number.isFinite(t) || t <= 0) return '—';
  const mins = Math.floor((Date.now() - t) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}
