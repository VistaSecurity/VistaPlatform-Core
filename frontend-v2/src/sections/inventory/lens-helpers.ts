// Pure display-derivation helpers for the Inventory lenses, split out of
// inventory-page.tsx so they can be unit-tested directly (mirrors
// sections/dashboard/dashboard-metrics.ts). No React, no network — every
// function here takes plain data and returns plain data.
import type { CryptoConfig } from './drawers';
import { cryptoRiskPresentation } from './crypto-risk-presentation';

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

// ---- Configuration lens: numeric risk grouping (#M-4) ----------------------
export type ConfigurationRiskGroup = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Not assessed';
export const CONFIGURATION_RISK_META: Record<ConfigurationRiskGroup, { color: string; icon: string }> = {
  Critical: { color: 'var(--danger)', icon: 'shield-x' },
  High: { color: 'var(--warn-strong)', icon: 'shield-x' },
  Medium: { color: 'var(--warn)', icon: 'shield' },
  Low: { color: 'var(--ok-lime)', icon: 'shield-check' },
  Informational: { color: 'var(--info)', icon: 'info' },
  'Not assessed': { color: 'var(--app-t3)', icon: 'help-circle' },
};
export function configurationRiskGroup(c: CryptoConfig): ConfigurationRiskGroup {
  const risk = cryptoRiskPresentation(c);
  return risk.assessed ? risk.level : 'Not assessed';
}
const CONFIGURATION_RISK_ORDER: ConfigurationRiskGroup[] = ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Not assessed'];
export function groupConfigurationsByRisk(configs: CryptoConfig[]) {
  return CONFIGURATION_RISK_ORDER
    .map((riskGroup) => ({ riskGroup, list: configs.filter((config) => configurationRiskGroup(config) === riskGroup) }))
    .filter((group) => group.list.length > 0);
}
export const ENV_OPTS = ['All', 'Production', 'Staging', 'Development', 'Test'];
export const RISK_OPTS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Informational'];
export const CONFIGURATION_RISK_OPTS = [...RISK_OPTS, 'Not assessed'];
export function effectiveInventoryRiskFilter(stored: string, isConfigurationLens: boolean): string {
  return stored === 'Not assessed' && !isConfigurationLens ? 'All' : stored;
}

// ---- Keys lens: Algorithm cell fallback (#L-8) -----------------------------
// algorithm_ref (the joined catalogue algorithm name) is null for keys the
// catalogue hasn't resolved — e.g. a CA key extracted straight from a
// certificate. Falling back to key_type (the key's algorithm FAMILY, e.g.
// "ECDSA") keeps the Algorithm cell from silently dropping to just the size
// ("256-bit") while the row title still shows "ECDSA · 256-bit".
export function keyAlgorithmLabel(algorithmRef: string | null | undefined, keyType: string | null | undefined, sizeLabel: string): string {
  return [algorithmRef || keyType, sizeLabel].filter(Boolean).join(' · ') || '—';
}

// ---- Keys lens: key custody ------------------------------------------------
// WHO HOLDS the key. A cloud KMS key discovered through a cloud integration
// carries `key_custody`: 'customer' for a customer-managed CMK, 'provider' for
// an AWS-managed `aws/s3`-style key. Everything else — every certificate-derived
// key, and any cloud key whose manager the provider did not report — has it
// absent, and absent is NOT a third answer meaning "provider": it means the
// question was not answered, so the cell renders nothing at all rather than a
// guess. Same three-valued honesty as the Data Protection lens's
// `custody-unknown` rung, which is the other half of this signal.
export type KeyCustody = 'customer' | 'provider';

export const KEY_CUSTODY_LABEL: Record<KeyCustody, string> = {
  customer: 'Customer-managed',
  provider: 'Provider-managed',
};

export const KEY_CUSTODY_DETAIL: Record<KeyCustody, string> = {
  customer: 'You control this key: its policy, its rotation, and whether it can be used at all.',
  provider: 'The cloud provider holds this key. It is encrypted at rest, but you do not control the key or its policy.',
};

/** The custody badge for a key row, or null when custody was not established. */
export function keyCustodyLabel(custody: string | null | undefined): string | null {
  if (custody === 'customer' || custody === 'provider') return KEY_CUSTODY_LABEL[custody];
  return null;
}

/** The hover text for the custody badge, or null when there is no badge. */
export function keyCustodyDetail(custody: string | null | undefined): string | null {
  if (custody === 'customer' || custody === 'provider') return KEY_CUSTODY_DETAIL[custody];
  return null;
}

// ---- Endpoint service identification -------------------------------------
// The asset-row derivations that used to live here (assetIdentity, assetLocation,
// assetService, assetRisk, protocolBadges, the counts and the status badge) moved
// to `asset-shape.ts` when ADR-0002 replaced the flat asset row: they all read
// `ip_address`, `port`, `asset_type` and `operating_system`, none of which are
// columns any more. What stayed is this one, which is about an ENDPOINT's service
// and is as true as it ever was.

const clean = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** How sure we are of the service name, and why.
 *
 *  The backend has always sent this — `service_confidence` (high/medium/low)
 *  and `service_identification_method` (banner/ja3s/port_heuristic/http_header/
 *  manual) ride along with every asset — and nothing rendered them, so a name
 *  inferred from nothing but a port number appeared exactly as certain as one
 *  read out of a server banner.
 *
 *  We will never be at 100%, so the honest thing is to say which it is. Returns
 *  a short qualifier for the drawer's Service row plus a fuller `title` for the
 *  hover. Both are null when the backend sent no method — an older row, or an
 *  operator-entered name from before those columns were populated — because
 *  inventing a confidence for it would be the same overclaim in reverse. */
const CONFIDENCE_WORD: Record<string, string> = {
  high: 'Confirmed',
  medium: 'Likely',
  low: 'Best guess',
};
const METHOD_SOURCE: Record<string, string> = {
  banner: 'from banner',
  ja3s: 'from TLS fingerprint',
  port_heuristic: 'from port',
  http_header: 'from HTTP header',
};
const METHOD_TITLE: Record<string, string> = {
  banner: 'The service announced itself in its banner.',
  ja3s: 'Matched on the TLS handshake fingerprint, not on anything the service said.',
  port_heuristic: 'Inferred from the port number alone. The port is the only evidence, so treat the name as a guess.',
  http_header: 'Read from an HTTP response header.',
  manual: 'Entered by a user, not discovered.',
};
export function serviceConfidence(a: { service_confidence?: string | null; service_identification_method?: string | null }):
  { qualifier: string | null; title: string | null } {
  const method = clean(a.service_identification_method).toLowerCase();
  if (!method) return { qualifier: null, title: null };
  if (method === 'manual') {
    return { qualifier: 'Set manually', title: METHOD_TITLE.manual };
  }
  const word = CONFIDENCE_WORD[clean(a.service_confidence).toLowerCase()];
  const source = METHOD_SOURCE[method];
  if (!word && !source) return { qualifier: null, title: null };
  return {
    qualifier: [word, source].filter(Boolean).join(' · ') || null,
    title: METHOD_TITLE[method] ?? null,
  };
}
