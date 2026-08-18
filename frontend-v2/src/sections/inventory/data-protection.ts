// Data Protection lens — at-rest encryption posture.
//
// Pure derivation helpers, split out of the page (mirrors lens-helpers.ts) so
// the two things that would silently regress — the THREE-state verdict and the
// custody LADDER — are unit-tested rather than eyeballed.
//
// Why this is a lens and not a new top-level Inventory area: the real
// distinction is PROTECTION MODE (keyed-and-durable at rest vs
// negotiated-and-ephemeral in transit), which is a property of a resource, not
// a place in a tree. Users ask cross-cutting questions ("what is unencrypted?"),
// so the resource family (bucket / database / KMS key) is a column, not a nav.
import type { inventoryComponents, inventoryOperations } from '@vistasecurity/api-contract';
import { levelFromScore, riskColor, type RiskLevel } from '../../components/ui';

// ---- API shape ------------------------------------------------------------
// Bound to the GENERATED contract type so a field rename breaks the build here
// instead of silently rendering blanks. It is wrapped in Partial<> on purpose:
// every derivation below must tolerate an ABSENT field (a missing
// `encryption_determined` has to fall to "not assessed", never to a verdict),
// and the row objects in tests are built field-by-field.
export type CryptoApplication = Partial<inventoryComponents['schemas']['CryptoApplication']> & {
  id: string;
  // Detail-only extras the drawer shows if the backend starts sending them;
  // not in the contract yet, so optional and absent-tolerant.
  bucket_key_enabled?: boolean | null;
  engine?: string | null;
  engine_version?: string | null;
};

export type CryptoApplicationList = Partial<inventoryComponents['schemas']['CryptoApplicationsResponse']>;

// ---- 1. THREE states, never two -------------------------------------------
// `encrypted: true`, `encrypted: false` and "we could not determine" are three
// different answers. An AccessDenied on the encryption read must NEVER paint as
// either verdict — it is NOT ASSESSED (same honesty as risk score 0 and the PQC
// `unclassified` bucket). Collapsing it would make a missing IAM grant read as
// a clean result, which is the worst thing this lens could do.
export type AtRestState = 'encrypted' | 'unencrypted' | 'not-assessed';

// The param type is deliberately WIDER than the contract (which declares both
// booleans non-nullable): JSON can still deliver null, and a null must land on
// "not assessed" rather than crashing through a type assumption.
export function atRestState(a: { encrypted?: boolean | null; encryption_determined?: boolean | null }): AtRestState {
  // Determined must be an explicit true. Anything else — false, null, absent —
  // means we did not establish an answer, so we do not render one.
  if (a.encryption_determined !== true) return 'not-assessed';
  if (a.encrypted === true) return 'encrypted';
  if (a.encrypted === false) return 'unencrypted';
  // Determined-but-no-boolean is incoherent; fail to the honest state.
  return 'not-assessed';
}

// ---- 2. Encryption is a LADDER, not a bit ---------------------------------
// Unencrypted → provider-managed key (encrypted, but the customer does not hold
// the key) → customer-managed KMS key. A green tick for SSE-S3 beside a green
// tick for SSE-KMS would hide a difference that matters.
//
// `custody-unknown` exists because "encrypted with a KMS key" does not by
// itself say WHOSE key: an AWS-managed `aws/s3` key is SSE-KMS too. When the
// backend cannot attribute custody we say so instead of guessing upward.
export type ProtectionRung = 'not-assessed' | 'unencrypted' | 'provider-managed' | 'custody-unknown' | 'customer-managed';

export const RUNG_ORDER: ProtectionRung[] = ['not-assessed', 'unencrypted', 'provider-managed', 'custody-unknown', 'customer-managed'];

export function protectionRung(a: CryptoApplication): ProtectionRung {
  const state = atRestState(a);
  if (state === 'not-assessed') return 'not-assessed';
  if (state === 'unencrypted') return 'unencrypted';
  if (a.key_manager === 'customer') return 'customer-managed';
  if (a.key_manager === 'provider') return 'provider-managed';
  // No custody attribution from the backend: SSE-S3 is provider-managed by
  // definition; the KMS variants could be either, so they stay unknown.
  const t = (a.encryption_type ?? '').toLowerCase();
  if (t === 'sse-s3') return 'provider-managed';
  return 'custody-unknown';
}

// Representative score per rung, run through the SHARED band ladder
// (components/ui/risk.ts levelFromScore) so the rung's colour and severity word
// come from the same CVSS-anchored bands the rest of the app uses. Nothing here
// hand-writes a threshold or a colour — change the bands and this follows.
//   unencrypted 90 → Critical · provider-managed 40 → Medium · customer 10 → Low
const RUNG_SCORE: Record<Exclude<ProtectionRung, 'not-assessed'>, number> = {
  unencrypted: 90,
  'provider-managed': 40,
  'custody-unknown': 40,
  'customer-managed': 10,
};

export function rungLevel(rung: ProtectionRung): RiskLevel {
  if (rung === 'not-assessed') return 'Informational';
  return levelFromScore(RUNG_SCORE[rung]);
}

export const rungColor = (rung: ProtectionRung): string => riskColor(rungLevel(rung));

export interface RungMeta {
  /** Row badge text. */
  label: string;
  /** One line explaining what the rung means, used as the badge tooltip. */
  detail: string;
  icon: string;
  /** Filled segments of the 3-rung custody meter; 0 = nothing claimed. */
  filled: number;
}

export const RUNG_META: Record<ProtectionRung, RungMeta> = {
  'not-assessed': {
    label: 'Not assessed',
    detail: 'The encryption setting could not be read (for example the discovery credential lacked permission). This is NOT a statement that the resource is encrypted.',
    icon: 'circle-help',
    filled: 0,
  },
  unencrypted: {
    label: 'Unencrypted',
    detail: 'No server-side encryption at rest.',
    icon: 'shield-x',
    filled: 1,
  },
  'provider-managed': {
    label: 'Provider key',
    detail: 'Encrypted with a key the cloud provider owns and rotates. You cannot revoke, audit, or scope access to it.',
    icon: 'shield',
    filled: 2,
  },
  'custody-unknown': {
    label: 'Key owner unknown',
    detail: 'Encrypted, but we could not establish whether the KMS key is yours or the provider’s.',
    icon: 'circle-help',
    filled: 2,
  },
  'customer-managed': {
    label: 'Customer key',
    detail: 'Encrypted with a KMS key you control — you can rotate, scope and revoke it.',
    icon: 'shield-check',
    filled: 3,
  },
};

// ---- Row risk badge --------------------------------------------------------
// Same rule as every other lens: prefer the server's banded level, fall back to
// the shared levelFromScore. Never band locally from a threshold of our own.
export function rowRiskLevel(a: CryptoApplication): RiskLevel {
  const lvl = (a.risk_level ?? '') as RiskLevel;
  if (lvl) return lvl;
  return levelFromScore(typeof a.risk_score === 'number' ? a.risk_score : 0);
}

// ---- Display labels --------------------------------------------------------
const RESOURCE_LABEL: Record<string, string> = {
  cloud_storage: 'Object storage',
  database: 'Database',
  kms_key: 'KMS key',
  disk: 'Disk',
  file_system: 'File system',
};

export const resourceTypeLabel = (t?: string | null): string =>
  (t ? RESOURCE_LABEL[t] ?? t.replace(/_/g, ' ') : '—');

const ENCRYPTION_TYPE_LABEL: Record<string, string> = {
  'sse-s3': 'SSE-S3',
  'sse-kms': 'SSE-KMS',
  'sse-kms-dsse': 'DSSE-KMS',
  unknown: 'Unknown',
};

export const encryptionTypeLabel = (t?: string | null): string =>
  (t ? ENCRYPTION_TYPE_LABEL[t.toLowerCase()] ?? t.toUpperCase() : '—');

/** Empty-string-aware fallback (`??` keeps "", which renders as a blank cell). */
export function orText(v: string | null | undefined, fallback: string): string {
  if (v === null || v === undefined || v === '') return fallback;
  return v;
}

/** "aws · us-east-1" — where the record came from, so a finding is actionable. */
export const originLabel = (a: CryptoApplication): string =>
  [a.cloud_provider, a.cloud_region].filter(Boolean).join(' · ') || '—';

// ---- Filters ---------------------------------------------------------------
export const RESOURCE_TYPE_OPTS = ['All', 'Object storage', 'Database'];
const RESOURCE_TYPE_PARAM: Record<string, ResourceTypeParam> = {
  'Object storage': 'cloud_storage',
  Database: 'database',
};
export const resourceTypeParam = (opt: string): ResourceTypeParam | undefined => RESOURCE_TYPE_PARAM[opt];

/** "All" | "Assessed" | "Not assessed" → the API's `determined` tri-state. */
export const ASSESSMENT_OPTS = ['All', 'Assessed', 'Not assessed'];
/** The API's `resource_type` enum member for a filter label. */
export type ResourceTypeParam = NonNullable<NonNullable<inventoryOperations['listCryptoApplications']['parameters']['query']>['resource_type']>;

export const determinedParam = (opt: string): boolean | undefined =>
  (opt === 'Assessed' ? true : opt === 'Not assessed' ? false : undefined);

// ---- CSV export ------------------------------------------------------------
// Page-local convenience export, same idiom as the other lenses (client-side,
// from already-loaded rows). Not evidence — for audit-grade output the user
// generates a CBOM artifact.
export const DATA_PROTECTION_CSV_HEADER = [
  'resource_name', 'resource_type', 'resource_identifier', 'encryption_state',
  'key_custody', 'encryption_type', 'algorithm', 'kms_key_id',
  'cloud_provider', 'cloud_region', 'risk_level', 'risk_score', 'last_verified_at',
];

const STATE_CSV: Record<AtRestState, string> = {
  encrypted: 'encrypted',
  unencrypted: 'unencrypted',
  'not-assessed': 'not_assessed',
};

export function dataProtectionCsvRow(a: CryptoApplication): (string | number | null | undefined)[] {
  const rung = protectionRung(a);
  return [
    a.resource_name,
    a.resource_type,
    a.resource_identifier,
    STATE_CSV[atRestState(a)],
    rung === 'not-assessed' ? 'not_assessed' : RUNG_META[rung].label,
    a.encryption_type,
    a.algorithm,
    a.kms_key_id,
    a.cloud_provider,
    a.cloud_region,
    rowRiskLevel(a),
    typeof a.risk_score === 'number' ? a.risk_score : null,
    a.last_verified_at,
  ];
}
