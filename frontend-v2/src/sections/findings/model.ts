// Findings domain model — the vocabulary bridge between the two live streams
// (inventory-service crypto risks + compliance-engine framework evaluation)
// and the mock's presentation vocabulary (Findings.jsx CAT / ISSUE maps).
import type { inventoryComponents, complianceEngineComponents } from '@vistasecurity/api-contract';

export type CryptoRisk = inventoryComponents['schemas']['CryptoRisk'];
export type BatchResult = complianceEngineComponents['schemas']['BatchEvaluateResult'];
export type BatchFinding = complianceEngineComponents['schemas']['BatchFindingSummary'];
export type BatchControl = complianceEngineComponents['schemas']['BatchControlStatus'];
export type ComplianceFinding = complianceEngineComponents['schemas']['ComplianceFinding'];

/** The joined asset object GET /findings rides on each finding (unpinned in the contract slice). */
export interface FindingAsset {
  hostname?: string | null;
  ip_address?: string | null;
  port?: number | null;
  asset_type?: string;
  environment?: string | null;
}
export const assetOf = (f: ComplianceFinding): FindingAsset => (f.asset ?? {}) as FindingAsset;

// Finding workflow vocabulary (backend: findings_service.go) with the mock's
// status colors (Findings.jsx FSTATUS).
export const WF_STATUSES = ['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'] as const;
export const WF_LABEL: Record<string, string> = { NEW: 'New', NOTIFIED: 'Notified', RESOLVED: 'Resolved', SUPPRESSED: 'Suppressed' };
export const WF_COLOR: Record<string, string> = { NEW: 'var(--info)', NOTIFIED: 'var(--warn)', RESOLVED: 'var(--ok)', SUPPRESSED: 'var(--neutral)' };
export const wfOf = (f: ComplianceFinding) => (f.workflow_status || 'NEW').toUpperCase();
export const isOpenWf = (f: ComplianceFinding) => { const w = wfOf(f); return w !== 'RESOLVED' && w !== 'SUPPRESSED'; };

// what KIND of thing failed — backend `category` values from the weak-crypto
// detector (protocol / algorithm / key_size / certificate).
export const CAT: Record<string, { label: string; icon: string }> = {
  protocol: { label: 'Protocol', icon: 'route' },
  algorithm: { label: 'Algorithm', icon: 'binary' },
  key_size: { label: 'Key size', icon: 'ruler' },
  certificate: { label: 'Certificate', icon: 'file-badge' },
  compliance: { label: 'Compliance', icon: 'scale' },
};
export const CAT_OPTS = ['All', 'Protocol', 'Algorithm', 'Key size', 'Certificate', 'Compliance'];

export const catOf = (risk: CryptoRisk) => CAT[risk.category] ?? { label: 'Other', icon: 'circle-alert' };

// human description of the failure, keyed by backend issue_type
const ISSUE: Record<string, string> = {
  weak_protocol: 'Weak protocol version in use',
  deprecated_protocol: 'Legacy protocol version in use',
  weak_cipher: 'Weak cipher negotiated',
  deprecated_cipher: 'Legacy cipher negotiated',
  weak_hash: 'Weak hash / MAC algorithm',
  deprecated_hash: 'Deprecated hash algorithm',
  weak_key_size: 'Inadequate key length',
  critically_weak_key_size: 'Critically weak key length',
};
export function issueLabel(risk: CryptoRisk): string {
  if (ISSUE[risk.issue_type]) return ISSUE[risk.issue_type];
  const t = risk.issue_type.replace(/_/g, ' ');
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : risk.description;
}

/** Backend severities are lowercase (critical/high/medium/informational). */
export function sevLevel(s: string | undefined): string {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'medium': return 'Medium';
    case 'med': return 'Medium'; // compliance_findings stores Low/Med/High/Critical
    case 'low': return 'Low';
    default: return 'Informational';
  }
}

const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
export const sevRank = (lvl: string) => SEV_RANK[lvl] ?? 4;
