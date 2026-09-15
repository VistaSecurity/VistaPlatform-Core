// B-31: the Findings page Export button used to be hard-wired to
// GET /crypto-risks/export regardless of which lens was on screen — wrong
// dataset entirely on the two compliance lenses (a different service's
// findings), no filters applied on the crypto lenses, and a silent no-op on
// any non-2xx. Building the CSV client-side from the rows already loaded and
// filtered on screen (mirroring inventory-page.tsx's exportCsv) fixes all
// three at once and needs no network round trip. Kept in its own DOM-free
// module — separate from findings-page.tsx's JSX — so the row-building logic
// is directly unit-testable.
import type { ComplianceFinding, ControlRef, CryptoRisk } from './model';
import { catOf, findingCitation, issueLabel, sevLevel, targetLabel, wfOf } from './model';
import { kindLabel, producerLabel } from './producer-evidence';

export interface ControlMeta { fwId: string; fwName: string; control: ControlRef }

export const CRYPTO_RISK_CSV_HEADER = ['asset', 'category', 'issue', 'current_value', 'severity', 'protocol', 'protocol_version', 'detected_at'];

export function buildCryptoRiskCsvRows(risks: CryptoRisk[]): (string | number | null | undefined)[][] {
  return risks.map((r) => [
    r.asset_hostname ?? r.asset_ip_address ?? r.asset_id,
    catOf(r).label,
    issueLabel(r),
    r.current_value,
    sevLevel(r.severity),
    r.protocol,
    r.protocol_version,
    r.detected_at,
  ]);
}

// `producer` and `kind` lead, and `control_id`/`framework` are blank for every
// producer but compliance. The export follows the page: once the list shows
// end-of-life and vulnerability findings, a CSV that still had "control_id"
// as its first column would be describing the page it used to be.
export const COMPLIANCE_FINDING_CSV_HEADER = ['producer', 'kind', 'control_id', 'framework', 'target', 'severity', 'score', 'workflow_status', 'assigned_to', 'first_seen', 'last_seen', 'summary', 'citation'];

/** The all-zero uuid `control_id` carries for every non-compliance producer. */
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

export function buildComplianceFindingCsvRows(findings: ComplianceFinding[], controlMeta: Map<string, ControlMeta>): (string | number | null | undefined)[][] {
  return findings.map((f) => {
    const isCompliance = (f.producer ?? 'compliance') === 'compliance';
    const meta = isCompliance ? controlMeta.get(f.control_id) : undefined;
    // The nil uuid is "no control", not a control nobody can find. Exporting it
    // verbatim would put a plausible-looking id in a column it does not belong
    // in — the same mistake the ticket asset link made for certificates.
    const controlCell = isCompliance && f.control_id && f.control_id !== NIL_UUID
      ? (meta?.control.name ?? f.control_id)
      : '';
    return [
      producerLabel(f.producer),
      kindLabel(f.kind),
      controlCell,
      meta?.fwName ?? '',
      targetLabel(f),
      sevLevel(f.severity),
      f.score ?? 0,
      wfOf(f),
      f.assigned_to ?? '',
      f.first_seen,
      f.last_seen,
      f.summary,
      findingCitation(f)?.href ?? '',
    ];
  });
}

/** Mirrors inventory-page.tsx's downloadCsv. */
export function downloadCsv(filename: string, header: string[], rows: (string | number | null | undefined)[][]) {
  const esc = (v: string | number | null | undefined) => {
    let s = v == null ? '' : String(v);
    // Neutralize formula injection: a leading = + - @ tab or CR makes
    // Excel/Sheets execute the cell.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const csv = [header, ...rows].map((r) => r.map(esc).join(',')).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
