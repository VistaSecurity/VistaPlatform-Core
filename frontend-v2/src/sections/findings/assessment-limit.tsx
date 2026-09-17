import type { ComplianceFinding } from './model';
import { assessmentLimitations, assessmentLimitText } from './producer-evidence';

/** Evidence-backed limitation notice. Renders only limitations supported by available evidence. */
export function AssessmentLimitNotice({ findings, assetContext = false }: {
  findings: ComplianceFinding[];
  assetContext?: boolean;
}) {
  const limit = assessmentLimitations(findings);
  if (!limit) return null;
  return (
    <div
      data-testid={assetContext ? 'asset-assessment-limit' : 'finding-assessment-limit'}
      style={{ marginBottom: assetContext ? 12 : 8, padding: assetContext ? '9px 11px' : '7px 9px', borderRadius: 8, border: assetContext ? '1px solid color-mix(in srgb, var(--warn) 35%, transparent)' : undefined, background: 'color-mix(in srgb, var(--warn) 8%, transparent)', color: 'var(--warn-text, var(--warn))', fontSize: 11.5 }}
    >
      {assessmentLimitText(limit)}{assetContext && limit.unscoredCves > 0 && limit.unscoredCves < limit.totalCves ? ' The known risk score still reflects the CVEs that do have scores.' : ''}
      {limit.crypto.length > 0 && (
        <ul style={{ margin: '5px 0 0', paddingLeft: 18 }}>
          {limit.crypto.map((item) => <li key={item}>{item}</li>)}
        </ul>
      )}
    </div>
  );
}
