import type { CryptoRisk } from './model';

const BASIS: Record<NonNullable<CryptoRisk['assessment_basis']>, { label: string; help: string }> = {
  configuration: {
    label: 'Configuration risk',
    help: 'Severity follows the configuration’s numeric risk assessment.',
  },
  certificate_lifecycle: {
    label: 'Certificate lifecycle',
    help: 'Severity follows certificate lifecycle evidence. A configuration risk score, when shown, is a separate assessment.',
  },
  retained_finding: {
    label: 'Retained finding',
    help: 'A previous active issue remains visible because the current evidence cannot disprove it.',
  },
};

/** Explain the independent sources behind a crypto risk's visible severity and score. */
export function CryptoAssessment({ risk }: { risk: CryptoRisk }) {
  const basis = risk.assessment_basis ? BASIS[risk.assessment_basis] : null;
  const limitations = risk.assessment_limitations ?? [];
  const sources = risk.score_sources ?? [];

  return (
    <div data-testid="crypto-assessment" style={{ padding: '14px 18px', borderBottom: '1px solid var(--app-border)' }}>
      <div className="eyebrow-app" style={{ marginBottom: 7 }}>How this was assessed</div>
      <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 12px', fontSize: 12.5 }}>
        <dt style={{ color: 'var(--app-t3)' }}>Basis</dt>
        <dd style={{ margin: 0, color: 'var(--app-t1)' }}>{basis?.label ?? 'Not specified'}</dd>
        <dt style={{ color: 'var(--app-t3)' }}>Risk score</dt>
        <dd className="mono" style={{ margin: 0, color: 'var(--app-t1)' }}>{risk.risk_score ?? 'Not scored'}</dd>
      </dl>
      {basis && <p style={{ margin: '7px 0 0', fontSize: 11.5, lineHeight: 1.5, color: 'var(--app-t3)' }}>{basis.help}</p>}
      {sources.length > 0 && (
        <div style={{ marginTop: 9, fontSize: 11.5, color: 'var(--app-t2)' }}>
          <strong style={{ color: 'var(--app-t1)' }}>Numeric contributors</strong>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {sources.map((source) => <li key={source}>{source}</li>)}
          </ul>
        </div>
      )}
      {limitations.length > 0 && (
        <div data-testid="crypto-assessment-limitations" style={{ marginTop: 9, padding: '8px 9px', borderRadius: 8, border: '1px solid var(--app-border)', background: 'var(--app-panel2)', fontSize: 11.5, lineHeight: 1.5, color: 'var(--app-t2)' }}>
          <strong style={{ color: 'var(--app-t1)' }}>Assessment limitations</strong>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
