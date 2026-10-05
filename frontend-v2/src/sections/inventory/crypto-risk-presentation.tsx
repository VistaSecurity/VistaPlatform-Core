import { RiskChip, levelFromScore, type RiskLevel } from '../../components/ui';

export interface CryptoRiskSource {
  risk_score?: number | null;
  risk_score_assessed?: boolean;
  risk_level?: string | null;
}

export interface CryptoRiskPresentation {
  assessed: boolean;
  score: number | null;
  level: RiskLevel;
  title: string;
}

/**
 * Present a configuration's numeric risk without collapsing an explicit zero
 * into an absent assessment. Positive legacy scores remain readable while the
 * API rolls out risk_score_assessed; zero needs the evidence-backed flag.
 */
export function cryptoRiskPresentation(config: CryptoRiskSource): CryptoRiskPresentation {
  const score = typeof config.risk_score === 'number'
    && Number.isFinite(config.risk_score)
    && config.risk_score >= 0
    && config.risk_score <= 100
    ? config.risk_score
    : null;
  const assessed = score !== null && (score > 0 || config.risk_score_assessed === true);
  if (!assessed) {
    return {
      assessed: false,
      score: null,
      level: 'Informational',
      title: 'Risk score not assessed — no numeric catalogue or stored score is available',
    };
  }
  const level = levelFromScore(score);
  return { assessed: true, score, level, title: `Risk score ${score} · ${level}` };
}

export function CryptoRiskChip({ config, size = 22 }: { config: CryptoRiskSource; size?: number }) {
  const risk = cryptoRiskPresentation(config);
  return <RiskChip level={risk.level} assessed={risk.assessed} size={size} title={risk.title} />;
}

// ---- partial assessment ---------------------------------------------------
// A configuration can be scored on only part of what it is ( W1.2): a
// protocol version no collector read, or a cipher string that could not be
// fully resolved. Inventory records which in raw_data; this names them, so an
// absent value reads as "not measured" rather than as nothing to worry about.

export const NOT_MEASURED_TITLE = 'The collector did not report this value';

export interface AssessmentGapSource {
  protocol_version?: string | null;
  raw_data?: Record<string, unknown> | null;
}

export interface AssessmentGaps {
  versionUnmeasured: boolean;
  /** What was not measured or resolved. Empty means fully assessed. */
  gaps: string[];
}

export function assessmentGaps(config: AssessmentGapSource): AssessmentGaps {
  const raw: Record<string, unknown> = config.raw_data ?? {};
  const unmeasured = Array.isArray(raw.unmeasured_components) ? raw.unmeasured_components : [];
  // The marker counts only while the value is really absent: raw_data is
  // merged across observations, and a later one may have measured it.
  const versionUnmeasured = unmeasured.includes('protocol_version') && !config.protocol_version;
  const gaps: string[] = [];
  if (versionUnmeasured) gaps.push('protocol version');
  if (raw.cipher_assessment === 'partial') gaps.push('cipher set (the cipher string could not be fully resolved)');
  return { versionUnmeasured, gaps };
}

export function PartialAssessmentNote({ config }: { config: AssessmentGapSource }) {
  const { gaps } = assessmentGaps(config);
  if (gaps.length === 0) return null;
  return (
    <div role="note" style={{ margin: '10px 0 4px', padding: '9px 11px', borderRadius: 9, border: '1px dashed var(--app-border2)', background: 'var(--app-panel2)', fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.45 }}>
      <strong style={{ color: 'var(--app-t1)' }}>Partially assessed.</strong>{' '}
      Not measured: {gaps.join('; ')}. The score covers only what was measured, and an unmeasured value is never counted as safe.
    </div>
  );
}
