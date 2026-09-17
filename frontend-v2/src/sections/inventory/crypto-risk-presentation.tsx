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
