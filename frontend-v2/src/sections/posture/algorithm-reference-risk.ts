type AlgorithmRisk = { code?: string | null; risk_score?: number | null };

// Numeric zero is an assessed score. Missing scores sort after every assessed
// row instead of borrowing zero's position in the catalogue.
export function compareAlgorithmRiskDescending(a: AlgorithmRisk, b: AlgorithmRisk): number {
  if (a.risk_score == null && b.risk_score == null) return (a.code ?? '').localeCompare(b.code ?? '');
  if (a.risk_score == null) return 1;
  if (b.risk_score == null) return -1;
  return b.risk_score - a.risk_score;
}

export function formatAlgorithmRiskScore(score: number | null | undefined, includeScale = false): string {
  if (score == null) return 'Unassessed';
  return includeScale ? `${score} / 100` : String(score);
}
