// Render a control measurement's typed predicate as a plain-language sentence.
// The shapes mirror the backend RuleEvaluator (services/compliance-engine/
// internal/services/rule_evaluator.go) exactly — a match in `pattern` is a
// VIOLATION, threshold passes when value <op> threshold, etc. This is the one
// place that turns `{operator:">=", value:2048}` into "Passes when RSA key size
// is at least 2,048 bits", so any "why-non-compliant" surface can reuse it.

export interface MeasurementLike {
  rule_type?: string | null;
  predicate?: Record<string, unknown> | null;
  measurement_type?: { name?: string; units?: string; code?: string } | null;
}

const OP_PHRASE: Record<string, string> = {
  '>=': 'at least',
  '<=': 'at most',
  '>': 'greater than',
  '<': 'less than',
  '==': 'exactly',
  '!=': 'not',
};

/** Humanize a measurement_type code as a fallback subject ("tls_version" → "Tls version"). */
function humanizeCode(code?: string): string {
  if (!code) return 'this measurement';
  const s = code.replace(/[_-]+/g, ' ').trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : 'this measurement';
}

/** The thing a measurement is about — prefer the measurement type's display name. */
export function measurementSubject(m: MeasurementLike): string {
  return m.measurement_type?.name?.trim() || humanizeCode(m.measurement_type?.code);
}

function fmtValue(v: unknown): string {
  if (typeof v === 'number') return v.toLocaleString();
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  return String(v ?? '');
}

/**
 * One sentence describing what makes a control pass (or, for pattern rules, what
 * trips a violation). Always returns something readable, even for an unknown
 * shape, so the UI never shows a raw predicate blob.
 */
export function describeMeasurement(m: MeasurementLike): string {
  const subject = measurementSubject(m);
  const units = m.measurement_type?.units ? ` ${m.measurement_type.units}` : '';
  const p = m.predicate ?? {};

  switch (m.rule_type) {
    case 'threshold': {
      const op = typeof p.operator === 'string' ? p.operator : '';
      const phrase = OP_PHRASE[op];
      if (phrase === undefined || !('value' in p)) break;
      const val = fmtValue(p.value);
      if (op === '!=') return `Passes when ${subject} is not ${val}${units}.`;
      return `Passes when ${subject} is ${phrase} ${val}${units}.`;
    }
    case 'presence': {
      if (typeof p.exists !== 'boolean') break;
      return p.exists
        ? `Passes when ${subject} is present.`
        : `Passes when ${subject} is absent.`;
    }
    case 'pattern': {
      if (typeof p.pattern !== 'string' || !p.pattern) break;
      return `Flags any ${subject} matching the pattern ${p.pattern}.`;
    }
    case 'range': {
      const hasMin = p.min !== undefined && p.min !== null;
      const hasMax = p.max !== undefined && p.max !== null;
      if (hasMin && hasMax) return `Passes when ${subject} is between ${fmtValue(p.min)} and ${fmtValue(p.max)}${units}.`;
      if (hasMin) return `Passes when ${subject} is at least ${fmtValue(p.min)}${units}.`;
      if (hasMax) return `Passes when ${subject} is at most ${fmtValue(p.max)}${units}.`;
      break;
    }
  }
  // Unknown / malformed predicate — degrade gracefully rather than leak JSON.
  return `Custom rule evaluated against ${subject}.`;
}
