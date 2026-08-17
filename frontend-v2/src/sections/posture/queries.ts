// Live queries for the two Posture transparency tabs (Algorithm Reference +
// Framework Transparency). All read-only; all surface data that already exists.
// Local row types decouple these components from the generated contract types
// (the responses are cast to them) so the JSX stays readable.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';

// ---- Algorithm Reference -------------------------------------------------

/** One row of the `algorithms` source-of-truth table (the assessment fields we surface). */
export interface AlgorithmRow {
  id: string;
  code: string;
  name: string;
  category?: string;
  subcategory?: string;
  description?: string;
  strength: string; // weak | acceptable | strong | recommended
  deprecation_status: string; // current | deprecated | obsolete
  deprecation_date?: string;
  risk_score: number;
  recommended_alternatives?: string[];
  migration_guidance?: string;
  is_pqc: boolean;
  pqc_standardization_status?: string;
  is_standard?: boolean;
  algorithm_family?: string;
  primitive?: string;
  mode?: string;
  padding?: string;
  oid?: string;
  crypto_functions?: string[];
  classical_security_level?: number;
  nist_quantum_security_level?: number;
  parameter_set_identifier?: string;
  curve?: string;
}

/** The full algorithm catalogue (small, static-ish set → fetch once, filter client-side). */
export function useAlgorithms() {
  return useQuery({
    queryKey: ['posture', 'algorithms'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/algorithms', {});
      if (error || !data) throw new Error('Failed to load algorithms');
      return (data.algorithms ?? []) as AlgorithmRow[];
    },
    staleTime: 5 * 60_000,
  });
}

// ---- Framework Transparency ----------------------------------------------

export interface AvailableFrameworkRow {
  platform_framework: {
    id: string;
    code: string;
    name: string;
    version: string;
    description: string;
    organization: string;
    controls_count: number;
  };
  is_licensed: boolean;
  is_platform_default: boolean;
  /**
   * Severity-weighted score over the ASSESSED controls only. Null until the
   * engine has produced a rollup, AND null once it has if NO control could be
   * assessed — rendered "—", never 0 and never 100.
   */
  preview_score?: number | null;
  controls_passing?: number | null;
  /** Controls with at least one ACTIVE, non-suppressed finding of ANY severity. */
  controls_failing?: number | null;
  /**
   * Controls excluded from the score because they could not be evaluated — no
   * measurement rule configured, nothing in scope, or the check failed.
   * passing + failing is the assessed subset behind the coverage line.
   */
  controls_not_assessed?: number | null;
  /**
   * Controls with at least one ACTIVE, non-suppressed finding of any severity —
   * the same "has an open exposure" definition /findings/by-control uses. Now
   * equal to controls_failing by construction; the two disagreed only while
   * status was derived from severity.
   */
  open_findings_controls?: number | null;
}

/**
 * Every published framework, each with `is_licensed` (activated vs available)
 * and a materialized `preview_score`. One call powers both the "My frameworks"
 * default (filter is_licensed) and the "Explore all published" toggle.
 */
export function useAvailableFrameworks() {
  return useQuery({
    queryKey: ['posture', 'available-frameworks'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/available', {});
      if (error || !data) throw new Error('Failed to load frameworks');
      return (data.frameworks ?? []) as AvailableFrameworkRow[];
    },
    staleTime: 60_000,
  });
}

// ---- Manual re-evaluation (cooldown-gated) --------------------------------

export type ReevaluationState = complianceEngineComponents['schemas']['ReevaluationState'];

/**
 * The tenant's re-evaluation cooldown. The control reads this so it can be
 * DISABLED before the user clicks — a button that is clickable and then answers
 * 429 is the defect this release just spent a dozen fixes removing.
 *
 * Refetched on an interval short enough that the button re-enables on its own
 * when the hour is up, without the user reloading the page.
 */
export function useReevaluationState() {
  return useQuery({
    queryKey: ['posture', 'reevaluation'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/reevaluation', {});
      if (error || !data) throw new Error('Failed to load re-evaluation state');
      return data;
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
}

/**
 * Trigger a re-evaluation. The reconcile is asynchronous, so success means
 * "queued", not "done" — the caller says so in the UI rather than implying the
 * numbers on screen have already moved.
 */
export function useReevaluate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.compliance.POST('/reevaluate', {});
      if (error || !response.ok) {
        // 429 carries the cooldown state; surface the server's own sentence
        // rather than inventing one.
        const msg = (error as { error?: string } | undefined)?.error;
        throw new Error(msg ?? 'Could not start a re-evaluation.');
      }
      return data;
    },
    onSettled: () => {
      // Re-read the cooldown either way: on success it has just been consumed,
      // and on a 429 our copy was evidently stale.
      void qc.invalidateQueries({ queryKey: ['posture', 'reevaluation'] });
    },
  });
}

export interface MeasurementRow {
  id: string;
  rule_type: string; // threshold | presence | pattern | range
  predicate: Record<string, unknown>;
  weight?: number;
  severity_override?: string;
  measurement_type?: { code?: string; name?: string; description?: string; units?: string } | null;
}

export interface FrameworkControlRow {
  id: string;
  control_id: string;
  title: string;
  description: string;
  baseline_severity: string; // Low | Med | High | Critical
  crypto_relevant: boolean;
  measurements?: MeasurementRow[];
}

export interface FrameworkDetail {
  framework: {
    id: string;
    code: string;
    name: string;
    version: string;
    description: string;
    organization: string;
    controls_count: number;
    controls?: FrameworkControlRow[];
  };
  licensed: boolean;
  message?: string;
}

/** A published framework with its full control + measurement detail (visible to all tenants). */
export function useFrameworkDetail(id: string | null) {
  return useQuery({
    queryKey: ['posture', 'framework-detail', id],
    enabled: !!id,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/published/{id}', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error('Failed to load framework');
      return data as unknown as FrameworkDetail;
    },
    staleTime: 60_000,
  });
}
