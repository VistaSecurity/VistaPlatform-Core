// Live queries for the two Posture transparency tabs (Algorithm Reference +
// Framework Transparency). All read-only; all surface data that already exists.
// Local row types decouple these components from the generated contract types
// (the responses are cast to them) so the JSX stays readable.
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';

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
  preview_score?: number | null;
  controls_passing?: number | null;
  controls_failing?: number | null;
  /**
   * Controls with at least one ACTIVE, non-suppressed finding of any severity.
   * controls_failing is severity-weighted (a control whose worst finding is Low
   * scores as passing), so this raw count can be higher — the same "has an open
   * exposure" definition /findings/by-control uses (#H-4/#M-15).
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
