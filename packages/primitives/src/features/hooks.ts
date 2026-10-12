// Feature-flag hooks: useFeatures / useFeature. Loads the resolved feature map
// + usage limits from the typed contract (/tenant/features). Independent of RBAC.
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { createAuthServiceClient } from '@vistasecurity/api-contract';
import { primitivesQueryKeys } from '../shared/query-keys';
import { defaultFeatures, type FeatureName, type FeaturesMap, type LimitsMap, type TenantPlan } from './types';

const featuresKey = primitivesQueryKeys.tenant.features();

async function fetchFeatures() {
  const c = createAuthServiceClient();
  const { data, error } = await c.GET('/tenant/features', {});
  if (error || !data) throw new Error('Failed to load features');
  return data;
}

export function useFeatures(enabled = true): {
  features: FeaturesMap;
  limits: LimitsMap;
  isLoading: boolean;
  /** The load FAILED; `features` is then the all-off defaults (fail-closed). */
  isError: boolean;
  refetch(): void;
} {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: featuresKey,
    queryFn: fetchFeatures,
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  return useMemo(
    () => ({
      features: { ...defaultFeatures, ...((data?.features as Partial<FeaturesMap> | undefined) ?? {}) },
      limits: (data?.limits ?? {}) as LimitsMap,
      isLoading,
      isError,
      refetch: () => { void refetch(); },
    }),
    [data, isLoading, isError, refetch],
  );
}

/**
 * The tenant's resolved plan block, from the same /tenant/features request as
 * useFeatures (one query, shared cache). `plan` is undefined while loading, on
 * error, and when the server could not resolve it — callers hide the plan
 * block then rather than fall back to a tier name.
 */
export function usePlan(enabled = true): { plan: TenantPlan | undefined; isLoading: boolean; isError: boolean } {
  const { data, isLoading, isError } = useQuery({
    queryKey: featuresKey,
    queryFn: fetchFeatures,
    enabled,
    staleTime: 5 * 60 * 1000,
  });
  return { plan: data?.plan as TenantPlan | undefined, isLoading, isError };
}

/** Single-flag convenience. Returns false while loading so gated UI defaults hidden. */
export function useFeature(name: FeatureName): boolean {
  return useFeatures().features[name];
}
