// Feature-flag hooks: useFeatures / useFeature. Loads the resolved feature map
// + usage limits from the typed contract (/tenant/features). Independent of RBAC.
import { useQuery } from '@tanstack/react-query';
import { createAuthServiceClient } from '@vistasecurity/api-contract';
import { defaultFeatures, type FeatureName, type FeaturesMap, type LimitsMap } from './types';

export function useFeatures(enabled = true): { features: FeaturesMap; limits: LimitsMap; isLoading: boolean } {
  const { data, isLoading } = useQuery({
    queryKey: ['tenant', 'features'],
    queryFn: async () => {
      const c = createAuthServiceClient();
      const { data, error } = await c.GET('/tenant/features', {});
      if (error || !data) throw new Error('Failed to load features');
      return data;
    },
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  return {
    features: { ...defaultFeatures, ...((data?.features as Partial<FeaturesMap> | undefined) ?? {}) },
    limits: (data?.limits ?? {}) as LimitsMap,
    isLoading,
  };
}

/** Single-flag convenience. Returns false while loading so gated UI defaults hidden. */
export function useFeature(name: FeatureName): boolean {
  return useFeatures().features[name];
}
