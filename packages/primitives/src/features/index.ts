// Feature-flag primitives.
export type { FeatureName, FeaturesMap, UsageLimit, LimitsMap } from './types';
export { defaultFeatures } from './types';
export { useFeatures, useFeature } from './hooks';
// Edition awareness — the fallback gate for carved capabilities that have no
// entitlement key yet. Prefer useFeature whenever a key exists; see edition.ts.
export {
  EDITION_UNAVAILABLE_STATUS,
  EditionUnavailableError,
  isEditionUnavailable,
  assertEditionPresent,
  editionAwareRetry,
} from './edition';
