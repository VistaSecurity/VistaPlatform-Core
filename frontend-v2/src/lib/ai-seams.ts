// What this deployment's AI seams can actually do, asked once and shared.
//
// `GET /api/v1/auth-service/tenant/ai` is the ONE availability question
// for every generative capability: it combines the deployment's provider
// environment, whether this image line links the Enterprise providers, the
// hand-maintained seam catalogue, and the tenant's own two switches. Settings →
// AI assistant renders the whole thing; every other surface wants one row of it.
//
// It lives here rather than in a section because it now has two consumers — the
// settings page and the Findings inspector's "Draft a remediation plan" — and a
// second copy of the query would mean a second query KEY, which means two
// fetches of the same endpoint on any screen that has both. One key, one cache
// entry, one answer.
import { useQuery } from '@tanstack/react-query';
import { clients } from './clients';

/** One row of the seam table: what this deployment can do with this capability. */
export type AISeamStatus = {
  key: string;
  /** Something can answer through this seam here, right now. */
  live: boolean;
  /**
   * An implementation a user can reach exists in the product AT ALL, in any
   * edition. Edition- and provider-independent, and on the wire precisely so a
   * client does not have to guess between "your edition does not have it" and
   * "nobody has written it yet".
   */
  built: boolean;
  edition_required: string;
  family: string;
  surface?: string;
  /** What answers when no model does. Never empty. */
  rule_default: string;
};

export type AIStatus = {
  provider_configured: boolean;
  provider_name?: string;
  model_id?: string;
  edition_linked: boolean;
  seams: AISeamStatus[];
  tenant: { record_questions: boolean; assistant_disabled: boolean; authoring_disabled: boolean };
};

/** The shared cache key. Both consumers use it, so the endpoint is fetched once. */
export const AI_QUERY_KEY = ['settings', 'ai-assistant'] as const;

/** The eight seam keys, as the backend's ai.Seam constants spell them. */
export const SEAM_REMEDIATOR = 'remediator';

export function useAIStatus() {
  return useQuery({
    queryKey: AI_QUERY_KEY,
    queryFn: async (): Promise<AIStatus> => {
      const { data, error } = await clients.auth.GET('/tenant/ai', {});
      if (error || !data) throw new Error('Failed to load the AI assistant settings');
      return data;
    },
    // A deployment's provider configuration and edition do not change between
    // requests — the environment is injected at pod start — and the tenant's two
    // switches change when somebody saves the settings page, which invalidates
    // this key itself. So a surface that asks on every open re-uses the answer
    // rather than re-fetching it.
    staleTime: 5 * 60_000,
  });
}

/**
 * Whether one seam can answer for THIS tenant right now.
 *
 * `available` is the only thing a button should read, and it is deliberately the
 * AND of two different facts: the deployment can answer through this seam, and
 * the tenant has not turned the assistant off. A surface that checked only the
 * first would offer a button that answers 403, which is a worse experience than
 * no button — the user cannot tell whether they are broken or switched off.
 *
 * The reason is carried separately, because the three "no"s send a reader to
 * three different places:
 *
 *   - `edition`      — a purchase
 *   - `no_provider`  — ten minutes of an administrator's time
 *   - `disabled`     — a switch this organization owns, in its own settings
 *   - `not_built`    — nobody has written it; nothing to do but wait
 *
 * `loading` matters as much: rendering "unavailable" while the answer is in
 * flight tells a user a capability is off when we have not looked yet, which is
 * the failure shape this whole area is written against. A caller renders nothing
 * until it resolves.
 */
export type SeamAvailability = {
  loading: boolean;
  available: boolean;
  reason?: 'edition' | 'no_provider' | 'disabled' | 'not_built' | 'unknown';
  /** What answers instead, from the catalogue. Safe to show in every edition. */
  ruleDefault?: string;
};

export function seamAvailability(
  key: string,
  status: AIStatus | undefined,
  isLoading: boolean,
  isError: boolean,
): SeamAvailability {
  if (isLoading) return { loading: true, available: false };
  // Fail closed on an error, and say we do not know. A read that did not
  // complete is not evidence the capability is there — nor that it is not.
  if (isError || !status) return { loading: false, available: false, reason: 'unknown' };

  const seam = status.seams.find((s) => s.key === key);
  if (!seam) return { loading: false, available: false, reason: 'not_built' };

  const ruleDefault = seam.rule_default;
  if (status.tenant.assistant_disabled) {
    return { loading: false, available: false, reason: 'disabled', ruleDefault };
  }
  if (seam.live) return { loading: false, available: true, ruleDefault };
  // Order matters, and `not_built` comes first: whether a capability has been
  // written is not a fact about the reader's licence. The settings page's
  // seamState() makes the same call for the same reason.
  if (!seam.built) return { loading: false, available: false, reason: 'not_built', ruleDefault };
  if (seam.edition_required === 'enterprise' && !status.edition_linked) {
    return { loading: false, available: false, reason: 'edition', ruleDefault };
  }
  if (seam.family === 'generative' && !status.provider_configured) {
    return { loading: false, available: false, reason: 'no_provider', ruleDefault };
  }
  return { loading: false, available: false, reason: 'not_built', ruleDefault };
}

/** The hook a surface uses: one seam, one answer. */
export function useSeamAvailability(key: string): SeamAvailability {
  const { data, isLoading, isError } = useAIStatus();
  return seamAvailability(key, data, isLoading, isError);
}
