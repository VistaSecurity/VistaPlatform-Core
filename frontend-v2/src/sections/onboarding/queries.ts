// Onboarding (Getting Started) data hooks — typed against the auth-service
// contract. The backend engine already existed; the default workflow is seeded
// in scripts/database/seed.sql. See feature spec:
// docsv4/internal/developer/standards/features/onboarding-wizard.md
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { unwrap } from '../../lib/api-result';

/**
 * Refresh the checklist. Steps auto-complete server-side from evidence (a
 * segment / location / sensor exists), but the status and workflow reads are
 * cached for 30-60s, so creating that evidence must invalidate them or the
 * checklist and the nudge show the step as still pending.
 */
export function invalidateOnboarding(qc: QueryClient): Promise<void> {
  return qc.invalidateQueries({ queryKey: ['onboarding'] });
}

// GET /onboarding/status — { required, completed, show_banner }. Cheap; drives
// whether the profile-dropdown "Getting Started" entry is shown. Does not depend
// on the workflow being seeded.
export function useOnboardingStatus() {
  return useQuery({
    queryKey: ['onboarding', 'status'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/onboarding/status', {});
      if (error || !data) throw new Error('Failed to load onboarding status');
      return data;
    },
    staleTime: 60_000,
  });
}

// GET /onboarding/workflow — the workflow with each step annotated with this
// user's status (pending/completed/skipped). One call renders the whole checklist.
export function useOnboardingWorkflow() {
  return useQuery({
    queryKey: ['onboarding', 'workflow'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/onboarding/workflow', {});
      if (error || !data) throw new Error('Failed to load onboarding workflow');
      return data.workflow;
    },
    staleTime: 30_000,
  });
}

// POST /onboarding/steps/{id}/complete — marks a step done for the current user.
// This is the manual "Mark as done" affordance. Steps ALSO auto-complete
// server-side when the tenant has real evidence (a segment / location / agent
// exists) — every onboarding GET reconciles, so the checklist converges without
// clicks. Manual marking remains for edge cases the detector can't see.
export function useCompleteStep() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const data = unwrap(await clients.auth.POST('/onboarding/steps/{id}/complete', {
        params: { path: { id } },
      }), 'Failed to complete step', { requireData: true });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['onboarding'] }),
  });
}

// POST /onboarding/dismiss — per-user permanent dismiss (persisted server-side).
export function useDismissOnboarding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const data = unwrap(await clients.auth.POST('/onboarding/dismiss', {}), 'Failed to dismiss onboarding', { requireData: true });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['onboarding'] }),
  });
}

// PUT /onboarding/settings — org-wide enable/disable (Tenant Admin, settings.update).
export function useSetOnboardingEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (enabled: boolean) => {
      const data = unwrap(await clients.auth.PUT('/onboarding/settings', { body: { enabled } }), 'Failed to update onboarding settings', { requireData: true });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['onboarding'] }),
  });
}
