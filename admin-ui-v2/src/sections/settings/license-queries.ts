// Settings → License & Usage data layer — TanStack Query over the typed
// admin-service client (GET /admin/license, GET/PUT /admin/license/retention).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { platformEditionKey } from '../../lib/edition';

export type LicenseInfo = adminServiceComponents['schemas']['LicenseInfo'];
export type RetentionSetting = adminServiceComponents['schemas']['RetentionSetting'];

export const licenseKey = ['platform', 'license'] as const;
export const retentionKey = ['platform', 'license', 'retention'] as const;

export function useLicense() {
  return useQuery({
    queryKey: licenseKey,
    staleTime: 60 * 1000,
    queryFn: async (): Promise<LicenseInfo> => {
      const { data, error } = await clients.admin.GET('/admin/license', {});
      if (error || !data) throw new Error('Could not read licence status');
      return data;
    },
  });
}

export function useRetention(enabled = true) {
  return useQuery({
    queryKey: retentionKey,
    enabled,
    staleTime: 60 * 1000,
    queryFn: async (): Promise<RetentionSetting> => {
      const { data, error } = await clients.admin.GET('/admin/license/retention', {});
      if (error || !data) throw new Error('Could not read the retention setting');
      return data;
    },
  });
}

export function useSaveRetention() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (maxDays: number | null): Promise<RetentionSetting> => {
      const { data, error } = await clients.admin.PUT('/admin/license/retention', { body: { max_days: maxDays } });
      if (error || !data) throw new Error((error as { error?: string } | undefined)?.error ?? 'Could not save the retention setting');
      return data;
    },
    onSuccess: (data) => {
      qc.setQueryData(retentionKey, data);
      void qc.invalidateQueries({ queryKey: platformEditionKey });
    },
  });
}

/**
 * The expiry warning to show, by days left: the tightest of the spec's three
 * thresholds (30 / 14 / 7) the licence is inside, or null when none applies.
 * An expired licence (0 days) warns at 7 — the card says it has expired.
 */
export function expiryWarning(daysLeft: number | null | undefined): 30 | 14 | 7 | null {
  if (daysLeft == null) return null;
  if (daysLeft <= 7) return 7;
  if (daysLeft <= 14) return 14;
  if (daysLeft <= 30) return 30;
  return null;
}

/** A retention cap as the form edits it. */
export type RetentionUnit = 'days' | 'years';

/** Form → days. Years are whole 365-day years. Returns null when the input is not a valid cap. */
export function retentionDays(amount: string, unit: RetentionUnit): number | null {
  const t = amount.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t) * (unit === 'years' ? 365 : 1);
  if (n < 1 || n > 36500) return null;
  return n;
}

/** Days → the most natural form value: whole years when it divides evenly. */
export function retentionForm(days: number | null | undefined): { mode: 'unlimited' | 'cap'; amount: string; unit: RetentionUnit } {
  if (days == null) return { mode: 'unlimited', amount: '', unit: 'years' };
  if (days % 365 === 0) return { mode: 'cap', amount: String(days / 365), unit: 'years' };
  return { mode: 'cap', amount: String(days), unit: 'days' };
}

/** "Unlimited" / "7 years" / "400 days". */
export function retentionLabel(days: number | null | undefined): string {
  if (days == null) return 'Unlimited';
  if (days % 365 === 0) {
    const y = days / 365;
    return `${y} year${y === 1 ? '' : 's'}`;
  }
  return `${days} day${days === 1 ? '' : 's'}`;
}
