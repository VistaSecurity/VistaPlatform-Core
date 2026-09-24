// VISTA Operations — Settings ▸ License & Usage: licence usage reporting
// (edition-licensing spec PR 4, delivery PR 5). Typed hooks over admin-service's
// /admin/license/{usage,reports} routes via the generated client
// (`clients.admin`, @vistasecurity/api-contract); no hand-rolled fetch.
//
// Every route answers only under an active MSP licence (404 with reason
// "not_msp" otherwise). The panel is rendered only on MSP installs, but the
// hooks still surface that answer as a typed NotMSPError rather than a generic
// failure, so a caller can explain it instead of offering Retry.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type LicenseUsage = adminServiceComponents['schemas']['LicenseUsage'];
export type LicenseUsageReport = adminServiceComponents['schemas']['LicenseUsageReport'];
export type LicenseUsageReportList = adminServiceComponents['schemas']['LicenseUsageReportList'];
export type GenerateReportRequest = adminServiceComponents['schemas']['GenerateLicenseUsageReportRequest'];
export type GenerateReportResponse = adminServiceComponents['schemas']['GenerateLicenseUsageReportResponse'];
export type RetryReportResponse = adminServiceComponents['schemas']['RetryLicenseUsageReportResponse'];

const KEY = ['platform', 'license', 'usage'] as const;

/** The install is not under an active MSP licence. */
export class NotMSPError extends Error {
  constructor() {
    super('Usage reporting is available only under an active MSP licence.');
    this.name = 'NotMSPError';
  }
}

/** Server message from a LegacyError body, or the fallback. */
function messageOf(error: unknown, fallback: string): string {
  const msg = (error as { error?: unknown } | undefined)?.error;
  return typeof msg === 'string' && msg.trim() ? msg : fallback;
}

function isNotMSP(error: unknown): boolean {
  return (error as { reason?: unknown } | undefined)?.reason === 'not_msp';
}

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

export async function fetchLicenseUsage(): Promise<LicenseUsage> {
  const { data, error } = await clients.admin.GET('/admin/license/usage', {});
  if (error) {
    if (isNotMSP(error)) throw new NotMSPError();
    throw new Error(messageOf(error, 'Could not load licence usage'));
  }
  if (!data) throw new Error('Could not load licence usage');
  return data;
}

export async function fetchLicenseUsageReports(): Promise<LicenseUsageReportList> {
  const { data, error } = await clients.admin.GET('/admin/license/reports', {});
  if (error || !data) throw new Error(messageOf(error, 'Could not load usage reports'));
  return data;
}

export async function generateLicenseUsageReport(body: GenerateReportRequest): Promise<GenerateReportResponse> {
  const { data, error } = await clients.admin.POST('/admin/license/reports', { body });
  if (error) {
    if (isNotMSP(error)) throw new NotMSPError();
    throw new Error(messageOf(error, 'Could not generate the report'));
  }
  if (!data) throw new Error('Could not generate the report');
  return data;
}

export async function retryLicenseUsageReport(id: string): Promise<RetryReportResponse> {
  const { data, error } = await clients.admin.POST('/admin/license/reports/{id}/retry', { params: { path: { id } } });
  if (error) {
    if (isNotMSP(error)) throw new NotMSPError();
    throw new Error(messageOf(error, 'Could not retry the delivery'));
  }
  if (!data) throw new Error('Could not retry the delivery');
  return data;
}

/**
 * Where a report stands with automatic delivery, for the reports table:
 *
 * - `preview` — a month-to-date preview; never sent, never billed.
 * - `delivered` — the receiver has it (even if delivery was since switched off).
 * - `not_configured` — licensing.reporting.endpoint is empty: download and upload.
 * - `queued` — pending, never failed: goes out at the next pass.
 * - `retrying` — pending after a network error / 5xx; `next_attempt_at` says when.
 * - `failed` — the receiver refused it (400/401 …); retried on the backoff.
 * - `rejected` — the receiver rejected it (422); only a manual retry sends it again.
 */
export type DeliveryState = 'preview' | 'delivered' | 'not_configured' | 'queued' | 'retrying' | 'failed' | 'rejected';

export function deliveryState(
  r: Pick<LicenseUsageReport, 'complete' | 'delivery_status' | 'last_error' | 'next_attempt_at'>,
  configured: boolean,
): DeliveryState {
  if (!r.complete) return 'preview';
  if (r.delivery_status === 'delivered') return 'delivered';
  if (!configured) return 'not_configured';
  if (r.delivery_status === 'failed') return r.next_attempt_at ? 'failed' : 'rejected';
  return r.last_error ? 'retrying' : 'queued';
}

/** A platform admin can re-queue a report whose delivery failed. */
export function canRetryDelivery(state: DeliveryState): boolean {
  return state === 'failed' || state === 'rejected';
}

export function useLicenseUsage() {
  return useQuery({
    queryKey: [...KEY, 'summary'],
    queryFn: fetchLicenseUsage,
    staleTime: 60_000,
    retry: (count, e) => !(e instanceof NotMSPError) && count < 2,
  });
}

export function useLicenseUsageReports() {
  return useQuery({
    queryKey: [...KEY, 'reports'],
    queryFn: fetchLicenseUsageReports,
    staleTime: 60_000,
  });
}

export function useGenerateLicenseUsageReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: generateLicenseUsageReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useRetryLicenseUsageReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: retryLicenseUsageReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Save a stored report exactly as signed, as <report_id>.json. */
export async function downloadLicenseUsageReport(report: Pick<LicenseUsageReport, 'report_id'>): Promise<void> {
  const { data, error, response } = await clients.admin.GET('/admin/license/reports/{id}/download', {
    params: { path: { id: report.report_id } },
    parseAs: 'blob',
  });
  if (error || !response.ok || !data) throw new Error(messageOf(error, 'Download failed'));
  const url = URL.createObjectURL(data);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${report.report_id}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** "YYYY-MM" of a Date, in UTC — reporting periods are UTC calendar months. */
export function utcMonth(d: Date): string {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/**
 * The periods the Generate modal offers: the current UTC month (a
 * month-to-date preview, never billed) and the closed months before it, back
 * to January 2026 (before usage metering existed), newest first.
 */
export function selectablePeriods(now: Date, max = 12): { value: string; label: string; preview: boolean }[] {
  const out: { value: string; label: string; preview: boolean }[] = [];
  const cursor = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  for (let i = 0; i < max; i++) {
    if (cursor.getUTCFullYear() < 2026) break;
    const value = utcMonth(cursor);
    const name = cursor.toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
    out.push({ value, preview: i === 0, label: i === 0 ? `${name} — month to date (preview)` : name });
    cursor.setUTCMonth(cursor.getUTCMonth() - 1);
  }
  return out;
}
