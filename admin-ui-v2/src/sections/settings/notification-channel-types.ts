// Channel transports a platform admin can create, and the failure text for a
// channel Test.
//
// `sms` was offered here although notification-service has no SMS sender — every
// SMS channel failed with "not implemented", permanently. It is not offered any
// more; channels that already exist as `sms` (from the API) still render (the
// edit modal keeps an unlisted existing type as an option).

export const PLATFORM_CHANNEL_TYPES = ['email', 'slack', 'webhook', 'pagerduty'] as const;

/**
 * The reason to show for a failed platform-channel Test. The server answers a
 * channel that did not deliver with 422 and a sanitized `reason` (a fixed
 * vocabulary — never the URL, headers or tokens), so it is safe to display.
 */
export function testFailureReason(error: unknown): string {
  if (error && typeof error === 'object') {
    const reason = (error as { reason?: unknown }).reason;
    if (typeof reason === 'string' && reason.trim()) return reason;
  }
  return 'Test failed';
}
