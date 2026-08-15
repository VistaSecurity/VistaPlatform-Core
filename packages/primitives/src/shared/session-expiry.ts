// Session-expiry handler for the api-contract 401 middleware. Headless: the
// app supplies the cookie check, the refresh call, and what to do when the
// session is truly dead (clear + navigate to /login). Register the result via
// `setSessionExpiredHandler` from @vistasecurity/api-contract at startup.
//
// Semantics: on the first 401 of a burst, run ONE refresh-token exchange (all
// concurrent 401s await the same in-flight promise). If it succeeds, report
// "recovered" so the middleware can replay idempotent requests. If it fails,
// fire `onSessionExpired` exactly once and answer false forever after — the
// callback navigates away, so the latch only has to hold until page unload.
//
// A 401 with no session signal at all still fires the callback (with reason
// 'no-session'), it just skips the pointless refresh. Returning silently there
// is what stranded users on "Couldn't load …" cards: nothing navigated, so the
// only feedback was one error card per panel.

/** Why the session ended, so the app can word the sign-in prompt correctly.
 *  - 'expired'    — a session existed and the refresh exchange failed.
 *  - 'no-session' — a protected call 401'd with no session signal present. */
export type SessionExpiredReason = 'expired' | 'no-session';

export interface SessionExpiryHandlerOptions {
  /** Does a session exist at all (csrf-cookie presence)? When false the refresh
   * exchange is skipped — there is no session to refresh. */
  hasSession(): boolean;
  /** Exchange the refresh token for a new access token (rejects when dead). */
  refresh(): Promise<unknown>;
  /** The session is unrecoverable: clear local state and send the user to
   * sign-in. Called at most once per page lifetime. */
  onSessionExpired(reason: SessionExpiredReason): void;
}

export function createSessionExpiryHandler(
  opts: SessionExpiryHandlerOptions,
): () => Promise<boolean> {
  let inflight: Promise<boolean> | null = null;
  let expired = false;

  const giveUp = (reason: SessionExpiredReason): boolean => {
    if (!expired) {
      expired = true;
      opts.onSessionExpired(reason);
    }
    return false;
  };

  return async () => {
    if (expired) return false;
    if (!opts.hasSession()) return giveUp('no-session');
    if (!inflight) {
      inflight = opts.refresh().then(
        () => true,
        () => false,
      );
      inflight.finally(() => {
        inflight = null;
      });
    }
    const recovered = await inflight;
    return recovered || giveUp('expired');
  };
}
