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

export interface SessionExpiryHandlerOptions {
  /** Does a session exist at all (csrf-cookie presence)? A 401 with no session
   * is an anonymous visitor, not an expiry — never fire the callback for it. */
  hasSession(): boolean;
  /** Exchange the refresh token for a new access token (rejects when dead). */
  refresh(): Promise<unknown>;
  /** The session is unrecoverable: clear local state and send the user to
   * sign-in. Called at most once per page lifetime. */
  onSessionExpired(): void;
}

export function createSessionExpiryHandler(
  opts: SessionExpiryHandlerOptions,
): () => Promise<boolean> {
  let inflight: Promise<boolean> | null = null;
  let expired = false;

  return async () => {
    if (expired || !opts.hasSession()) return false;
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
    if (!recovered && !expired) {
      expired = true;
      opts.onSessionExpired();
    }
    return recovered;
  };
}
