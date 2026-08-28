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
//
// The second phase, `onRecoveryFailed`, closes the LAST way to get stranded:
// the refresh exchange succeeds but the replayed request still 401s (the
// data plane rejects the token auth just minted — revoked session family,
// key mismatch, whatever). Every path above latches only when the refresh
// REJECTS, so this state used to loop silently: refresh 200 → replay 401 →
// error card, on every load, with no redirect ever. Now the replay-401
// triggers a single confirmation probe (`checkSession`, a bare fetch that
// deliberately does NOT ride the api-contract middleware — that would
// recurse); if the probe says the session is dead, the same latch fires. If
// the probe says the session is alive, the 401 was one buggy endpoint and the
// user is NOT evicted — wrongly bouncing users off working sessions is the
// same bug pointed the other way (see the public-routes guard).

/** Why the session ended, so the app can word the sign-in prompt correctly.
 *  - 'expired'    — a session existed and the refresh exchange failed, or a
 *                   "successful" refresh produced a session that doesn't work.
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
  /** Confirm whether the session works at all, after a recovered-then-401
   * replay. Resolves true = alive (don't evict; the 401 came from one buggy
   * endpoint), false = dead (latch and navigate). MUST be a bare fetch to the
   * app's whoami endpoint, not an api-contract client — a client call would
   * re-enter the 401 middleware and recurse. A rejection (network error)
   * counts as alive: never evict on uncertainty. Optional; when absent, a
   * recovered-then-401 replay latches directly. */
  checkSession?(): Promise<boolean>;
}

/** The two-phase handler consumed by api-contract's `setSessionExpiredHandler`. */
export interface SessionExpiryHandlers {
  onAuthFailure(): Promise<boolean>;
  onRecoveryFailed(): Promise<void>;
}

export function createSessionExpiryHandler(
  opts: SessionExpiryHandlerOptions,
): SessionExpiryHandlers {
  let inflight: Promise<boolean> | null = null;
  let confirming: Promise<void> | null = null;
  let expired = false;

  const giveUp = (reason: SessionExpiredReason): boolean => {
    if (!expired) {
      expired = true;
      opts.onSessionExpired(reason);
    }
    return false;
  };

  return {
    async onAuthFailure() {
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
    },

    async onRecoveryFailed() {
      if (expired) return;
      const check = opts.checkSession;
      if (!check) {
        giveUp('expired');
        return;
      }
      // One probe per burst: concurrent replay-401s share it, same shape as
      // the shared refresh above.
      if (!confirming) {
        confirming = check().then(
          (alive) => {
            if (!alive) giveUp('expired');
          },
          () => {
            // Probe itself failed (network, 5xx mapped to rejection): session
            // state is unknown — do not evict. The next 401 will re-probe.
          },
        );
        confirming.finally(() => {
          confirming = null;
        });
      }
      await confirming;
    },
  };
}
