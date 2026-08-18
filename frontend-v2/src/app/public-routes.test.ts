// Guards the predicate the session-expiry handler in main.tsx branches on.
//
// The bug this exists for: that handler exempted only '/login', so a visitor
// holding a stale cookie — an expired session, or one signed by a key that no
// longer exists after an environment is redeployed — was redirected off
// /signup, /accept-invite and /reset-password. Those are the routes declared
// outside RequireAuth precisely so they work signed out, and two of them are
// email landings where being bounced to /login strands the user completely.
//
// The handler only fires when a token is PRESENT, which is why the symptom
// looks like a cache problem: an incognito window has no cookie and works.
import { describe, expect, it } from 'vitest';
import { PUBLIC_PATHS, isPublicPath } from './public-routes';

describe('isPublicPath', () => {
  it.each(PUBLIC_PATHS)('%s is public, so a stale cookie must not redirect it', (path) => {
    expect(isPublicPath(path)).toBe(true);
  });

  // The email landings are called out separately: they are the cases where a
  // wrong redirect does the most damage, because the token is in the URL and
  // bouncing loses it.
  it.each(['/accept-invite', '/reset-password', '/register/complete', '/auth/sso/callback'])(
    '%s (email landing) stays reachable with a stale session',
    (path) => {
      expect(isPublicPath(path)).toBe(true);
    },
  );

  it.each(['/dashboard', '/inventory', '/settings/people', '/risk-compliance/posture', '/'])(
    '%s is an app route and must still redirect',
    (path) => {
      expect(isPublicPath(path)).toBe(false);
    },
  );

  it('does not treat a prefix match as public', () => {
    // '/signup' is public; '/signup-admin' is not a declared route and must not
    // inherit publicness from a substring match.
    expect(isPublicPath('/signupsomething')).toBe(false);
    expect(isPublicPath('/legal')).toBe(false);
  });
});
