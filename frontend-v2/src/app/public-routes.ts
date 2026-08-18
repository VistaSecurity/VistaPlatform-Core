// The routes reachable while signed out.
//
// These are declared outside <RequireAuth> in App.tsx precisely so an
// unauthenticated visitor is not bounced to /login — the comments there say so
// for the invite, reset and SSO-callback landings, which arrive from email
// links with a token in the URL.
//
// The session-expiry handler in main.tsx has to honour the same list. It fires
// when a request 401s AND a token is present, which is the stale-cookie case:
// a session that has expired, or one signed by a key that no longer exists
// (a redeployed environment regenerates the JWT signing key). Redirecting to
// /login there is right for an app route and wrong for every route in this
// list — it bounces an invited user off the invitation link they just clicked
// and sends them somewhere they cannot act.
//
// Keep this in sync with App.tsx: routing.contract.test.tsx asserts that every
// route declared outside RequireAuth appears here, so adding a public route
// without listing it fails the build rather than silently regressing.
export const PUBLIC_PATHS: readonly string[] = [
  '/login',
  '/signup',
  '/verify-email',
  '/reset-password',
  '/accept-invite',
  '/auth/sso/callback',
  '/register/complete',
  '/register/complete-profile',
  '/legal/terms',
  '/legal/privacy',
];

/** True when `pathname` is a route reachable while signed out. */
export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.includes(pathname);
}
