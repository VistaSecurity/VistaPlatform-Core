// Messages for the ?error= codes the returning social sign-in ("Continue with
// Google/Microsoft" through Vista's shared sign-up app) redirects to /login
// with — auth-service ee/sso/platform_sso.go and platform_sso_identity.go.
// Unknown codes map to null so the page shows nothing rather than echoing
// arbitrary query-string text.
const SOCIAL_SIGN_IN_ERRORS: Record<string, string> = {
  no_account: 'No account is linked to that sign-in. Sign up first, or sign in with your password.',
  account_inactive: 'This account is deactivated. Contact your organization administrator.',
  verify_email: 'Confirm your email address first — check your inbox for the verification link, then sign in again.',
  sso_enforced: 'Your organization requires its own single sign-on. Enter your email to continue.',
  email_exists: 'An account with this email already exists. Sign in instead.',
  sso_identity_mismatch: 'That email address belongs to an account linked to a different sign-in at this provider, so it cannot be used here.',
  sso_email_unverified: 'The provider did not confirm that email address is verified, so it cannot be used to sign in.',
  sso_identity_unavailable: 'The provider did not return a stable account identifier, so this sign-in cannot be used.',
  sso_identity_ambiguous: 'This sign-in matches more than one account. Contact support to resolve it.',
  sso_identity_linked: 'This sign-in is already linked to an account. Sign in instead.',
};

export function socialSignInErrorMessage(code: string | null): string | null {
  if (!code) return null;
  return Object.prototype.hasOwnProperty.call(SOCIAL_SIGN_IN_ERRORS, code) ? SOCIAL_SIGN_IN_ERRORS[code] : null;
}
