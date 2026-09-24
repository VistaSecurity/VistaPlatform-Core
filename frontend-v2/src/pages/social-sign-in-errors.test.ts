import { describe, expect, it } from 'vitest';
import { socialSignInErrorMessage } from './social-sign-in-errors';

describe('social sign-in error messages', () => {
  it.each([
    'no_account', 'account_inactive', 'verify_email', 'sso_enforced', 'email_exists',
    'sso_identity_mismatch', 'sso_email_unverified', 'sso_identity_unavailable',
    'sso_identity_ambiguous', 'sso_identity_linked',
  ])('explains %s', (code) => {
    expect(socialSignInErrorMessage(code)).toMatch(/\w/);
  });

  it('shows nothing for no code, an unknown code, or a prototype key', () => {
    expect(socialSignInErrorMessage(null)).toBeNull();
    expect(socialSignInErrorMessage('<script>alert(1)</script>')).toBeNull();
    expect(socialSignInErrorMessage('constructor')).toBeNull();
    expect(socialSignInErrorMessage('__proto__')).toBeNull();
  });
});
