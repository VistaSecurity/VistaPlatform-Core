import { describe, expect, it } from 'vitest';
import { getSsoCallbackError } from './sso-callback-page';

describe('SSO callback security contract', () => {
  it.each(['access_token', 'refresh_token', 'id_token'])('rejects a URL containing %s without exposing its value', (name) => {
    const secret = 'secret-that-must-not-be-rendered';
    const error = getSsoCallbackError(new URLSearchParams({ [name]: secret }));

    expect(error).toContain('obsolete and insecure format');
    expect(error).not.toContain(secret);
  });

  it('allows the cookie-backed callback when no URL token is present', () => {
    expect(getSsoCallbackError(new URLSearchParams())).toBeNull();
  });

  it('preserves provider errors for the signed-out failure page', () => {
    const params = new URLSearchParams({ error_description: 'Identity provider rejected sign-in' });
    expect(getSsoCallbackError(params)).toBe('Identity provider rejected sign-in');
  });

  it('fails closed before considering a provider error when a URL token is present', () => {
    const params = new URLSearchParams({
      access_token: 'secret-token',
      error_description: 'Attacker-controlled text',
    });
    expect(getSsoCallbackError(params)).toContain('obsolete and insecure format');
  });
});
