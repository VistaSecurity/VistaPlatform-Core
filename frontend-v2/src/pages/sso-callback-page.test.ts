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

  it('never renders provider-supplied text: a bare error_description gets the generic message', () => {
    const params = new URLSearchParams({ error_description: 'Identity provider rejected sign-in' });
    const msg = getSsoCallbackError(params);
    expect(msg).toContain('couldn’t complete single sign-on');
    expect(msg).not.toContain('rejected');
  });

  it('maps a known error code to our own wording', () => {
    expect(getSsoCallbackError(new URLSearchParams({ error: 'no_account' }))).toContain('No account is linked');
  });

  it('shows the generic message for an unknown, attacker-chosen error value', () => {
    const msg = getSsoCallbackError(new URLSearchParams({ error: '<script>phish', error_description: 'Call 555-0100' }));
    expect(msg).toContain('couldn’t complete single sign-on');
    expect(msg).not.toContain('phish');
    expect(msg).not.toContain('555');
  });

  it('fails closed before considering a provider error when a URL token is present', () => {
    const params = new URLSearchParams({
      access_token: 'secret-token',
      error_description: 'Attacker-controlled text',
    });
    expect(getSsoCallbackError(params)).toContain('obsolete and insecure format');
  });
});
