import { expect, it } from 'vitest';
import {
  applyWebhookOptions, generateSigningSecret, initialWebhookOptions, storedHeaderCount, webhookModeOf, webhookOptionsError,
  type WebhookOptions,
} from './webhook-options';

const URL_CFG = { url: 'https://hooks.example.test/••••' };
const opts = (over: Partial<WebhookOptions> = {}): WebhookOptions => ({ ...initialWebhookOptions(null), ...over });

it('reads the current mode off a stored (masked) config', () => {
  expect(webhookModeOf(null)).toBe('none');
  expect(webhookModeOf({ auth: { type: 'bearer', token: '••••wxyz' } })).toBe('bearer');
  expect(webhookModeOf({ auth: { type: 'basic', username: '••••', password: '••••' } })).toBe('basic');
  expect(webhookModeOf({ headers: { 'X-Api-Key': '••••1234' } })).toBe('header');
  expect(webhookModeOf({ headers: {} })).toBe('none');
});

it('never prefills a credential', () => {
  const o = initialWebhookOptions({ auth: { type: 'bearer', token: '••••wxyz' }, webhook_secret: '••••abcd' });
  expect(o).toMatchObject({ mode: 'bearer', token: '', username: '', password: '', headerValue: '', signingSecret: '' });
  expect(initialWebhookOptions({ headers: { 'X-Api-Key': '••••1234' } })).toMatchObject({ mode: 'header', headerName: 'X-Api-Key', headerValue: '' });
});

it('bearer: the token goes in auth; a blank token on edit is left out so the server keeps it', () => {
  expect(applyWebhookOptions({ ...URL_CFG }, opts({ mode: 'bearer', token: ' tok_test_only ' }))).toEqual({
    ...URL_CFG, auth: { type: 'bearer', token: 'tok_test_only' },
  });
  expect(applyWebhookOptions({ ...URL_CFG }, opts({ mode: 'bearer' }))).toEqual({ ...URL_CFG, auth: { type: 'bearer' } });
});

it('basic: username + password', () => {
  expect(applyWebhookOptions({ ...URL_CFG }, opts({ mode: 'basic', username: 'svc', password: 'pw_test_only' }))).toEqual({
    ...URL_CFG, auth: { type: 'basic', username: 'svc', password: 'pw_test_only' },
  });
});

it('custom header: exactly one header; blank value is sent blank (keeps the stored value)', () => {
  expect(applyWebhookOptions({ ...URL_CFG }, opts({ mode: 'header', headerName: 'X-Api-Key', headerValue: 'k_test_only' }))).toEqual({
    ...URL_CFG, headers: { 'X-Api-Key': 'k_test_only' },
  });
  expect(applyWebhookOptions({ ...URL_CFG }, opts({ mode: 'header', headerName: 'X-Api-Key' }))).toEqual({ ...URL_CFG, headers: { 'X-Api-Key': '' } });
});

it('none removes auth and headers that were carried through from the GET', () => {
  const carried = { ...URL_CFG, auth: { type: 'bearer', token: '••••wxyz' }, headers: { 'X-Api-Key': '••••1234' } };
  expect(applyWebhookOptions(carried, opts({ mode: 'none' }))).toEqual(URL_CFG);
});

it('switching mode drops the previous mode\'s object', () => {
  const carried = { ...URL_CFG, auth: { type: 'bearer', token: '••••wxyz' } };
  const out = applyWebhookOptions(carried, opts({ mode: 'header', headerName: 'X-Api-Key', headerValue: 'k' }));
  expect(out).not.toHaveProperty('auth');
  expect(out.headers).toEqual({ 'X-Api-Key': 'k' });
});

// The masked signing secret from the GET must NEVER ride along as if it were new —
// that would overwrite the real secret with its own mask (the server would treat the
// masked form as "unchanged", but a client must not depend on that).
it('the signing secret is sent only when typed; a carried masked one is dropped', () => {
  const carried = { ...URL_CFG, webhook_secret: '••••abcd' };
  expect(applyWebhookOptions(carried, opts())).not.toHaveProperty('webhook_secret');
  expect(applyWebhookOptions(carried, opts({ signingSecret: ' whsec_new_value ' }))).toHaveProperty('webhook_secret', 'whsec_new_value');
});

it('create requires the credential for the chosen mode', () => {
  expect(webhookOptionsError(opts({ mode: 'none' }), null, false)).toBeNull();
  expect(webhookOptionsError(opts({ mode: 'bearer' }), null, false)).toMatch(/bearer token/i);
  expect(webhookOptionsError(opts({ mode: 'bearer', token: 't' }), null, false)).toBeNull();
  expect(webhookOptionsError(opts({ mode: 'basic', username: 'u' }), null, false)).toMatch(/password/i);
  expect(webhookOptionsError(opts({ mode: 'header', headerName: 'X-Key' }), null, false)).toMatch(/header value/i);
  expect(webhookOptionsError(opts({ mode: 'header', headerName: 'bad name', headerValue: 'v' }), null, false)).toMatch(/valid HTTP header name/i);
  expect(webhookOptionsError(opts({ mode: 'header', headerValue: 'v' }), null, false)).toMatch(/header name/i);
});

it('edit: a blank credential is fine only when it keeps a stored one of the same kind', () => {
  const stored = { auth: { type: 'bearer', token: '••••wxyz' } };
  // same mode, blank => keep
  expect(webhookOptionsError(opts({ mode: 'bearer' }), stored, true)).toBeNull();
  // switching to a mode that has nothing stored => must enter one
  expect(webhookOptionsError(opts({ mode: 'basic' }), stored, true)).toMatch(/username/i);
  const storedHeader = { headers: { 'X-Api-Key': '••••1234' } };
  expect(webhookOptionsError(opts({ mode: 'header', headerName: 'x-api-key' }), storedHeader, true)).toBeNull();
  // renaming the header is a new credential
  expect(webhookOptionsError(opts({ mode: 'header', headerName: 'X-Other' }), storedHeader, true)).toMatch(/header value/i);
});

it('counts stored headers so the form can warn that saving replaces the extras', () => {
  expect(storedHeaderCount(null)).toBe(0);
  expect(storedHeaderCount({ headers: { A: '1', B: '2' } })).toBe(2);
});

it('generates a signing secret in the server\'s shape', () => {
  const a = generateSigningSecret();
  expect(a).toMatch(/^whsec_[0-9a-f]{64}$/);
  expect(generateSigningSecret()).not.toBe(a);
});
