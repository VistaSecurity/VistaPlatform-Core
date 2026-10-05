// Settings → AI assistant (platform): the pure helpers the page renders from.
import { describe, expect, it } from 'vitest';
import { formFrom, inEffectSummary, providerKindLabel, requestBody, validateForm, type PlatformAISettings } from './ai-queries';

function settings(patch: Partial<PlatformAISettings>): PlatformAISettings {
  return {
    provider_kinds: ['anthropic', 'openai_compat'],
    can_store_credentials: true,
    in_effect: 'none',
    available: false,
    tenant_providers_allowed: true,
    tenant_private_endpoints_allowed: false,
    ...patch,
  };
}

describe('inEffectSummary', () => {
  it('says nothing is set, and what that means for organizations', () => {
    const s = inEffectSummary(settings({}));
    expect(s.ok).toBe(false);
    expect(s.text).toContain('No default provider');
    expect(s.text).toContain('connect their own');
  });

  it('names the provider set on this page, and that it overrides the install’s', () => {
    const s = inEffectSummary(settings({
      in_effect: 'platform', available: true,
      provider: { kind: 'openai_compat', base_url: 'https://llm.example/v1', model: 'm1', allow_private_endpoints: false, has_key: true },
      environment: { kind: 'anthropic' },
    }));
    expect(s.ok).toBe(true);
    expect(s.text).toContain('OpenAI-compatible (m1)');
    expect(s.text).toContain('set on this page');
    expect(s.text).toContain('overrides the one set at install');
  });

  it('does not mention an override when the install sets nothing', () => {
    const s = inEffectSummary(settings({
      in_effect: 'platform', available: true,
      provider: { kind: 'anthropic', allow_private_endpoints: false, has_key: true },
    }));
    expect(s.text).not.toContain('overrides');
  });

  it('names the provider set at install, and that this page can override it', () => {
    const s = inEffectSummary(settings({ in_effect: 'environment', available: true, environment: { kind: 'anthropic', model: 'x' } }));
    expect(s.ok).toBe(true);
    expect(s.text).toContain('Anthropic (x), set at install');
    expect(s.text).toContain('Setting one here overrides it');
  });

  it('does not call a configured provider that is not answering “ok”', () => {
    const s = inEffectSummary(settings({
      in_effect: 'platform', available: false,
      provider: { kind: 'anthropic', allow_private_endpoints: false, has_key: true },
    }));
    expect(s.ok).toBe(false);
    expect(s.text).toContain('not answering');
  });

  it('explains the edition on a build with no model clients', () => {
    const s = inEffectSummary(settings({ provider_kinds: [] }));
    expect(s.ok).toBe(false);
    expect(s.text).toContain('Vista Platform Enterprise');
  });
});

describe('formFrom', () => {
  it('opens on what is stored, with the key field empty', () => {
    const f = formFrom(settings({
      provider: { kind: 'openai_compat', base_url: 'http://ollama:11434/v1', model: 'llama', allow_private_endpoints: true, has_key: true, api_key_hint: '1234' },
    }));
    expect(f).toEqual({ kind: 'openai_compat', baseUrl: 'http://ollama:11434/v1', model: 'llama', apiKey: '', allowPrivate: true });
  });

  it('opens on the first kind the build has when nothing is stored', () => {
    expect(formFrom(settings({})).kind).toBe('anthropic');
    expect(formFrom(settings({ provider_kinds: ['openai_compat'] })).kind).toBe('openai_compat');
  });
});

describe('validateForm', () => {
  const compat = { kind: 'openai_compat', baseUrl: 'https://llm.example/v1', model: 'm', apiKey: '', allowPrivate: false };

  it('requires an address and a model for an OpenAI-compatible endpoint, and no key', () => {
    expect(validateForm(compat, false, true)).toBeNull();
    expect(validateForm({ ...compat, baseUrl: '' }, false, true)).toContain('base URL');
    expect(validateForm({ ...compat, model: '' }, false, true)).toContain('model id');
  });

  it('requires a key for Anthropic unless one is stored', () => {
    const a = { kind: 'anthropic', baseUrl: '', model: '', apiKey: '', allowPrivate: false };
    expect(validateForm(a, false, true)).toContain('API key');
    expect(validateForm(a, true, true)).toBeNull();
  });

  it('refuses to send a key the deployment cannot store, and still allows a keyless endpoint', () => {
    expect(validateForm({ ...compat, apiKey: 'k' }, false, false)).toContain('ENCRYPTION_MASTER_KEY');
    expect(validateForm(compat, false, false)).toBeNull();
  });

  it('refuses an address that is not http(s)', () => {
    expect(validateForm({ ...compat, baseUrl: 'llm.example' }, false, true)).toContain('http');
  });
});

describe('requestBody', () => {
  const form = { kind: 'openai_compat', baseUrl: ' https://llm.example/v1 ', model: ' m ', apiKey: '', allowPrivate: true };

  it('omits api_key to keep a stored key', () => {
    const b = requestBody(form, true);
    expect('api_key' in b).toBe(false);
    expect(b).toMatchObject({ kind: 'openai_compat', base_url: 'https://llm.example/v1', model: 'm', allow_private_endpoints: true });
  });

  it('sends an empty api_key when nothing is stored — “this endpoint needs no key”', () => {
    expect(requestBody(form, false).api_key).toBe('');
  });

  it('sends a typed key either way', () => {
    expect(requestBody({ ...form, apiKey: ' k ' }, true).api_key).toBe('k');
  });
});

describe('providerKindLabel', () => {
  it('names the kinds and falls back to the key', () => {
    expect(providerKindLabel('anthropic')).toBe('Anthropic');
    expect(providerKindLabel('openai_compat')).toBe('OpenAI-compatible');
    expect(providerKindLabel('new_kind')).toBe('new_kind');
  });
});
