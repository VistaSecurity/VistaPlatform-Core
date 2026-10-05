// The provider row on Settings → AI assistant.
//
// What it says is decided by `providerRowView`, which is pure, so every
// combination the API can return is driven here without rendering. The cases
// that matter are the ones where two different facts would otherwise look the
// same on screen: "your plan does not include this" against "the deployment
// switched it off", and "none connected — connect one" against "none
// configured — and you cannot".
import { describe, expect, it } from 'vitest';
import type { AIStatus } from '../../lib/ai-seams';
import {
  ACTION_LABELS,
  providerKindLabel,
  providerRequestBody,
  providerRowView,
  validateProviderForm,
} from './ai-provider';

function status(patch: Partial<AIStatus>): AIStatus {
  return {
    provider_configured: false,
    edition_linked: true,
    provider_source: 'none',
    provider_kinds: ['anthropic', 'openai_compat'],
    tenant_provider_allowed: true,
    seams: [],
    tenant: { record_questions: false, assistant_disabled: false, authoring_disabled: false },
    ...patch,
  };
}

describe('providerRowView', () => {
  it('offers to connect when nothing answers and the organization may connect its own', () => {
    const v = providerRowView(status({}));
    expect(v.primary).toBe('None connected');
    expect(v.action).toBe('connect');
    expect(v.live).toBe(false);
  });

  it('says whose provider it is when the organization connected its own', () => {
    const v = providerRowView(status({
      provider_configured: true,
      provider_source: 'tenant',
      provider_name: 'openai_compat',
      tenant_provider: { kind: 'openai_compat', host: 'llm.example.com', model: 'm1', has_key: true, api_key_hint: '9876' },
    }));
    expect(v.primary).toBe('OpenAI-compatible · llm.example.com');
    expect(v.tag?.label).toBe('Connected by your organization');
    expect(v.hint).toContain('9876');
    expect(v.action).toBe('change');
    expect(v.live).toBe(true);
    expect(v.saved).toBeUndefined();
  });

  it('says the deployment provides it, and offers the organization its own instead', () => {
    const v = providerRowView(status({ provider_configured: true, provider_source: 'deployment', provider_name: 'anthropic' }));
    expect(v.primary).toBe('Anthropic');
    expect(v.tag?.label).toBe('Provided by this deployment');
    expect(v.action).toBe('use-own');
  });

  it('tells "your plan" apart from "this deployment" when the organization may not connect its own', () => {
    const byPlan = providerRowView(status({ tenant_provider_allowed: false, tenant_provider_blocked_by: 'plan' }));
    const byDeployment = providerRowView(status({ tenant_provider_allowed: false, tenant_provider_blocked_by: 'deployment' }));
    expect(byPlan.action).toBeNull();
    expect(byDeployment.action).toBeNull();
    expect(byPlan.primary).toBe('None configured');
    expect(byPlan.hint).toContain('plan');
    expect(byDeployment.hint).toContain('whoever runs this deployment');
    expect(byPlan.hint).not.toBe(byDeployment.hint);
  });

  it('offers nothing when the build can connect to nothing, whatever the flag says', () => {
    const v = providerRowView(status({ provider_kinds: [], tenant_provider_allowed: true }));
    expect(v.action).toBeNull();
  });

  it('explains the edition, and nothing else, on a Core build', () => {
    const v = providerRowView(status({ edition_linked: false, provider_kinds: [], tenant_provider_allowed: false }));
    expect(v.primary).toBe('Not included in this edition');
    expect(v.action).toBeNull();
    expect(v.hint).toContain('Vista Platform Enterprise');
  });

  it('says so when a saved provider is no longer the one in use', () => {
    const v = providerRowView(status({
      provider_configured: true,
      provider_source: 'deployment',
      provider_name: 'anthropic',
      tenant_provider_allowed: false,
      tenant_provider_blocked_by: 'plan',
      tenant_provider: { kind: 'openai_compat', host: 'llm.example.com', has_key: true },
    }));
    expect(v.tag?.label).toBe('Provided by this deployment');
    expect(v.saved).toContain('llm.example.com');
    expect(v.saved).toContain('not in use');
    expect(v.action).toBeNull();
  });

  it('does not claim a configured-but-broken deployment provider is live', () => {
    const v = providerRowView(status({ provider_configured: false, provider_source: 'deployment', provider_problem: 'x' }));
    expect(v.live).toBe(false);
    expect(v.primary).toBe('Configured, but not available');
  });

  it('falls back to the pre-source fields for an answer that carries no source', () => {
    const v = providerRowView(status({ provider_source: undefined, provider_configured: true, provider_name: 'anthropic' }));
    expect(v.tag?.label).toBe('Provided by this deployment');
  });

  it('has a button label for every action it can return', () => {
    for (const action of ['connect', 'change', 'use-own'] as const) {
      expect(ACTION_LABELS[action]).toBeTruthy();
    }
  });
});

describe('providerKindLabel', () => {
  it('names the kinds the API can return, and falls back to the key', () => {
    expect(providerKindLabel('anthropic')).toBe('Anthropic');
    expect(providerKindLabel('openai_compat')).toBe('OpenAI-compatible');
    expect(providerKindLabel('something_new')).toBe('something_new');
    expect(providerKindLabel(undefined)).toBe('');
  });
});

describe('validateProviderForm', () => {
  const blank = { kind: 'openai_compat', baseUrl: '', model: '', apiKey: '' };

  it('requires an address and a model for an OpenAI-compatible endpoint', () => {
    expect(validateProviderForm(blank, false)).toContain('base URL');
    expect(validateProviderForm({ ...blank, baseUrl: 'https://llm.example.com/v1' }, false)).toContain('model id');
    expect(validateProviderForm({ ...blank, baseUrl: 'https://llm.example.com/v1', model: 'm' }, false)).toBeNull();
  });

  it('does not require a key for an OpenAI-compatible endpoint — a local model has none', () => {
    expect(validateProviderForm({ kind: 'openai_compat', baseUrl: 'http://ollama:11434/v1', model: 'm', apiKey: '' }, false)).toBeNull();
  });

  it('requires a key for Anthropic unless one is already saved', () => {
    const form = { kind: 'anthropic', baseUrl: '', model: '', apiKey: '' };
    expect(validateProviderForm(form, false)).toContain('API key');
    expect(validateProviderForm(form, true)).toBeNull();
    expect(validateProviderForm({ ...form, apiKey: 'sk-ant-x' }, false)).toBeNull();
  });

  it('refuses an address that is not http(s)', () => {
    expect(validateProviderForm({ ...blank, baseUrl: 'llm.example.com', model: 'm' }, false)).toContain('http');
    expect(validateProviderForm({ ...blank, baseUrl: 'ftp://llm.example.com', model: 'm' }, false)).toContain('http');
  });
});

describe('providerRequestBody', () => {
  const form = { kind: 'openai_compat', baseUrl: ' https://llm.example.com/v1 ', model: ' m1 ', apiKey: '' };

  it('omits api_key to keep a saved key — the server decides whether it may', () => {
    const body = providerRequestBody(form, true);
    expect('api_key' in body).toBe(false);
    expect(body.base_url).toBe('https://llm.example.com/v1');
    expect(body.model).toBe('m1');
  });

  it('sends an empty api_key when nothing is saved, which is how "no key" is said', () => {
    expect(providerRequestBody(form, false).api_key).toBe('');
  });

  it('sends a typed key whether or not one is saved', () => {
    expect(providerRequestBody({ ...form, apiKey: ' new-key ' }, true).api_key).toBe('new-key');
    expect(providerRequestBody({ ...form, apiKey: 'new-key' }, false).api_key).toBe('new-key');
  });
});
