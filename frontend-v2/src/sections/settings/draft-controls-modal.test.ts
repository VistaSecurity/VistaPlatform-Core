// Settings → Policies → Custom Policies → "Draft from a standard…".
//
// Two halves, because the feature has two halves that can break independently:
//
//  - the ACCEPT FLOW, exercised for real against a stub client. The sequence
//    and its partial-failure rules are tested in
//    @vistasecurity/primitives/authoring; what is pinned here is that this app
//    binds them to the TENANT endpoints and carries the provenance.
//  - the MODAL STATES, pinned by reading the source. There is no jsdom or
//    React harness in this app (see vitest.config.ts), so this is the same
//    approach the rest of the suite takes — and the state machine itself is
//    unit-tested where it lives.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { acceptDraft, type ControlDraft } from '@vistasecurity/primitives/authoring';
import { buildAcceptDeps } from './draft-controls-modal';

const src = readFileSync(fileURLToPath(new URL('./draft-controls-modal.tsx', import.meta.url)), 'utf8');
const detailSrc = readFileSync(fileURLToPath(new URL('./custom-policy-detail.tsx', import.meta.url)), 'utf8');

function draft(over: Partial<ControlDraft> = {}): ControlDraft {
  const base: ControlDraft = {
    source_kind: 'inferred',
    source_ref: 'author:test-model',
    confidence: 0,
    model_id: 'test-model',
    control_id: 'SEC-1',
    title: 'No deprecated ciphers',
    description: 'Disallow 3DES and RC4.',
    severity: 'high',
    published: false,
    citations: [{ kind: 'standard_span', ref: '0-31' }],
    measurements: [
      { measurement_type_code: 'tls_version', rule_type: 'pattern', predicate: { pattern: '^TLS1\\.0$', flags: 'i' } },
    ],
  };
  return { ...base, ...over };
}

/** A stub of the one method buildAcceptDeps uses. */
function stubClient(impl?: (path: string, init: unknown) => unknown) {
  const POST = vi.fn().mockImplementation((path: string, init: unknown) => {
    const custom = impl?.(path, init);
    if (custom !== undefined) return Promise.resolve(custom);
    if (path.endsWith('/controls')) return Promise.resolve({ data: { control: { id: 'ctrl-1' } } });
    return Promise.resolve({ data: {} });
  });
  return { client: { POST } as never, POST };
}

describe('accept flow (tenant endpoints)', () => {
  it('creates the control on the tenant route and marks it as drafted', async () => {
    const { client, POST } = stubClient();
    const deps = buildAcceptDeps(client, 'policy-1', new Map([['tls_version', 'mt-1']]));

    const outcome = await acceptDraft(draft(), 'test-model', deps);

    expect(outcome).toEqual({ controlId: 'ctrl-1', rulesAdded: 1, ruleErrors: [] });
    expect(POST).toHaveBeenNthCalledWith(1, '/frameworks/tenant/{id}/controls', {
      params: { path: { id: 'policy-1' } },
      body: {
        control_id: 'SEC-1',
        title: 'No deprecated ciphers',
        description: 'Disallow 3DES and RC4.',
        baseline_severity: 'high',
        crypto_relevant: true,
        // The whole reason the accept goes through the ordinary endpoint: the
        // row records that a model drafted it, and which one.
        source_kind: 'inferred',
        source_ref: 'author:test-model',
      },
    });
  });

  it('adds each rule to the control the create call returned', async () => {
    const { client, POST } = stubClient();
    const deps = buildAcceptDeps(client, 'policy-1', new Map([['tls_version', 'mt-1']]));

    await acceptDraft(draft(), 'test-model', deps);

    expect(POST).toHaveBeenNthCalledWith(2, '/frameworks/tenant/controls/{id}/measurements', {
      params: { path: { id: 'ctrl-1' } },
      body: { measurement_type_id: 'mt-1', rule_type: 'pattern', predicate: { pattern: '^TLS1\\.0$', flags: 'i' }, weight: 1 },
    });
  });

  // The tenant plane must never post to the admin routes: they are
  // platform-admin only and would 401 for a tenant, which reads as a session
  // problem rather than as a wiring one.
  it('never touches the platform-admin routes', async () => {
    const { client, POST } = stubClient();
    await acceptDraft(draft(), 'm', buildAcceptDeps(client, 'policy-1', new Map([['tls_version', 'mt-1']])));
    for (const [path] of POST.mock.calls) {
      expect(String(path).startsWith('/admin/')).toBe(false);
    }
  });

  it('surfaces the server’s message when the control cannot be created', async () => {
    const { client } = stubClient((path) =>
      path.endsWith('/controls') ? { error: { error: 'Custom policies require an Enterprise subscription' } } : undefined,
    );
    const deps = buildAcceptDeps(client, 'policy-1', new Map());
    await expect(acceptDraft(draft(), 'm', deps)).rejects.toThrow('Enterprise subscription');
  });

  // The control exists at this point. Rejecting would invite a retry that
  // creates a second one.
  it('keeps the created control when a rule fails', async () => {
    const { client } = stubClient((path) =>
      path.endsWith('/measurements') ? { error: { error: 'Validation failed' } } : undefined,
    );
    const deps = buildAcceptDeps(client, 'policy-1', new Map([['tls_version', 'mt-1']]));

    const outcome = await acceptDraft(draft(), 'm', deps);
    expect(outcome.controlId).toBe('ctrl-1');
    expect(outcome.ruleErrors[0]).toContain('Validation failed');
  });
});

describe('modal states', () => {
  it('renders the paste state with a textarea', () => {
    expect(src).toContain('<textarea');
    expect(src).toMatch(/label="The standard"/);
  });

  it('renders a loading state while the model is working', () => {
    expect(src).toContain("state.phase === 'running'");
    expect(src).toMatch(/drafting controls…/i);
  });

  it('renders the error state with the server’s message', () => {
    expect(src).toContain("state.phase === 'error'");
    expect(src).toContain('{state.message}');
  });

  // "The model drafted no controls from this text" is a real answer and must
  // read as one — not as the modal having failed to open.
  it('renders an explicit empty state rather than an empty list', () => {
    expect(src).toContain('state.items.length === 0');
    expect(src).toMatch(/drafted no controls from this text/);
    expect(src).toMatch(/not the same as the text containing no requirements/);
  });

  it('renders the success state with per-draft accept and discard', () => {
    expect(src).toContain('onAccept');
    expect(src).toContain('onDiscard');
    expect(src).toMatch(/'Retry' : 'Accept'/);
  });

  it('shows the cited passage highlighted inside the pasted text', () => {
    expect(src).toContain('citedSegments(source, draft.citations)');
    expect(src).toContain('<mark');
    expect(src).toMatch(/Cited from your text/);
  });

  it('shows the drop report with reasons', () => {
    expect(src).toContain('dropReasonLabel(d.reason)');
    expect(src).toMatch(/discarded before review/);
  });

  it('says every draft is unpublished', () => {
    expect(src).toMatch(/>unpublished</);
  });

  // A control with no rule scores "not assessed", not a pass.
  it('warns when a draft measures nothing', () => {
    expect(src).toMatch(/not assessed.*not to a pass/s);
  });

  it('reports a truncated answer as a partial reading', () => {
    expect(src).toContain('state.truncated');
    expect(src).toMatch(/partial reading of the text/);
  });

  it('says the text is redacted and the call audited', () => {
    expect(src).toMatch(/redacted before it is sent/);
    expect(src).toMatch(/audit log/);
  });
});

describe('availability and permission gating', () => {
  it('hides the action unless the server says the seam can answer', () => {
    expect(detailSrc).toContain('draftingOffered(draftAvailability.data)');
  });

  // canManage already folds in compliance.update AND the interim authoring
  // kill-switch ( — custom policies are not evaluated yet). Drafting into
  // a policy nothing evaluates would be a new way to build something that does
  // nothing, so it hides with the rest of authoring rather than beside it.
  it('offers it only where the rest of authoring is offered', () => {
    expect(detailSrc).toMatch(/canManage && draftingOffered\(draftAvailability\.data\)/);
    expect(detailSrc).toContain('useDraftingAvailability(canManage)');
  });

  it('marks a drafted control in the control list', () => {
    expect(detailSrc).toContain("ctrl.source_kind === 'inferred'");
    expect(detailSrc).toMatch(/>drafted</);
  });
});
