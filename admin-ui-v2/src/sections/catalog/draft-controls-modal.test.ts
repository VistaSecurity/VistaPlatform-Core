// Catalog → Frameworks → "Draft from a standard…", on the platform plane.
//
// Two halves, because the feature has two halves that can break independently:
//
//  - the ACCEPT FLOW, exercised for real against a stub client. The sequence
//    and its partial-failure rules are tested in
//    @vistasecurity/primitives/authoring; what is pinned here is that this app
//    binds them to the PLATFORM endpoints and carries the provenance.
//  - the MODAL STATES, pinned by reading the source. There is no jsdom or
//    React harness in this app (see vitest.config.ts), so this is the same
//    approach the rest of the suite takes — and the state machine itself is
//    unit-tested where it lives.
import { describe, expect, it, vi } from 'vitest';
import { acceptDraft, type ControlDraft } from '@vistasecurity/primitives/authoring';
import { buildAcceptDeps } from './draft-controls-modal';
// Vite `?raw` rather than node:fs — this app has no @types/node, and the
// vite/client types already declare the ?raw suffix.
import src from './draft-controls-modal.tsx?raw';
import pageSrc from './frameworks-page.tsx?raw';

function draft(over: Partial<ControlDraft> = {}): ControlDraft {
  const base: ControlDraft = {
    source_kind: 'inferred',
    source_ref: 'author:test-model',
    confidence: 0,
    model_id: 'test-model',
    control_id: '4.2.1',
    title: 'Strong cryptography',
    description: 'Use strong cryptography.',
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

describe('accept flow (platform endpoints)', () => {
  it('creates the control on the admin route and marks it as drafted', async () => {
    const { client, POST } = stubClient();
    const deps = buildAcceptDeps(client, 'fw-1', new Map([['tls_version', 'mt-1']]));

    const outcome = await acceptDraft(draft(), 'test-model', deps);

    expect(outcome).toEqual({ controlId: 'ctrl-1', rulesAdded: 1, ruleErrors: [] });
    expect(POST).toHaveBeenNthCalledWith(1, '/admin/frameworks/{id}/controls', {
      params: { path: { id: 'fw-1' } },
      body: {
        control_id: '4.2.1',
        title: 'Strong cryptography',
        description: 'Use strong cryptography.',
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
    const deps = buildAcceptDeps(client, 'fw-1', new Map([['tls_version', 'mt-1']]));

    await acceptDraft(draft(), 'test-model', deps);

    expect(POST).toHaveBeenNthCalledWith(2, '/admin/controls/{id}/measurements', {
      params: { path: { id: 'ctrl-1' } },
      body: { measurement_type_id: 'mt-1', rule_type: 'pattern', predicate: { pattern: '^TLS1\\.0$', flags: 'i' }, weight: 1 },
    });
  });

  // The platform plane must never post to the tenant routes: they are gated on
  // a tenant entitlement and would 402 for a platform admin, which reads as a
  // billing problem rather than as a wiring one.
  it('never touches the tenant routes', async () => {
    const { client, POST } = stubClient();
    await acceptDraft(draft(), 'm', buildAcceptDeps(client, 'fw-1', new Map([['tls_version', 'mt-1']])));
    for (const [path] of POST.mock.calls) {
      expect(String(path).startsWith('/admin/')).toBe(true);
    }
  });

  it('surfaces the server’s message when the control cannot be created', async () => {
    const { client } = stubClient((path) =>
      path.endsWith('/controls') ? { error: { error: 'A control with that ID already exists' } } : undefined,
    );
    const deps = buildAcceptDeps(client, 'fw-1', new Map());
    await expect(acceptDraft(draft(), 'm', deps)).rejects.toThrow('A control with that ID already exists');
  });

  // The control exists at this point. Rejecting would invite a retry that
  // creates a second one.
  it('keeps the created control when a rule fails', async () => {
    const { client } = stubClient((path) =>
      path.endsWith('/measurements') ? { error: { error: 'predicate rejected' } } : undefined,
    );
    const deps = buildAcceptDeps(client, 'fw-1', new Map([['tls_version', 'mt-1']]));

    const outcome = await acceptDraft(draft(), 'm', deps);
    expect(outcome.controlId).toBe('ctrl-1');
    expect(outcome.ruleErrors[0]).toContain('predicate rejected');
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

  it('says every draft is unpublished, on the card and in the description', () => {
    expect(src).toMatch(/>unpublished</);
    expect(src).toMatch(/publishing the framework is still a separate step/i);
  });

  // A control with no rule scores "not assessed", not a pass. A reviewer
  // accepting a page of them must not think they have covered the standard.
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

describe('availability gating on the page', () => {
  it('hides the action unless the server says the seam can answer', () => {
    expect(pageSrc).toContain('draftingOffered(draftAvailability.data)');
  });

  // Drafting into a published framework would put unreviewed controls where
  // the reconcile worker walks. The endpoint 409s; the button is hidden so
  // nobody meets that error.
  it('offers it only on an unpublished framework', () => {
    expect(pageSrc).toMatch(/draftingOffered\(draftAvailability\.data\) && !published/);
  });

  it('marks a drafted control in the control list', () => {
    expect(pageSrc).toContain("ctrl.source_kind === 'inferred'");
    expect(pageSrc).toMatch(/>drafted</);
  });
});
