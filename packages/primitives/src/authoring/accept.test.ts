import { describe, expect, it, vi } from 'vitest';
import { acceptDraft, acceptSummary, controlBodyFor, measurementBodyFor, type AcceptDeps } from './accept';
import type { ControlDraft } from './drafts';

function draft(over: Partial<ControlDraft> = {}): ControlDraft {
  return {
    source_kind: 'inferred',
    source_ref: 'author:model',
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
    ...over,
  } as ControlDraft;
}

function deps(over: Partial<AcceptDeps> = {}): AcceptDeps {
  return {
    createControl: vi.fn().mockResolvedValue('control-1'),
    addMeasurement: vi.fn().mockResolvedValue(undefined),
    measurementTypeId: (code: string) => (code === 'tls_version' ? 'mt-1' : undefined),
    ...over,
  };
}

describe('controlBodyFor', () => {
  it('marks the control as inferred and names the model that drafted it', () => {
    const body = controlBodyFor(draft(), 'test-model');
    expect(body.source_kind).toBe('inferred');
    expect(body.source_ref).toBe('author:test-model');
  });

  it('rejects a severity outside the four the column admits', () => {
    expect(() => controlBodyFor(draft({ severity: 'catastrophic' as never }), 'm')).toThrow();
    expect(() => controlBodyFor(draft({ severity: undefined }), 'm')).toThrow();
    expect(controlBodyFor(draft({ severity: 'critical' }), 'm').baseline_severity).toBe('critical');
  });

  // A control with no rule is not evidence of cryptographic relevance. Flagging
  // every draft as relevant would quietly inflate the crypto-control count on
  // every framework it touched.
  it('flags crypto_relevant only when the draft actually measures something', () => {
    expect(controlBodyFor(draft(), 'm').crypto_relevant).toBe(true);
    expect(controlBodyFor(draft({ measurements: [] }), 'm').crypto_relevant).toBe(false);
    expect(controlBodyFor(draft({ measurements: undefined }), 'm').crypto_relevant).toBe(false);
  });

  it('falls back to the title when the model suggested no control id', () => {
    const body = controlBodyFor(draft({ control_id: '  ' }), 'm');
    expect(body.control_id).toBe('Strong cryptography');
    expect(body.control_id.length).toBeLessThanOrEqual(100);
  });
});

describe('measurementBodyFor', () => {
  it('resolves the code to this deployment’s measurement id', () => {
    const body = measurementBodyFor(
      { measurement_type_code: 'tls_version', rule_type: 'pattern', predicate: { pattern: 'x' } },
      (c) => (c === 'tls_version' ? 'mt-1' : undefined),
    );
    expect(body).toEqual({ measurement_type_id: 'mt-1', rule_type: 'pattern', predicate: { pattern: 'x' }, weight: 1 });
  });

  it('returns null for a code the catalogue does not have', () => {
    expect(measurementBodyFor({ measurement_type_code: 'nope', rule_type: 'presence', predicate: {} }, () => undefined)).toBeNull();
  });
});

describe('acceptDraft', () => {
  it.each(['info', 'Med', 'High', 'invalid', ''])('rejects %s before any writes', async (severity) => {
    const d = deps();
    await expect(acceptDraft(draft({ severity: severity as never }), 'm', d)).rejects.toThrow();
    expect(d.createControl).not.toHaveBeenCalled();
    expect(d.addMeasurement).not.toHaveBeenCalled();
  });

  it('creates the control then adds each rule, in that order', async () => {
    const order: string[] = [];
    const d = deps({
      createControl: vi.fn().mockImplementation(async () => {
        order.push('control');
        return 'control-1';
      }),
      addMeasurement: vi.fn().mockImplementation(async () => {
        order.push('rule');
      }),
    });

    const outcome = await acceptDraft(draft(), 'test-model', d);
    expect(order).toEqual(['control', 'rule']);
    expect(outcome).toEqual({ controlId: 'control-1', rulesAdded: 1, ruleErrors: [] });
    expect(d.addMeasurement).toHaveBeenCalledWith('control-1', {
      measurement_type_id: 'mt-1',
      rule_type: 'pattern',
      predicate: { pattern: '^TLS1\\.0$', flags: 'i' },
      weight: 1,
    });
  });

  // Nothing was written, so retrying is exactly right and the caller needs to
  // know it can.
  it('rejects when the control itself could not be created', async () => {
    const d = deps({ createControl: vi.fn().mockRejectedValue(new Error('duplicate control id')) });
    await expect(acceptDraft(draft(), 'm', d)).rejects.toThrow('duplicate control id');
    expect(d.addMeasurement).not.toHaveBeenCalled();
  });

  // The row EXISTS. Reporting the whole accept as failed would invite a retry
  // that creates a second control with the same id — and a duplicated control
  // in a published framework is a duplicated finding for every tenant.
  it('resolves with the failures listed when a rule fails after the control was created', async () => {
    const d = deps({ addMeasurement: vi.fn().mockRejectedValue(new Error('predicate rejected')) });
    const outcome = await acceptDraft(draft(), 'm', d);
    expect(outcome.controlId).toBe('control-1');
    expect(outcome.rulesAdded).toBe(0);
    expect(outcome.ruleErrors).toHaveLength(1);
    expect(outcome.ruleErrors[0]).toContain('predicate rejected');
  });

  it('reports a rule whose measurement type vanished between drafting and accepting', async () => {
    const d = deps({ measurementTypeId: () => undefined });
    const outcome = await acceptDraft(draft(), 'm', d);
    expect(outcome.rulesAdded).toBe(0);
    expect(outcome.ruleErrors[0]).toContain('tls_version');
    expect(d.addMeasurement).not.toHaveBeenCalled();
  });

  it('accepts a draft with no rules at all', async () => {
    const d = deps();
    const outcome = await acceptDraft(draft({ measurements: [] }), 'm', d);
    expect(outcome).toEqual({ controlId: 'control-1', rulesAdded: 0, ruleErrors: [] });
    expect(d.addMeasurement).not.toHaveBeenCalled();
  });
});

describe('acceptSummary', () => {
  it('says the control is unpublished, every time', () => {
    for (const outcome of [
      { controlId: 'c', rulesAdded: 0, ruleErrors: [] },
      { controlId: 'c', rulesAdded: 2, ruleErrors: [] },
      { controlId: 'c', rulesAdded: 1, ruleErrors: ['x'] },
    ]) {
      expect(acceptSummary(outcome)).toContain('unpublished');
    }
  });

  // A control with no rule scores "not assessed" and is excluded from the
  // score. It is not a control that passes, and a reviewer accepting a page of
  // them would otherwise believe they had covered the standard.
  it('warns when the accepted control measures nothing', () => {
    expect(acceptSummary({ controlId: 'c', rulesAdded: 0, ruleErrors: [] })).toContain('not assessed');
  });

  it('names the rules that could not be added', () => {
    const msg = acceptSummary({ controlId: 'c', rulesAdded: 1, ruleErrors: ['Rule on "x" could not be added: boom'] });
    expect(msg).toContain('1 rule could not be');
    expect(msg).toContain('boom');
  });
});
