// The verify drawer's hash verdict has three states, and the one that used to
// be missing is the one that matters most to a customer.
//
// A CBOM artifact is evidence. When its bytes cannot be read — object-store
// credentials rotated, object expired, storage never wired — the server
// answers hash_valid=false with hash_recomputed OMITTED, meaning "nothing was
// compared". The drawer branched on hash_valid alone and painted that as a red
// "Hash mismatch" with no explanation, telling an operator holding an
// untampered artifact that its integrity check had failed.
import { describe, it, expect } from 'vitest';
import { hashVerdict } from './kit';

describe('hashVerdict', () => {
  it('reports a verified hash', () => {
    const v = hashVerdict({ hash_valid: true, hash_stored: 'a'.repeat(64), hash_recomputed: 'a'.repeat(64) });
    expect(v.state).toBe('verified');
    expect(v.label).toBe('Hash verified');
    expect(v.tone).toBe('var(--ok)');
  });

  it('reports a real mismatch, with the two hashes', () => {
    const v = hashVerdict({ hash_valid: false, hash_stored: 'a'.repeat(64), hash_recomputed: 'b'.repeat(64) });
    expect(v.state).toBe('mismatch');
    expect(v.label).toBe('Hash mismatch');
    expect(v.tone).toBe('var(--danger)');
    // The explanatory line is the whole point of the red state — a mismatch
    // with no numbers is an accusation without evidence.
    expect(v.detail).toContain('expected');
    expect(v.detail).toContain('got');
  });

  it('does NOT report a mismatch when the bytes could not be read', () => {
    // The headline guarantee. hash_valid is false in both this case and the
    // one above; only the absence of hash_recomputed separates them.
    const v = hashVerdict({ hash_valid: false, hash_stored: 'a'.repeat(64) });
    expect(v.state).toBe('not-checked');
    expect(v.label).not.toContain('mismatch');
    expect(v.tone).not.toBe('var(--danger)');
    // And it must say why, rather than leaving a bare verdict on screen.
    expect(v.detail).toBeTruthy();
    expect(v.detail).toContain('not a tamper signal');
  });

  it('treats an empty-string hash_recomputed as not-checked too', () => {
    // openapi-typescript models the omitted field as optional, but a client
    // that normalises undefined to '' must land in the same place — '' is not
    // a hash anyone computed.
    const v = hashVerdict({ hash_valid: false, hash_stored: 'a'.repeat(64), hash_recomputed: '' });
    expect(v.state).toBe('not-checked');
  });

  it('never returns the danger tone without a recomputed hash to justify it', () => {
    for (const recomputed of [undefined, '']) {
      const v = hashVerdict({ hash_valid: false, hash_stored: 'a'.repeat(64), hash_recomputed: recomputed });
      expect(v.tone).not.toBe('var(--danger)');
      expect(v.icon).not.toBe('shield-x');
    }
  });
});
