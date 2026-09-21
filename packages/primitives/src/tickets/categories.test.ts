import { describe, expect, it } from 'vitest';
import { FINDING_PRODUCERS } from '../findings';
import {
  LEGACY_TICKET_CATEGORIES,
  TICKET_CATEGORIES,
  TICKET_CATEGORY_KEYS,
  categoryForProducer,
  isWritableTicketCategory,
  ticketCategory,
} from './categories';

describe('ticket category registry', () => {
  it('gives every finding producer a category to become', () => {
    // The reason this registry exists. Before the split, five of the seven
    // producers collapsed into one `remediation` bucket, which made a category
    // filter on the work queue meaningless. A producer with no category of its
    // own would silently fall back to `general` and recreate that.
    for (const p of FINDING_PRODUCERS) {
      const mapped = categoryForProducer(p.key);
      expect(
        TICKET_CATEGORIES.some((c) => c.producer === p.key),
        `producer ${p.key} has no ticket category`,
      ).toBe(true);
      expect(mapped, `producer ${p.key} fell through to general`).not.toBe('general');
    }
  });

  it('splits PQC out of cryptography only for the pqc_vulnerable kind', () => {
    expect(categoryForProducer('crypto', 'pqc_vulnerable')).toBe('pqc');
    expect(categoryForProducer('crypto', 'weak_configuration')).toBe('crypto');
    expect(categoryForProducer('crypto', 'weak_certificate')).toBe('crypto');
    // No kind means the safe half: calling PQC work "cryptography" is a lesser
    // error than labelling a weak cipher suite as quantum migration.
    expect(categoryForProducer('crypto')).toBe('crypto');
  });

  it('falls back to general for a producer it has never heard of', () => {
    expect(categoryForProducer('something_new')).toBe('general');
    expect(categoryForProducer(undefined)).toBe('general');
  });

  it('keys are unique and match the exported key list', () => {
    expect(new Set(TICKET_CATEGORY_KEYS).size).toBe(TICKET_CATEGORIES.length);
    expect(TICKET_CATEGORY_KEYS).toEqual(TICKET_CATEGORIES.map((c) => c.key));
  });

  it('never offers a retired category as writable', () => {
    for (const legacy of LEGACY_TICKET_CATEGORIES) {
      expect(isWritableTicketCategory(legacy)).toBe(false);
      expect(TICKET_CATEGORY_KEYS).not.toContain(legacy as string);
    }
  });

  it('still resolves a retired category so old rows render a label', () => {
    // A pre-split row whose category resolved to undefined would render a
    // blank cell in the queue — the row would look broken rather than old.
    const remediation = ticketCategory('remediation');
    expect(remediation?.label).toBe('Remediation');
    expect(remediation?.icon).toBeTruthy();
  });

  it('returns undefined for an unknown category rather than inventing one', () => {
    expect(ticketCategory('not_a_category')).toBeUndefined();
    expect(ticketCategory(undefined)).toBeUndefined();
    expect(ticketCategory('')).toBeUndefined();
  });

  it('every category carries a label, an icon and a description', () => {
    for (const c of [...TICKET_CATEGORIES, ticketCategory('remediation')!]) {
      expect(c.label.length, `${c.key} label`).toBeGreaterThan(0);
      expect(c.icon.length, `${c.key} icon`).toBeGreaterThan(0);
      expect(c.description.length, `${c.key} description`).toBeGreaterThan(0);
    }
  });
});
