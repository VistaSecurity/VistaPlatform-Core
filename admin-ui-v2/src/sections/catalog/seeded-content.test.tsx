import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AcceptUpdateButton, SeededContentBadges, describeOffer } from './seeded-content';

// The seeded-content badges and the "Update available" action shared by
// Catalog ▸ Frameworks (frameworks, controls, measurement rules) and
// Catalog ▸ Classification rules (decision 4, RC-12).

const html = (el: ReturnType<typeof createElement>) => renderToStaticMarkup(el);

describe('SeededContentBadges', () => {
  it('marks shipped content, and shipped content edited here', () => {
    expect(html(createElement(SeededContentBadges, { row: { content_origin: 'vista' } }))).toContain('>Vista<');
    const edited = html(createElement(SeededContentBadges, { row: { content_origin: 'vista', admin_modified: true } }));
    expect(edited).toContain('>Modified<');
    expect(edited).toContain('Upgrades keep this version');
  });

  it('marks a custom row as custom and never as modified', () => {
    const custom = html(createElement(SeededContentBadges, { row: { content_origin: 'custom', admin_modified: true } }));
    expect(custom).toContain('>Custom<');
    expect(custom).not.toContain('Modified');
  });

  it('renders nothing for a row from a read that does not report origin', () => {
    expect(html(createElement(SeededContentBadges, { row: {} }))).toBe('');
  });
});

describe('describeOffer', () => {
  it('lists each offered field as current → shipped, sorted', () => {
    expect(describeOffer({ title: 'Ours', weight: 3, offered_update: { weight: 9, title: 'Shipped' } }))
      .toBe('title: Ours → Shipped\nweight: 3 → 9');
  });

  it('names an absent current value rather than printing undefined', () => {
    expect(describeOffer({ offered_update: { model: 'X1' } })).toBe('model: (none) → X1');
  });
});

describe('AcceptUpdateButton', () => {
  it('is absent when nothing is on offer', () => {
    expect(html(createElement(AcceptUpdateButton, { row: { update_available: false }, pending: false, onAccept: vi.fn(), label: 'BP-001' }))).toBe('');
  });

  it('offers the update, naming the row and what accepting writes', () => {
    const out = html(createElement(AcceptUpdateButton, {
      row: { update_available: true, title: 'Ours', offered_update: { title: 'Shipped' } },
      pending: false, onAccept: vi.fn(), label: 'BP-001',
    }));
    expect(out).toContain('Update available');
    expect(out).toContain('Accept the shipped update for BP-001');
    expect(out).toContain('title: Ours → Shipped');
  });

  it('is disabled while an accept is in flight', () => {
    const out = html(createElement(AcceptUpdateButton, {
      row: { update_available: true, offered_update: { title: 'Shipped' } },
      pending: true, onAccept: vi.fn(), label: 'BP-001',
    }));
    expect(out).toContain('disabled');
  });
});
