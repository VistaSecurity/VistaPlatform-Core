// The selection model behind Inventory's multi-select.
import { describe, expect, it } from 'vitest';
import {
  MAX_BULK, MAX_BULK_SCAN, NO_SELECTION, isSelected, offerSelectAll, overCapReason, pageState,
  selectAllMatching, selectedCount, selectionBody, selectionRefusal, toggleRow, togglePage, type AssetSelection,
} from './asset-selection';

const page = ['a', 'b', 'c'];
const ids = (...xs: string[]): AssetSelection => ({ kind: 'ids', ids: new Set(xs) });

describe('ticking rows', () => {
  it('ticks and unticks one row; nothing ticked is no selection', () => {
    const one = toggleRow(NO_SELECTION, 'a', page);
    expect(selectedCount(one)).toBe(1);
    expect(isSelected(one, 'a')).toBe(true);
    expect(toggleRow(one, 'a', page)).toEqual(NO_SELECTION);
  });

  it('keeps rows ticked on other pages when this page is ticked and unticked', () => {
    const elsewhere = ids('z');
    const all = togglePage(elsewhere, page);
    expect(pageState(all, page)).toBe('all');
    expect(selectedCount(all)).toBe(4);
    const none = togglePage(all, page);
    expect(pageState(none, page)).toBe('none');
    expect(isSelected(none, 'z')).toBe(true);
  });

  it('a partly ticked page is "some", and the header ticks the rest', () => {
    expect(pageState(ids('a'), page)).toBe('some');
    expect(pageState(togglePage(ids('a'), page), page)).toBe('all');
  });
});

describe('select all matching', () => {
  it('is offered only when the whole page is ticked, more match, and the rows ARE the query', () => {
    expect(offerSelectAll(ids('a', 'b', 'c'), page, 40, true)).toBe(true);
    expect(offerSelectAll(ids('a', 'b'), page, 40, true)).toBe(false);
    expect(offerSelectAll(ids('a', 'b', 'c'), page, 3, true)).toBe(false);
    // A lens filtering in the browser: "all matching" would mean more than shown.
    expect(offerSelectAll(ids('a', 'b', 'c'), page, 40, false)).toBe(false);
  });

  it('selects the query and its count; every row reads as ticked', () => {
    const all = selectAllMatching('environment:production', 40);
    expect(selectedCount(all)).toBe(40);
    expect(isSelected(all, 'anything')).toBe(true);
    expect(pageState(all, page)).toBe('all');
    expect(selectAllMatching('x', 0)).toEqual(NO_SELECTION);
  });

  it('unticking one row falls back to this page minus that row, never to "all but one"', () => {
    const back = toggleRow(selectAllMatching('q', 40), 'b', page);
    expect(back).toEqual(ids('a', 'c'));
  });

  it('the header on an all-matching selection clears it', () => {
    expect(togglePage(selectAllMatching('q', 40), page)).toEqual(NO_SELECTION);
  });
});

describe('the request', () => {
  it('sends ticked rows as asset_ids, and all-matching as the query with the confirmed count', () => {
    expect(selectionBody(ids('a', 'b'))).toEqual({ asset_ids: ['a', 'b'] });
    expect(selectionBody(selectAllMatching('', 7))).toEqual({ query: '', expected_count: 7 });
  });

  it('holds a scan to the scan cap and the rest to the bulk cap', () => {
    expect(overCapReason(selectAllMatching('q', MAX_BULK_SCAN), 'scan')).toBeNull();
    expect(overCapReason(selectAllMatching('q', MAX_BULK_SCAN + 1), 'scan')).toMatch(/at most 1,000/);
    expect(overCapReason(selectAllMatching('q', MAX_BULK_SCAN + 1), 'archive')).toBeNull();
    expect(overCapReason(selectAllMatching('q', MAX_BULK + 1), 'archive')).toMatch(/at most 5,000/);
  });

  it('says what to do about a refused selection, and nothing about other failures', () => {
    expect(selectionRefusal(409, { error: 'selection_changed', count: 12, expected_count: 10 })).toMatch(/now matches 12 assets, more than the 10 you confirmed/);
    expect(selectionRefusal(413, { error: 'selection_too_large', limit: 5000 })).toMatch(/limit of 5,000/);
    expect(selectionRefusal(409, { error: 'sensor offline' })).toBeNull();
    expect(selectionRefusal(500, undefined)).toBeNull();
  });
});
