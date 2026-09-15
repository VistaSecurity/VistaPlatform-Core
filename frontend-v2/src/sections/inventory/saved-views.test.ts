// The saved-views menu had two states for three situations.
//
// A failed read left `views` empty, and an empty `views` rendered "No saved
// views yet. Build a filter, then save it here…" — an invitation to recreate
// work the user may already have done, on the strength of a request that
// failed.
import { describe, expect, it } from 'vitest';
import { savedViewsMenuState } from './saved-views';

const ok = { isLoading: false, isError: false };
const loading = { isLoading: true, isError: false };
const failed = { isLoading: false, isError: true };

describe('savedViewsMenuState (gate1 C9)', () => {
  it('says the read failed rather than that there are no views', () => {
    expect(savedViewsMenuState(failed, 0)).toBe('failed');
  });

  it('still says "no views yet" when the read succeeded and there are none (the other polarity)', () => {
    expect(savedViewsMenuState(ok, 0)).toBe('empty');
  });

  it('lists the views when there are some', () => {
    expect(savedViewsMenuState(ok, 3)).toBe('list');
  });

  it('reports loading only while the read is in flight and has not failed', () => {
    expect(savedViewsMenuState(loading, 0)).toBe('loading');
    expect(savedViewsMenuState({ isLoading: true, isError: true }, 0)).toBe('failed');
  });
});
