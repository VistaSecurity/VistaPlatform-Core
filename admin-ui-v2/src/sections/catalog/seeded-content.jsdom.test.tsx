// @vitest-environment jsdom
//
// The "Update available" action, MOUNTED and clicked: accepting a shipped
// update overwrites the platform admin's own values, so the click must show
// exactly what will be written and write nothing unless confirmed.
import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AcceptUpdateButton } from './seeded-content';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.restoreAllMocks();
});

function mountAndClick(confirmed: boolean) {
  const onAccept = vi.fn();
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(confirmed);
  act(() => {
    root.render(createElement(AcceptUpdateButton, {
      row: { update_available: true, title: 'Ours', offered_update: { title: 'Shipped' } },
      pending: false, onAccept, label: 'BP-001',
    }));
  });
  const button = container.querySelector('[data-testid="accept-shipped-update"]') as HTMLButtonElement;
  act(() => button.click());
  return { onAccept, confirm };
}

describe('AcceptUpdateButton (mounted)', () => {
  it('asks first, showing what accepting writes, and writes nothing when declined', () => {
    const { onAccept, confirm } = mountAndClick(false);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm.mock.calls[0][0]).toContain('BP-001');
    expect(confirm.mock.calls[0][0]).toContain('title: Ours → Shipped');
    expect(onAccept).not.toHaveBeenCalled();
  });

  it('accepts once confirmed', () => {
    const { onAccept } = mountAndClick(true);
    expect(onAccept).toHaveBeenCalledTimes(1);
  });
});
