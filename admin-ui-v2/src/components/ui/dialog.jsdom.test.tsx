// @vitest-environment jsdom
//
// Dialog / Modal primitive, MOUNTED. Every admin overlay (Modal, tenant
// drawer, plan builder, role drawer) sits on it, so the accessible contract is
// pinned here: role + accessible name, Esc, a focus trap with focus return,
// a ref-counted scroll lock, and the dirty-form guard that stops a stray scrim
// click or Esc from discarding typed input.
//
// Mutations run (each red, then restored green): removing the dirty check in
// requestClose; removing the Tab wrap in onKeyDown; unlocking scroll without
// the ref count.
import { act, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Dialog } from './dialog';
import { Modal } from './modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
  document.body.style.overflow = '';
});

function mount(node: React.ReactNode) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(node));
}
const esc = () => act(() => { document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); });
const tab = (el: Element, shiftKey = false) => act(() => { el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', shiftKey, bubbles: true, cancelable: true })); });
const scrim = () => document.querySelector('[data-dialog-scrim]') as HTMLElement;
const click = (el: Element) => act(() => { (el as HTMLElement).click(); });
const byText = (t: string) => Array.from(document.querySelectorAll('button')).find((b) => b.textContent === t) as HTMLButtonElement;

function Sample({ dirty = false, onClose }: { dirty?: boolean; onClose: () => void }) {
  return (
    <Dialog onClose={onClose} dirty={dirty} labelId="t">
      <h2 id="t">Sample title</h2>
      <input aria-label="first" />
      <button>middle</button>
      <button>last</button>
    </Dialog>
  );
}

describe('Dialog semantics', () => {
  it('is a modal dialog named by its title', () => {
    mount(<Sample onClose={() => {}} />);
    const d = document.querySelector('[role="dialog"]')!;
    expect(d.getAttribute('aria-modal')).toBe('true');
    const id = d.getAttribute('aria-labelledby')!;
    expect(document.getElementById(id)?.textContent).toBe('Sample title');
  });

  it('Modal wires its title, description and an accessibly named close button', () => {
    mount(<Modal open onClose={() => {}} title="Rename" description="Pick a name" />);
    const d = document.querySelector('[role="dialog"]')!;
    expect(document.getElementById(d.getAttribute('aria-labelledby')!)?.textContent).toBe('Rename');
    expect(document.getElementById(d.getAttribute('aria-describedby')!)?.textContent).toBe('Pick a name');
    expect(d.querySelector('button[aria-label="Close"]')).not.toBeNull();
  });

  it('Modal shows the caller\'s loading label, not a hardcoded one', () => {
    mount(<Modal open onClose={() => {}} title="x" primaryLabel="Delete" primaryLoading primaryLoadingLabel="Deleting…" />);
    expect(byText('Deleting…')).toBeDefined();
  });

  it('renders nothing when closed', () => {
    mount(<Modal open={false} onClose={() => {}} title="x" />);
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });
});

describe('Esc and scrim', () => {
  it('Esc closes a clean dialog', () => {
    const onClose = vi.fn();
    mount(<Sample onClose={onClose} />);
    esc();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('a scrim click closes a clean dialog; a click inside does not', () => {
    const onClose = vi.fn();
    mount(<Sample onClose={onClose} />);
    click(byText('middle'));
    expect(onClose).not.toHaveBeenCalled();
    click(scrim());
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('Esc does NOT close a dirty dialog until the discard is confirmed', () => {
    const onClose = vi.fn();
    mount(<Sample dirty onClose={onClose} />);
    esc();
    expect(onClose).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain('Discard changes?');
    click(byText('Discard'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('a scrim click on a dirty dialog keeps it open and asks; Keep editing dismisses the ask', () => {
    const onClose = vi.fn();
    mount(<Sample dirty onClose={onClose} />);
    click(scrim());
    expect(onClose).not.toHaveBeenCalled();
    expect(document.querySelector('[role="alert"]')?.textContent).toContain('Discard changes?');
    click(byText('Keep editing'));
    expect(document.querySelector('[role="alert"]')).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('Esc while the discard ask is showing returns to editing', () => {
    const onClose = vi.fn();
    mount(<Sample dirty onClose={onClose} />);
    esc();
    esc();
    expect(onClose).not.toHaveBeenCalled();
    expect(document.querySelector('[role="alert"]')).toBeNull();
  });

  it('does not re-subscribe when the caller passes a fresh inline onClose, and calls the latest one', () => {
    const add = vi.spyOn(document, 'addEventListener');
    const first = vi.fn();
    const second = vi.fn();
    mount(<Dialog onClose={first} labelId="t"><h2 id="t">T</h2><button>b</button></Dialog>);
    const before = add.mock.calls.filter((c) => c[0] === 'keydown').length;
    act(() => root!.render(<Dialog onClose={second} labelId="t"><h2 id="t">T</h2><button>b</button></Dialog>));
    expect(add.mock.calls.filter((c) => c[0] === 'keydown').length).toBe(before);
    esc();
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
    add.mockRestore();
  });

  it('Esc closes only the topmost of two stacked dialogs', () => {
    const outer = vi.fn();
    const inner = vi.fn();
    mount(<><Sample onClose={outer} /><Sample onClose={inner} /></>);
    esc();
    expect(inner).toHaveBeenCalledTimes(1);
    expect(outer).not.toHaveBeenCalled();
  });
});

describe('focus', () => {
  it('moves into the dialog on open and returns to the opener on close', () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return (<><button id="opener" onClick={() => setOpen(true)}>open</button>{open && <Sample onClose={() => setOpen(false)} />}</>);
    }
    mount(<Host />);
    const opener = document.getElementById('opener') as HTMLButtonElement;
    opener.focus();
    click(opener);
    const dialog = document.querySelector('[role="dialog"]')!;
    expect(dialog.contains(document.activeElement)).toBe(true);
    esc();
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it('keeps focus already placed inside the dialog (autoFocus)', () => {
    mount(<Dialog onClose={() => {}} labelId="t"><h2 id="t">T</h2><button>a</button><input aria-label="auto" autoFocus /></Dialog>);
    expect((document.activeElement as HTMLElement).getAttribute('aria-label')).toBe('auto');
  });

  it('Tab from the last focusable wraps to the first; Shift+Tab from the first wraps to the last', () => {
    mount(<Sample onClose={() => {}} />);
    const first = document.querySelector('input') as HTMLElement;
    const last = byText('last');
    last.focus();
    tab(last);
    expect(document.activeElement).toBe(first);
    tab(first, true);
    expect(document.activeElement).toBe(last);
  });
});

describe('body scroll lock', () => {
  it('is ref-counted: stacked dialogs closing out of order restore the original overflow only at the end', () => {
    document.body.style.overflow = 'auto';
    function Host({ a, b }: { a: boolean; b: boolean }) {
      return (<>{a && <Sample onClose={() => {}} />}{b && <Sample onClose={() => {}} />}</>);
    }
    mount(<Host a b />);
    expect(document.body.style.overflow).toBe('hidden');
    act(() => root!.render(<Host a={false} b />)); // the first-opened closes first
    expect(document.body.style.overflow).toBe('hidden');
    act(() => root!.render(<Host a={false} b={false} />));
    expect(document.body.style.overflow).toBe('auto');
  });
});
