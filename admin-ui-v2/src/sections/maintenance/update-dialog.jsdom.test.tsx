// @vitest-environment jsdom
//
// Maintenance ▸ Update confirmation dialog: the state machine (pre-flight
// spinner → check list; a failing check blocks; warnings allow; Update needs
// the version typed exactly) and what it sends — skip_backup only when the
// operator ticked "I have my own backup".
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PreflightCheck, PreflightResult } from './maintenance-queries';

interface PreflightQ { isLoading: boolean; isError: boolean; data?: PreflightResult; error: unknown; refetch: () => void }
interface DialogMocks {
  preflight: PreflightQ;
  mutate: (body: unknown, opts: { onSuccess: (r: { run: { id: string } }) => void }) => void;
  updateError: unknown;
  updatePending: boolean;
  askedFor: string[];
}
const st: DialogMocks = vi.hoisted(() => ({
  preflight: { isLoading: true, isError: false, data: undefined, error: null, refetch: () => {} },
  mutate: () => {},
  updateError: null,
  updatePending: false,
  askedFor: [],
}));

vi.mock('./maintenance-queries', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    usePreflight: (version: string) => { st.askedFor.push(version); return st.preflight; },
    useRunMutations: () => ({ update: { mutate: st.mutate, error: st.updateError, isPending: st.updatePending }, rollback: {} }),
  };
});

import { CHECK_LABEL, UpdateDialog, dialogState } from './update-dialog';
import { PreflightFailedError, RunInProgressError } from './maintenance-queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const NAMES: PreflightCheck['name'][] = ['capabilities', 'version', 'signature', 'value_overrides', 'single_node', 'schema', 'no_run_in_progress', 'recent_backup'];
function result(over: Partial<Record<PreflightCheck['name'], PreflightCheck['status']>> = {}): PreflightResult {
  const checks = NAMES.map((name) => ({ name, status: over[name] ?? 'pass', detail: `${name} detail` }));
  return { version: '4.6.0', current_version: '4.5.0', ok: !checks.some((c) => c.status === 'fail'), checks };
}

describe('dialogState (pure)', () => {
  const base = { version: '4.6.0', typed: '', starting: false };
  it('checking while pre-flight loads', () => {
    expect(dialogState({ ...base, preflight: { isLoading: true, isError: false } })).toMatchObject({ phase: 'checking', canUpdate: false });
  });
  it('pre-flight error when it could not run', () => {
    expect(dialogState({ ...base, preflight: { isLoading: false, isError: true } })).toMatchObject({ phase: 'preflight-error', canUpdate: false });
  });
  it('a failing check blocks, even with the version typed', () => {
    const r = result({ version: 'fail' });
    expect(dialogState({ ...base, typed: '4.6.0', preflight: { isLoading: false, isError: false, data: r } })).toMatchObject({ phase: 'blocked', canUpdate: false });
    // ok:true with a fail row is still blocked: the rows are the truth.
    expect(dialogState({ ...base, typed: '4.6.0', preflight: { isLoading: false, isError: false, data: { ...r, ok: true } } }).canUpdate).toBe(false);
  });
  it('warnings allow, but only once the version is typed exactly', () => {
    const r = result({ value_overrides: 'warn', single_node: 'warn', recent_backup: 'warn' });
    const pf = { isLoading: false, isError: false, data: r };
    expect(dialogState({ ...base, preflight: pf })).toMatchObject({ phase: 'confirm', canUpdate: false });
    expect(dialogState({ ...base, typed: '4.6', preflight: pf }).canUpdate).toBe(false);
    expect(dialogState({ ...base, typed: 'v4.6.0', preflight: pf }).canUpdate).toBe(false);
    expect(dialogState({ ...base, typed: '4.6.0', preflight: pf })).toMatchObject({ phase: 'ready', canUpdate: true });
    expect(dialogState({ ...base, typed: ' 4.6.0 ', preflight: pf }).canUpdate).toBe(true);
  });
  it('a 422 from the start call replaces the pre-flight and blocks', () => {
    const pf = { isLoading: false, isError: false, data: result() };
    expect(dialogState({ ...base, typed: '4.6.0', preflight: pf, rejected: result({ no_run_in_progress: 'fail' }) })).toMatchObject({ phase: 'blocked', canUpdate: false });
  });
  it('starting disables Update', () => {
    expect(dialogState({ ...base, typed: '4.6.0', starting: true, preflight: { isLoading: false, isError: false, data: result() } }).canUpdate).toBe(false);
  });
});

let root: Root | null = null;
let host: HTMLDivElement;
const q = (sel: string) => document.querySelector(sel);
const byTest = (id: string) => q(`[data-testid="${id}"]`);
const primary = () => [...document.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent?.startsWith('Update to')) as HTMLButtonElement;
function type(el: HTMLInputElement, value: string) {
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
const onStarted = vi.fn();
function mount() {
  act(() => root!.render(<UpdateDialog version="4.6.0" currentVersion="4.5.0" onClose={() => {}} onStarted={onStarted} />));
}

beforeEach(() => {
  st.preflight = { isLoading: true, isError: false, data: undefined, error: null, refetch: vi.fn() };
  st.mutate = vi.fn();
  st.updateError = null;
  st.updatePending = false;
  st.askedFor = [];
  onStarted.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
});

describe('UpdateDialog', () => {
  it('opening runs pre-flight for the version and shows the spinner; Update is disabled', () => {
    mount();
    expect(st.askedFor).toContain('4.6.0');
    expect(byTest('preflight-loading')).not.toBeNull();
    expect(byTest('update-dialog')?.getAttribute('data-phase')).toBe('checking');
    expect(primary().disabled).toBe(true);
    expect((byTest('confirm-version') as HTMLInputElement).disabled).toBe(true);
  });

  it('shows every check in plain language with its status', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result({ single_node: 'warn' }) };
    mount();
    const rows = [...document.querySelectorAll('[data-testid="preflight-check"]')];
    expect(rows).toHaveLength(8);
    expect(rows.map((r) => r.getAttribute('data-status'))).toContain('warn');
    expect(rows[0].textContent).toContain(CHECK_LABEL.capabilities);
    expect(rows[0].textContent).toContain('capabilities detail');
  });

  it('a failing check: named, Update disabled, the confirm field disabled', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result({ signature: 'fail' }) };
    mount();
    expect(q('[data-check="signature"]')?.getAttribute('data-status')).toBe('fail');
    expect(byTest('preflight-blocked')).not.toBeNull();
    expect((byTest('confirm-version') as HTMLInputElement).disabled).toBe(true);
    expect(primary().disabled).toBe(true);
    act(() => primary().click());
    expect(st.mutate).not.toHaveBeenCalled();
  });

  it('warnings: Update enables only when the version is typed, and sends skip_backup false', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result({ value_overrides: 'warn', recent_backup: 'warn' }) };
    mount();
    expect(primary().disabled).toBe(true);
    type(byTest('confirm-version') as HTMLInputElement, '4.5.0');
    expect(primary().disabled).toBe(true);
    type(byTest('confirm-version') as HTMLInputElement, '4.6.0');
    expect(primary().disabled).toBe(false);
    act(() => primary().click());
    expect(st.mutate).toHaveBeenCalledWith({ version: '4.6.0', skip_backup: false }, expect.anything());
  });

  it('"I have my own backup" sends skip_backup and strikes the backup step from the plan', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result() };
    mount();
    expect(byTest('plan-backup')?.textContent).toContain('Back up the database first');
    act(() => (byTest('own-backup') as HTMLInputElement).click());
    expect(byTest('plan-backup')?.textContent).toContain('skipped');
    type(byTest('confirm-version') as HTMLInputElement, '4.6.0');
    act(() => primary().click());
    expect(st.mutate).toHaveBeenCalledWith({ version: '4.6.0', skip_backup: true }, expect.anything());
  });

  it('on start it hands the run id to the caller', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result() };
    st.mutate = vi.fn((_body: unknown, opts: { onSuccess: (r: { run: { id: string } }) => void }) => opts.onSuccess({ run: { id: 'run-1' } }));
    mount();
    type(byTest('confirm-version') as HTMLInputElement, '4.6.0');
    act(() => primary().click());
    expect(onStarted).toHaveBeenCalledWith('run-1');
  });

  it('a 409 is reported inline; a 422 re-renders the fresh pre-flight as blocked', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result() };
    st.updateError = new RunInProgressError();
    mount();
    expect(byTest('update-start-error')?.textContent).toContain('in progress');
    act(() => root!.unmount());
    root = createRoot(host);
    st.updateError = new PreflightFailedError(result({ no_run_in_progress: 'fail' }), 'pre-flight failed');
    mount();
    expect(byTest('update-dialog')?.getAttribute('data-phase')).toBe('blocked');
    expect(q('[data-check="no_run_in_progress"]')?.getAttribute('data-status')).toBe('fail');
  });

  it('says what will happen, and uses the product name', () => {
    st.preflight = { ...st.preflight, isLoading: false, data: result() };
    mount();
    const text = byTest('update-plan')?.textContent ?? '';
    for (const s of ['Back up the database', 'signature', 'schema', 'restart every service', 'Recreate']) expect(text).toContain(s);
    expect(document.body.textContent).toContain('Vista Platform 4.6.0');
    expect(document.body.textContent).not.toMatch(/VistaPlatform/);
  });
});
