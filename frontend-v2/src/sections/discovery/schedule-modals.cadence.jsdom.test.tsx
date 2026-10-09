// @vitest-environment jsdom
// The scheduled-scan modal picks timing in plain language and sends the cron
// the API stores. Drives the real modal: what the person picks is what is POSTed.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScheduleFormModal } from './schedule-modals';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const post = vi.hoisted(() => vi.fn());
const put = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { devices: { POST: post, PUT: put } } }));
vi.mock('./queries', () => ({
  useDevices: () => ({ data: [{ id: '00000000-0000-0000-0000-0000000000d1', hostname: 'core-sw-1' }] }),
  useIntegrations: () => ({ data: [] }),
}));
// The browser's zone is the default for a new schedule; pin it.
const realResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
vi.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockImplementation(function (this: Intl.DateTimeFormat) {
  return { ...realResolved.call(this), timeZone: 'America/Chicago' };
});

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  post.mockReset(); put.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  await act(async () => {
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
  });
}
function field<T extends Element>(label: string, selector: string): T {
  const l = [...host.querySelectorAll('label')].find((x) => x.firstElementChild?.textContent === label);
  expect(l, `field "${label}"`).toBeTruthy();
  return l!.querySelector<T>(selector)!;
}
function button(text: string) {
  const b = [...host.querySelectorAll('button')].find((x) => x.textContent === text);
  expect(b, `button "${text}"`).toBeTruthy();
  return b!;
}
const sentCron = (fn: typeof post) => (fn.mock.calls[0] as [string, { body: { cron_expression: string } }])[1].body.cron_expression;
const summary = () => host.querySelector('[data-testid="schedule-summary"]')!.textContent;
const render = (ui: React.ReactNode) => act(async () => root.render(<QueryClientProvider client={cache}>{ui}</QueryClientProvider>));

it('creates a weekday schedule in the person\'s time zone without them typing cron', async () => {
  post.mockResolvedValue({ data: { id: 'x' } });
  await render(<ScheduleFormModal open onClose={() => {}} />);

  expect(host.textContent).not.toContain('Cron expression');
  await setValue(field<HTMLInputElement>('Name', 'input'), 'Weekday sweep');
  await setValue(field<HTMLSelectElement>('Runs', 'select'), 'weekly');
  // Default days are Mon–Fri; drop Friday, then put it back.
  await act(async () => button('Fri').click());
  expect(summary()).toContain('every Monday, Tuesday, Wednesday and Thursday');
  await act(async () => button('Fri').click());
  await setValue(field<HTMLInputElement>('Time', 'input'), '23:30');
  expect(summary()).toMatch(/Runs every weekday at 11:30\sPM \(America\/Chicago\)\./);

  await setValue(field<HTMLSelectElement>('Device', 'select'), '00000000-0000-0000-0000-0000000000d1');
  await act(async () => button('Create schedule').click());
  expect(post).toHaveBeenCalledOnce();
  expect(sentCron(post)).toBe('CRON_TZ=America/Chicago 30 23 * * 1-5');
});

it('blocks saving a weekly schedule with no days', async () => {
  await render(<ScheduleFormModal open onClose={() => {}} />);
  await setValue(field<HTMLInputElement>('Name', 'input'), 'x');
  await setValue(field<HTMLSelectElement>('Device', 'select'), '00000000-0000-0000-0000-0000000000d1');
  await setValue(field<HTMLSelectElement>('Runs', 'select'), 'weekly');
  for (const d of ['Mon', 'Tue', 'Wed', 'Thu', 'Fri']) await act(async () => button(d).click());
  expect(summary()).toBe('Pick at least one day.');
  expect(button('Create schedule').disabled).toBe(true);
});

it('keeps a legacy schedule\'s expression byte-for-byte when only the name changes', async () => {
  put.mockResolvedValue({ data: { id: 's1' } });
  const schedule = { id: 's1', name: 'Nightly', cron_expression: '0 2 * * *', target_type: 'device', target_id: 'd', is_enabled: true };
  await render(<ScheduleFormModal open schedule={schedule as never} onClose={() => {}} />);

  expect(field<HTMLSelectElement>('Runs', 'select').value).toBe('daily');
  expect(summary()).toMatch(/every day at 2:00\sAM \(UTC\)/);
  await setValue(field<HTMLInputElement>('Name', 'input'), 'Nightly renamed');
  await act(async () => button('Save changes').click());
  expect(sentCron(put)).toBe('0 2 * * *');
});

it('opens a cadence the picker cannot express as Custom, and validates it', async () => {
  const schedule = { id: 's2', name: 'Busy hours', cron_expression: '*/15 9-17 * * 1-5', target_type: 'device', target_id: 'd', is_enabled: true };
  await render(<ScheduleFormModal open schedule={schedule as never} onClose={() => {}} />);

  const cron = field<HTMLInputElement>('Cron expression', 'input');
  expect(cron.value).toBe('*/15 9-17 * * 1-5');
  await setValue(cron, '*/15 9-17 * *');
  expect(summary()).toMatch(/Expected 5 fields/);
  expect(button('Save changes').disabled).toBe(true);
});

it('seeds Custom from the picker so a power user starts from valid cron', async () => {
  await render(<ScheduleFormModal open onClose={() => {}} />);
  await setValue(field<HTMLSelectElement>('Runs', 'select'), 'custom');
  expect(field<HTMLInputElement>('Cron expression', 'input').value).toBe('CRON_TZ=America/Chicago 0 2 * * *');
});
