// @vitest-environment jsdom
//
// The create modal and the drawer's edit form, MOUNTED.
//
// Both exist to close the same gap from opposite ends: a ticket could only be
// born from a finding or an alert, and once born only its status could change,
// while PUT /tickets/{id} had always accepted a dozen other fields. So what
// matters here is the REQUEST each form sends — that the fields reach the API
// at all, and in the shape that makes a nullable column clearable.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SLA_DAYS, LEGACY_TICKET_CATEGORIES, TICKET_CATEGORIES } from '@vistasecurity/primitives/tickets';

const posted: { path: string; body?: Record<string, unknown> }[] = [];
const put: { path: string; body?: Record<string, unknown> }[] = [];
const deleted: { path: string; id?: string }[] = [];

vi.mock('../../lib/clients', () => ({
  clients: {
    compliance: {
      POST: vi.fn(async (path: string, opts?: { body?: Record<string, unknown> }) => {
        posted.push({ path, body: opts?.body });
        return { data: { ticket: { id: 'new-1', title: 'x' } }, error: undefined, response: { ok: true } };
      }),
      PUT: vi.fn(async (path: string, opts?: { body?: Record<string, unknown> }) => {
        put.push({ path, body: opts?.body });
        return { data: { ticket: {} }, error: undefined, response: { ok: true } };
      }),
      DELETE: vi.fn(async (path: string, opts?: { params?: { path?: { id?: string } } }) => {
        deleted.push({ path, id: opts?.params?.path?.id });
        return { data: {}, error: undefined, response: { ok: true } };
      }),
      GET: vi.fn(async () => ({ data: { comments: [] }, error: undefined })),
    },
    auth: { GET: vi.fn(async () => ({ data: { users: [] }, error: undefined })) },
  },
}));
vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ tenant: { id: 't-1' } }) }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import { CreateTicketModal } from './create-ticket-modal';
import { TicketEditForm } from './ticket-edit';
import type { Ticket } from './meta';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

async function settle(): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  }
}

async function mount(node: React.ReactElement): Promise<void> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>);
  });
  await settle();
}

/** The modal renders into a portal-less overlay appended to body, so search there. */
const scope = () => document.body;

function field(labelText: string): HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  const label = Array.from(scope().querySelectorAll('label'))
    .find((l) => l.firstElementChild?.textContent?.trim() === labelText);
  if (!label) throw new Error(`no field labelled "${labelText}"`);
  const input = label.querySelector('input, select, textarea');
  if (!input) throw new Error(`field "${labelText}" has no control`);
  return input as HTMLInputElement;
}

function setValue(el: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype
    : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

/**
 * Click a button INSIDE the open confirmation dialog.
 *
 * The form's trigger and the dialog's confirm both read "Delete ticket", so a
 * document-wide search finds the trigger again and re-opens what is already
 * open — which is how the first draft of these tests "passed" while never
 * confirming anything.
 */
function clickInDialog(text: string) {
  const dialog = scope().querySelector('[role="dialog"]');
  if (!dialog) throw new Error('no dialog is open');
  const btn = Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent?.includes(text));
  if (!btn) throw new Error(`no button containing "${text}" in the dialog`);
  btn.click();
}

function clickButton(text: string) {
  const btn = Array.from(scope().querySelectorAll('button')).find((b) => b.textContent?.includes(text));
  if (!btn) throw new Error(`no button containing "${text}"`);
  btn.click();
}

beforeEach(() => { posted.length = 0; put.length = 0; deleted.length = 0; });
afterEach(async () => {
  await act(async () => { root.unmount(); });
  container.remove();
  vi.clearAllMocks();
});

describe('the create-ticket modal', () => {
  it('offers every writable category and no retired one', async () => {
    // A retired category in the picker files a ticket the server rejects with
    // a 400, so the button would simply not work.
    await mount(<CreateTicketModal open onClose={() => {}} />);
    const options = Array.from((field('Category') as HTMLSelectElement).options).map((o) => o.value);
    expect(options).toEqual(TICKET_CATEGORIES.map((c) => c.key));
    for (const legacy of LEGACY_TICKET_CATEGORIES) expect(options).not.toContain(legacy);
  });

  it('pre-fills a due date, so no ticket is filed invisible to the SLA views', async () => {
    await mount(<CreateTicketModal open onClose={() => {}} />);
    const due = (field('Due') as HTMLInputElement).value;
    expect(due).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    const days = Math.round((new Date(`${due}T12:00:00Z`).getTime() - Date.now()) / 86400000);
    expect(days).toBe(DEFAULT_SLA_DAYS.medium);
  });

  it('moves the due date when the priority changes', async () => {
    await mount(<CreateTicketModal open onClose={() => {}} />);
    const before = (field('Due') as HTMLInputElement).value;
    await act(async () => { setValue(field('Priority'), 'critical'); });
    const after = (field('Due') as HTMLInputElement).value;
    expect(after).not.toBe(before);
    expect(new Date(after).getTime()).toBeLessThan(new Date(before).getTime());
  });

  it('stops re-deriving the due date once the user sets one', async () => {
    // Re-deriving after an explicit choice silently discards a date somebody
    // picked on purpose, which is the more annoying of the two failure modes.
    await mount(<CreateTicketModal open onClose={() => {}} />);
    await act(async () => { setValue(field('Due'), '2027-01-15'); });
    await act(async () => { setValue(field('Priority'), 'critical'); });
    expect((field('Due') as HTMLInputElement).value).toBe('2027-01-15');
  });

  it('posts the whole form, with the due date as RFC 3339', async () => {
    await mount(<CreateTicketModal open onClose={() => {}} />);
    await act(async () => {
      setValue(field('Title'), 'Rotate the edge wildcard');
      setValue(field('Category'), 'certificate');
      setValue(field('Priority'), 'high');
      setValue(field('Tags'), 'q3, edge');
    });
    await act(async () => { clickButton('Create ticket'); });
    await settle();

    expect(posted).toHaveLength(1);
    expect(posted[0].path).toBe('/tickets');
    expect(posted[0].body).toMatchObject({
      title: 'Rotate the edge wildcard',
      category: 'certificate',
      priority: 'high',
      tags: ['q3', 'edge'],
      source: 'manual',
    });
    expect(posted[0].body!.due_date).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('refuses to submit without a title', async () => {
    await mount(<CreateTicketModal open onClose={() => {}} />);
    await act(async () => { clickButton('Create ticket'); });
    await settle();
    expect(posted).toHaveLength(0);
  });

  it('refuses a non-http external link rather than storing it', async () => {
    // safeHttpUrl blocks javascript:/data: at render time; blocking it at
    // ENTRY means the row never carries one in the first place.
    await mount(<CreateTicketModal open onClose={() => {}} />);
    await act(async () => {
      setValue(field('Title'), 'x');
      setValue(field('URL'), 'javascript:alert(1)');
    });
    await act(async () => { clickButton('Create ticket'); });
    await settle();
    expect(posted).toHaveLength(0);
    expect(scope().textContent).toContain('http(s)');
  });
});

const TICKET = {
  id: 'tk-1',
  tenant_id: 't-1',
  category: 'crypto',
  title: 'Weak cipher on edge',
  status: 'open',
  priority: 'medium',
  source: 'manual',
  created_by: 'u-1',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  external_sync_status: 'none',
  due_date: '2026-02-01T12:00:00Z',
  severity: 'high',
  tags: ['edge'],
} as unknown as Ticket;


describe('the drawer edit form', () => {
  it('sends every editable field, not just the status', async () => {
    // The gap this closes: the drawer previously exposed a status-advance
    // button and nothing else, while PUT accepted all of this.
    await mount(<TicketEditForm ticket={TICKET} onDone={() => {}} onDeleted={() => {}} />);
    await act(async () => {
      setValue(field('Priority'), 'critical');
      setValue(field('Category'), 'pqc');
      setValue(field('Tags'), 'edge, q4');
    });
    await act(async () => { clickButton('Save changes'); });
    await settle();

    expect(put).toHaveLength(1);
    expect(put[0].body).toMatchObject({
      priority: 'critical',
      category: 'pqc',
      tags: ['edge', 'q4'],
      status: 'open',
    });
  });

  it('sends an empty string, not undefined, so a nullable field can be cleared', async () => {
    // undefined means "leave it alone" to the server. If the form sent that,
    // a due date or an assignee could be set once and never removed.
    await mount(<TicketEditForm ticket={TICKET} onDone={() => {}} onDeleted={() => {}} />);
    await act(async () => { setValue(field('Due'), ''); });
    await act(async () => { clickButton('Save changes'); });
    await settle();
    expect(put[0].body!.due_date).toBe('');
    expect(put[0].body).toHaveProperty('assigned_to', '');
  });

  it('shows resolution notes only once the ticket is being resolved', async () => {
    await mount(<TicketEditForm ticket={TICKET} onDone={() => {}} onDeleted={() => {}} />);
    expect(() => field('Resolution notes')).toThrow();
    await act(async () => { setValue(field('Status'), 'resolved'); });
    expect(field('Resolution notes')).toBeTruthy();
  });

  it('keeps a retired category selectable only as the current value', async () => {
    // Offering it in the list would let someone re-file under it and get a
    // 400; dropping it entirely would silently rewrite the ticket's category
    // to whatever happened to be first.
    const legacy = { ...TICKET, category: 'remediation' };
    await mount(<TicketEditForm ticket={legacy} onDone={() => {}} onDeleted={() => {}} />);
    const select = field('Category') as HTMLSelectElement;
    expect(select.value).toBe('remediation');
    expect(Array.from(select.options)[0].textContent).toContain('retired');
  });

  it('refuses a non-http external link', async () => {
    await mount(<TicketEditForm ticket={TICKET} onDone={() => {}} onDeleted={() => {}} />);
    await act(async () => { setValue(field('External URL'), 'data:text/html,<script>'); });
    await act(async () => { clickButton('Save changes'); });
    await settle();
    expect(put).toHaveLength(0);
  });
});

// Delete is permanent, takes the comment thread with it, and is one click from
// a row anyone can open — so the interesting assertions are about what does
// NOT happen.
describe('deleting a ticket', () => {
  const mountEdit = (t = TICKET, onDeleted = () => {}, commentCount = 0) =>
    mount(<TicketEditForm ticket={t} onDone={() => {}} onDeleted={onDeleted} commentCount={commentCount} />);

  it('never deletes on the first click', async () => {
    await mountEdit();
    await act(async () => { clickButton('Delete ticket'); });
    await settle();
    // The first click opens the confirmation. A DELETE here would mean a
    // mis-click destroys a record with no way back.
    expect(deleted).toHaveLength(0);
  });

  it('deletes once confirmed, by id', async () => {
    await mountEdit();
    await act(async () => { clickButton('Delete ticket'); });     // opens the dialog
    await act(async () => { clickInDialog('Delete ticket'); });   // confirms in it
    await settle();
    expect(deleted).toEqual([{ path: '/tickets/{id}', id: TICKET.id }]);
  });

  it('closes the drawer afterwards, because there is nothing left to show', async () => {
    let closed = false;
    await mountEdit(TICKET, () => { closed = true; });
    await act(async () => { clickButton('Delete ticket'); });
    await act(async () => { clickInDialog('Delete ticket'); });
    await settle();
    expect(closed).toBe(true);
  });

  it('cancelling leaves the ticket alone', async () => {
    await mountEdit();
    await act(async () => { clickButton('Delete ticket'); });
    await act(async () => { clickInDialog('Cancel'); });
    await settle();
    expect(deleted).toHaveLength(0);
  });

  it('says the comment thread goes too, with the count', async () => {
    // "Delete this ticket?" understates it: the comments are user-written
    // content and they cascade. The number is what makes that concrete.
    await mountEdit(TICKET, () => {}, 3);
    await act(async () => { clickButton('Delete ticket'); });
    expect(scope().textContent).toContain('3 comments');
    expect(scope().textContent).toContain('cannot be undone');
  });

  it('does not claim comments that do not exist', async () => {
    await mountEdit(TICKET, () => {}, 0);
    await act(async () => { clickButton('Delete ticket'); });
    expect(scope().textContent).not.toContain('comment');
  });

  it('tells the user the deletion is audited under their name', async () => {
    await mountEdit();
    await act(async () => { clickButton('Delete ticket'); });
    expect(scope().textContent).toContain('audit trail');
  });

  it('explains what happens to a linked alert, and only when there is one', async () => {
    await mountEdit({ ...TICKET, alert_id: 'al-1' } as Ticket);
    await act(async () => { clickButton('Delete ticket'); });
    expect(scope().textContent).toContain('alert it came from stays open');
  });

  it('says nothing about alerts for a ticket that has none', async () => {
    await mountEdit();
    await act(async () => { clickButton('Delete ticket'); });
    expect(scope().textContent).not.toContain('alert it came from');
  });
});
