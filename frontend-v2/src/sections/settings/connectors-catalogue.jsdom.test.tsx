// @vitest-environment jsdom
// The WIRING test for the "Available connectors" catalogue: the pure rules
// (connectorAction / connectorBadge / connectorCaption) are pinned in
// connectors-catalogue.test.ts, and this pins that the page renders them —
// which card gets an Add button, which badge, which caption. Deleting the
// badge, the operator branch or the isSelectable gate must fail here.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { IntegrationsPage } from './pages-integrations';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const notifications = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn() }));
const inventory = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { notifications, inventory, compliance: { GET: vi.fn() } } }));
vi.mock('@vistasecurity/primitives/features', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/features')>()),
  useFeature: () => false,
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

type Entry = Record<string, unknown>;
const base = { direction: 'push', description: 'x', edition: 'core', entitled: true, configured_by: 'tenant', addable: true, status: 'live' };
const catalogue: Array<{ kind: string; connectors: Entry[] }> = [
  { kind: 'cmdb', connectors: [
    // A CMDB card has an onAdd handler on the page, so this is the case that
    // proves the isSelectable gate: not entitled, so no button.
    { ...base, key: 'servicenow', label: 'ServiceNow CMDB', kind: 'cmdb', direction: 'both', edition: 'enterprise', entitled: false, addable: false, unavailable_reason: 'upgrade' },
  ] },
  { kind: 'network_source_of_truth', connectors: [
    { ...base, key: 'netbox', label: 'NetBox', kind: 'network_source_of_truth', direction: 'pull', edition: 'enterprise' },
  ] },
  { kind: 'siem', connectors: [
    // Entitled, and still not the tenant's to add.
    { ...base, key: 'splunk', label: 'Splunk', kind: 'siem', edition: 'enterprise', configured_by: 'platform_operator', addable: false, unavailable_reason: 'operator' },
    // Not entitled either: the same card, the same missing button.
    { ...base, key: 'elastic', label: 'Elasticsearch', kind: 'siem', edition: 'enterprise', entitled: false, configured_by: 'platform_operator', addable: false, unavailable_reason: 'operator' },
  ] },
  { kind: 'notification', connectors: [
    { ...base, key: 'slack', label: 'Slack', kind: 'notification' },
  ] },
  { kind: 'sbom_source', connectors: [
    { ...base, key: 'sbom_upload', label: 'SBOM upload', kind: 'sbom_source', direction: 'pull' },
    { ...base, key: 'github', label: 'GitHub', kind: 'sbom_source', direction: 'pull', status: 'registered', addable: false, unavailable_reason: 'unavailable' },
  ] },
  { kind: 'generic', connectors: [
    { ...base, key: 'custom', label: 'Custom integration', kind: 'generic', direction: 'both', status: 'registered', addable: false, unavailable_reason: 'unavailable' },
  ] },
];

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  notifications.GET.mockReset().mockImplementation(async () => ({ data: [], response: { ok: true } }));
  inventory.GET.mockReset().mockImplementation(async (path: string) => {
    if (path === '/connectors') return { data: { kinds: catalogue.map((g) => g.kind), groups: catalogue }, response: { ok: true } };
    return { data: { connectors: [], connections: [], profiles: [] }, response: { ok: true } };
  });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render() {
  const meta = { key: 'integrations', label: 'Integrations', icon: 'plug', job: 'Connections' };
  await act(async () => { root.render(<QueryClientProvider client={cache}><IntegrationsPage meta={meta} /></QueryClientProvider>); });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}

/** The catalogue card for this connector label (label → name column → row → card). */
function card(label: string): HTMLElement {
  // The LAST match: other sections of the page (NetBox, Configured connections)
  // reuse a connector's name as a heading, and the catalogue is the final one.
  const title = [...host.querySelectorAll('div')].filter((d) => d.textContent === label && d.children.length === 0).pop();
  expect(title, `no card labelled ${label}`).toBeTruthy();
  return title!.parentElement!.parentElement!.parentElement!;
}
const hasAdd = (el: HTMLElement) => [...el.querySelectorAll('button')].some((b) => b.textContent?.trim() === 'Add');

it('offers Add on a connector this page can add, and on nothing else', async () => {
  await render();
  expect(hasAdd(card('NetBox'))).toBe(true);
  expect(card('ServiceNow CMDB').textContent).toContain('Included in Enterprise');
  for (const label of ['ServiceNow CMDB', 'Splunk', 'Elasticsearch', 'Slack', 'SBOM upload', 'GitHub', 'Custom integration']) {
    expect(hasAdd(card(label)), `${label} must have no Add button`).toBe(false);
  }
});

it('says a SIEM destination is configured by the platform operator, with the edition badge, entitled or not', async () => {
  await render();
  for (const label of ['Splunk', 'Elasticsearch']) {
    const text = card(label).textContent ?? '';
    expect(text).toContain('Configured by your platform operator');
    expect(text).toContain('Enterprise');
    expect(text).not.toContain('Soon');
  }
});

it('renders a registered connector, `custom` included, as Soon and not yet available', async () => {
  await render();
  for (const label of ['GitHub', 'Custom integration']) {
    const text = card(label).textContent ?? '';
    expect(text, label).toContain('Soon');
    expect(text, label).toContain('Not yet available');
  }
  // ...and never points at the notification-channel form.
  expect(card('Custom integration').textContent).not.toContain('Add connection');
});

it('says where a tenant-configured connector without a form here is configured', async () => {
  await render();
  expect(card('Slack').textContent).toContain('Add connection');
  expect(card('SBOM upload').textContent).toContain('SBOM Upload');
  expect(card('Slack').textContent).not.toContain('Soon');
});
