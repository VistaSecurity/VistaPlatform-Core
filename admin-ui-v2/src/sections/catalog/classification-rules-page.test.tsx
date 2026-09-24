import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ClassificationRulesPage } from './classification-rules-page';
import type { ClassificationRule, ClassificationRulePage } from './catalog-queries';

// Every screen state of Catalog ▸ Classification rules, rendered.
//
// This page is the ONLY place a platform admin can see or change the evidence
// behind class proposals (ADR-0004 D6), so the states that are easy to leave
// out — loading, error, empty, the add form, the delete confirmation — are the
// ones pinned here, along with the two things the page has to SAY rather than
// merely support: that a null class is the normal shape of a vendor-only rule,
// and that a wrong class is worse than none.

const queryState = vi.hoisted(() => ({
  rules: {
    data: undefined as ClassificationRulePage | undefined,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  },
  create: { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined as Error | undefined },
  update: { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined as Error | undefined },
  remove: { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined as Error | undefined },
  accept: { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined as Error | undefined },
}));

vi.mock('./catalog-queries', async (importOriginal) => {
  // The label and hint maps are part of what these tests assert, so the real
  // module is kept and only the hooks are replaced.
  const actual = await importOriginal<typeof import('./catalog-queries')>();
  return {
    ...actual,
    useClassificationRules: () => queryState.rules,
    useCreateClassificationRule: () => queryState.create,
    useUpdateClassificationRule: () => queryState.update,
    useDeleteClassificationRule: () => queryState.remove,
    useAcceptClassificationRuleUpdate: () => queryState.accept,
  };
});

const ALL_KINDS = [
  'oui', 'sysobjectid', 'enip', 'cloud_type', 'banner', 'port_profile', 'model', 'platform',
] as ClassificationRulePage['kinds'];

const rule = (over: Partial<ClassificationRule> = {}): ClassificationRule => ({
  id: '11111111-1111-4111-8111-111111111111',
  rule_kind: 'oui',
  pattern: '00000C',
  class_key: 'network_device',
  vendor: 'Cisco Systems',
  model: null,
  confidence: 0.7,
  source_url: 'https://standards-oui.ieee.org/',
  created_at: '2026-09-11T00:00:00Z',
  updated_at: '2026-09-11T00:00:00Z',
  content_origin: 'vista',
  admin_modified: false,
  update_available: false,
  ...over,
});

const page = (rows: ClassificationRule[], over: Partial<ClassificationRulePage> = {}): ClassificationRulePage => ({
  rows,
  total: rows.length,
  page: 1,
  pageSize: 50,
  kinds: ALL_KINDS,
  ...over,
});

beforeEach(() => {
  queryState.rules = { data: undefined, isLoading: false, isError: false, refetch: vi.fn() };
  queryState.create = { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined };
  queryState.update = { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined };
  queryState.remove = { mutate: vi.fn(), reset: vi.fn(), isPending: false, error: undefined };
});

describe('Catalog ▸ Classification rules', () => {
  it('renders the loading state', () => {
    queryState.rules.isLoading = true;
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('Loading the classification rules…');
  });

  it('renders the error state with a retry', () => {
    queryState.rules.isError = true;
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('t load the classification rules.');
    expect(html).toContain('Retry');
  });

  // An empty table here almost certainly means the seed did not run, not that
  // the catalogue is legitimately empty — 215 rules ship with it. Saying so is
  // the difference between a five-minute check and an afternoon.
  it('tells an operator what an empty table probably means', () => {
    queryState.rules.data = page([]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('the seed did not run');
  });

  it('renders a rule with its kind, pattern, class, vendor, confidence and citation', () => {
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('MAC OUI');
    expect(html).toContain('00000C');
    expect(html).toContain('network_device');
    expect(html).toContain('Cisco Systems');
    expect(html).toContain('0.70');
    expect(html).toContain('https://standards-oui.ieee.org/');
    expect(html).toContain('1 rules');
  });

  // A null class is the NORMAL shape of a vendor-only rule — most OUI rules are
  // one — so the cell says "vendor only" rather than a dash that reads as
  // missing data an admin ought to go and fill in.
  it('renders a vendor-only rule as vendor only, not as a gap', () => {
    queryState.rules.data = page([rule({ class_key: null, vendor: 'Dell Inc.', confidence: 0.85 })]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('vendor only');
    expect(html).toContain('Dell Inc.');
    expect(html).not.toContain('network_device');
  });

  it('marks a rule that cites nothing', () => {
    queryState.rules.data = page([rule({ source_url: null })]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('uncited');
  });

  // The kind vocabulary comes from the SERVER. A hard-coded list in the
  // frontend is how a ninth rule kind ships invisible: present in the engine,
  // absent from every filter and form.
  it('builds the kind filter from the vocabulary the server served', () => {
    queryState.rules.data = page([rule()], { kinds: ['oui', 'platform'] as ClassificationRulePage['kinds'] });
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('MAC OUI');
    expect(html).toContain('Collector platform');
    // A kind the server did not offer must not appear in the filter.
    expect(html).not.toContain('EtherNet/IP vendor');
  });

  it('offers every kind the server knows about', () => {
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    for (const label of [
      'MAC OUI', 'SNMP sysObjectID', 'EtherNet/IP vendor', 'Cloud resource type',
      'Service banner', 'Port profile', 'Model prefix', 'Collector platform',
    ]) {
      expect(html).toContain(label);
    }
  });

  it('has an add control and a per-row edit and delete', () => {
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('Add rule');
    expect(html).toContain('Edit 00000C');
    expect(html).toContain('Delete 00000C');
  });

  // The page states the governing rule where the decision is made. An admin
  // filling in the class field is exactly the person who needs to read it.
  it('states the wrong-class-is-worse-than-none rule on the page', () => {
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('proposal');
    expect(html).toContain('no</strong> class');
  });

  it('says a rule never classifies anything on its own', () => {
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('goes through Approvals');
  });

  // The page must not imply that curating a rule changes anything yet. The
  // classifier runs on the compiled-in copy of the shipped rules and nothing
  // reads this table at run time until intake lands, so a console that stayed
  // quiet about it would have an admin curating for a week and wondering why
  // nothing moved.
  it('says plainly WHEN a rule added here takes effect', () => {
    // The notice said "not live yet" for a release, which was true then. It is
    // live now (workstream 2.10b), and stating that without the refresh window
    // would leave an admin who re-runs a discovery thirty seconds later
    // wondering why nothing moved — the same complaint, one step along.
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('rules-are-live-notice');
    expect(html).toContain('five minutes');
    expect(html).toContain('CLASSIFICATION_RULES_REFRESH');
    expect(html).not.toContain('not live yet');
  });

  it('paginates when there is more than one page', () => {
    queryState.rules.data = page([rule()], { total: 120 });
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('Page 1 of 3');
    expect(html).toContain('Next');
  });

  it('does not paginate an empty table', () => {
    queryState.rules.data = page([]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).not.toContain('Previous');
  });

  // Decision 4 (RC-12): shipped rules the admin edits stay edited, and a later
  // shipped change arrives as an offer. The page has to show which rules are
  // shipped, which were changed here, and the one action an offer needs.
  it('marks shipped and custom rules, and a shipped rule edited here', () => {
    queryState.rules.data = page([
      rule(),
      rule({ id: '22222222-2222-4222-8222-222222222222', pattern: '00188B', content_origin: 'custom' }),
      rule({ id: '33333333-3333-4333-8333-333333333333', pattern: '000048', admin_modified: true }),
    ]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('>Vista<');
    expect(html).toContain('>Custom<');
    expect(html).toContain('>Modified<');
  });

  it('offers the shipped update on a rule that has one, and nowhere else', () => {
    queryState.rules.data = page([
      rule({ admin_modified: true, confidence: 0.55, update_available: true, offered_update: { confidence: 0.75 } }),
      rule({ id: '22222222-2222-4222-8222-222222222222', pattern: '00188B' }),
    ]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('Accept the shipped update for 00000C');
    expect(html).not.toContain('Accept the shipped update for 00188B');
    // The tooltip says exactly what accepting writes.
    expect(html).toContain('confidence: 0.55 → 0.75');
  });

  it('says upgrades keep an edited shipped rule rather than that they undo it', () => {
    queryState.rules.data = page([rule()]);
    const html = renderToStaticMarkup(createElement(ClassificationRulesPage));
    expect(html).toContain('Your edits to them survive upgrades');
  });
});
