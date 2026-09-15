// Settings → AI assistant: reachability, both polarities, and the honesty
// rules the page exists to state.
//
// The page is CORE and carries NO feature-flag lock, which is the unusual part
// and the easiest thing for a future edit to "tidy" into a lock — so both
// polarities of that are pinned here: the entry is present with every flag OFF
// (a Core deployment) and still present with every flag ON.
import { describe, it, expect } from 'vitest';
import { defaultFeatures, type FeaturesMap } from '@vistasecurity/primitives/features';
import { TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { SETTINGS_NAV, settingsPageMeta, visibleSettingsNav } from './nav';
import { HONEST_LINE, SEAM_LABELS, aiPageState, seamLabel, seamState } from './pages-ai';

const allOn: FeaturesMap = Object.fromEntries(
  Object.keys(defaultFeatures).map((k) => [k, true]),
) as unknown as FeaturesMap;

const keysOf = (sections: ReturnType<typeof visibleSettingsNav>) =>
  sections.flatMap((s) => s.items.map((i) => i.key));

describe('reachability', () => {
  // The nav home is the hard stop of the feature framework: a page nothing
  // links to is an orphan, however good it is.
  it('is reachable from the Settings rail on a CORE deployment', () => {
    expect(keysOf(visibleSettingsNav(defaultFeatures))).toContain('ai-assistant');
  });

  it('is still reachable with every entitlement on', () => {
    expect(keysOf(visibleSettingsNav(allOn))).toContain('ai-assistant');
  });

  // The page EXPLAINS the edition; it is not gated by it. A `feature` here
  // would hide from a Core tenant the two switches they genuinely own.
  it('carries no feature gate and no upgrade card', () => {
    const meta = settingsPageMeta('ai-assistant');
    expect(meta.feature).toBeUndefined();
    expect(meta.lock).toBeUndefined();
  });

  // settings.update, not settings.read: PUT /tenant/ai requires it, so a
  // settings.read-only role reaching the page would get one whose only controls
  // fail. (GET is looser — authentication only — so other surfaces can explain
  // an absent capability without an administrator; that is the endpoint's
  // gating, not the rail's.)
  it('is gated on the permission its endpoint actually requires', () => {
    expect(settingsPageMeta('ai-assistant').permission).toBe(TENANT_PERMISSIONS.settings.update);
  });

  it('is marked built, so the rail renders it rather than the spec-pending panel', () => {
    expect(settingsPageMeta('ai-assistant').built).toBe(true);
  });

  it('sits in exactly one section', () => {
    const hits = SETTINGS_NAV.flatMap((s) => s.items).filter((i) => i.key === 'ai-assistant');
    expect(hits).toHaveLength(1);
  });
});

describe('page states', () => {
  it('renders the table only when data has actually arrived', () => {
    expect(aiPageState({ isError: false, isLoading: false, hasData: true })).toBe('ready');
  });

  it('shows loading while the query is in flight', () => {
    expect(aiPageState({ isError: false, isLoading: true, hasData: false })).toBe('loading');
  });

  // react-query reports isLoading alongside isError while a failed query is
  // retrying. Loading-first would spin forever on a page whose whole job is to
  // say what is true.
  it('shows the error card even while a failed query is still retrying', () => {
    expect(aiPageState({ isError: true, isLoading: true, hasData: false })).toBe('error');
  });

  // A 200 with an unreadable body must not render an empty capabilities table:
  // "you have nothing turned on" and "we could not read the answer" are
  // different facts, and only one of them is safe to assert.
  it('does not render an empty page for a successful-but-empty response', () => {
    expect(aiPageState({ isError: false, isLoading: false, hasData: false })).toBe('loading');
  });
});

describe('the honest line', () => {
  // ADR-0008's promise, stated on the page in the tenant's own words. It is
  // exported so this cannot quietly become marketing.
  it('says the product does not depend on AI', () => {
    expect(HONEST_LINE).toMatch(/Nothing here depends on AI/);
    expect(HONEST_LINE).toMatch(/rule-based default/);
  });
});

describe('seamState', () => {
  const generative = { key: 'narrator', live: false, built: true, edition_required: 'enterprise', family: 'generative', rule_default: 'x' };
  const classical = { key: 'classifier', live: true, built: true, edition_required: 'core', family: 'classical', rule_default: 'x' };
  const unbuilt = { key: 'remediator', live: false, built: false, edition_required: 'enterprise', family: 'generative', rule_default: 'x' };

  it('reports a live seam as on', () => {
    expect(seamState(classical, { edition_linked: false, provider_configured: false })).toBe('live');
  });

  // The distinction the whole status column exists for. "Your edition does not
  // include this" is a purchase; "nobody configured a provider" is ten minutes
  // of an administrator's time. One grey dash for both sends every reader to
  // the wrong place.
  it('separates "not in this edition" from "no provider configured"', () => {
    expect(seamState(generative, { edition_linked: false, provider_configured: false })).toBe('edition');
    expect(seamState(generative, { edition_linked: true, provider_configured: false })).toBe('unconfigured');
  });

  // A seam nothing implements yet must not read as "you could turn this on",
  // even on an Enterprise build with a working provider.
  it('reports a seam nothing implements as not yet built', () => {
    expect(seamState(unbuilt, { edition_linked: true, provider_configured: true })).toBe('not-built');
  });

  // The one that was wrong: whether something has been WRITTEN is not a fact
  // about the reader's licence. Reading `edition_linked` first labelled an
  // unbuilt seam "Enterprise" on a Core deployment — a capability claim nothing
  // backs, and the opposite answer the same build gives on Enterprise.
  it('says "not yet built", not "Enterprise", for an unbuilt seam on a Core build', () => {
    expect(seamState(unbuilt, { edition_linked: false, provider_configured: false })).toBe('not-built');
  });

  // Both polarities of that branch: a seam that IS built still reports the
  // edition, or the fix would have silenced the whole Enterprise column.
  it('still reports the edition for a built seam a Core build cannot run', () => {
    expect(seamState({ ...unbuilt, built: true }, { edition_linked: false, provider_configured: false })).toBe('edition');
  });
});

describe('seam labels', () => {
  // The backend can return any of the eight seam keys; a missing label renders
  // the raw key, which reads like a bug to a reader and like nothing to a
  // stakeholder.
  const API_SEAM_KEYS = [
    'matcher', 'classifier', 'drift_detector', 'enricher',
    'narrator', 'query', 'author', 'remediator',
  ];

  it('has a human label for every seam the API can return', () => {
    for (const key of API_SEAM_KEYS) {
      expect(SEAM_LABELS[key], `seam ${key} has no label`).toBeTruthy();
      expect(seamLabel(key)).not.toBe(key);
    }
  });

  it('has no label for a key the API cannot return', () => {
    expect(Object.keys(SEAM_LABELS).sort()).toEqual([...API_SEAM_KEYS].sort());
  });

  it('falls back to the key rather than rendering nothing', () => {
    expect(seamLabel('a_ninth_seam')).toBe('a_ninth_seam');
  });
});

describe('the #1439 authoring notice', () => {
  // The AI assistant page renders the SAME copy the Custom Policies page uses,
  // read from nav.ts. If that entry is deleted while the backend constant is
  // still true, the AI page would silently show nothing where it promised an
  // explanation — so the two are pinned together here.
  it('has copy to render, sourced from the custom-policies entry', () => {
    const notice = settingsPageMeta('custom-policies').authoringDisabled;
    expect(notice, 'the AI assistant page renders this copy; deleting it must also flip the Go constant').toBeTruthy();
    expect(notice!.message).toMatch(/1439/);
  });
});
