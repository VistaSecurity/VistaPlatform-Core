// B-33: the routing-rule "Alert source" dropdown used to be a hand-maintained
// list of nine values matched by EXACT string against
// tenant_notification_rules.alert_source (rule_engine.go
// GetTenantRulesForAlert) — most of it was fiction (`certificates`,
// `platform` are emitted by nothing) while it omitted every real tenant-track
// producer, so only 4 of 9 values could ever match a rule. The real
// vocabulary is GET /alert-catalog's `source` field — generated from
// standards/alert-registry.yaml, and GET /alert-catalog only ever returns
// tenant-track entries — unioned with the handful of tenant-scoped
// AlertSource labels that exist outside the registry (they raise no
// `alert_type`, so they have no catalog row to derive from):
//   system            — notification-service's own delivery/config notices
//   digest            — notification-service's periodic digest summaries
//   billing-service   — admin-service's billing-webhook alerts
//   billing           — admin-service's subscription/invoice notifications
//   discovery         — discovery job results (device-interrogation, cluster-sensor)
//   ticketing         — compliance-engine's ticket assignment / status events
//   remediation_plans — compliance-engine's remediation-plan events
//
// The four added last were real producers the dropdown did not offer, so a
// routing rule scoped to them could never be created (integrations review M26).
// alert-sources.test.ts now scans the Go producers for every AlertSource they
// publish to notifications.send and fails when this list lacks one — add new
// producer sources HERE.
//
// Kept DOM/network-free so both pieces — the option-list arithmetic and the
// catalog fetch — are unit-testable independently of the modal.
import { clients } from '../../lib/clients';

export const NON_REGISTRY_ALERT_SOURCES = ['system', 'digest', 'billing-service', 'billing', 'discovery', 'ticketing', 'remediation_plans'];

/** The routing-rule "Alert source" options: 'all' + every source that can
 *  actually appear on `alert_source`, plus whatever the rule being edited
 *  already has (so an edit never orphans a value the select can't render). */
export function alertSourceOptions(registrySources: string[], current: string): string[] {
  const sources = new Set([...registrySources, ...NON_REGISTRY_ALERT_SOURCES, current].filter((s) => s !== 'all'));
  return ['all', ...[...sources].sort()];
}

// Inventory changes (DCIM gap 5) are offered as a SOURCE of their own in the
// rule editor although on the wire they are alert_source `inventory-service` +
// alert_type `object_changed` (standards/alert-registry.yaml). They are a
// different thing from alerts — something happened, not a condition to fix —
// and notification-service routes them ONLY to a rule that names the type, so
// the editor has to set alert_type, which it never did for any other source.
export const INVENTORY_CHANGES_OPTION = 'inventory-changes';
export const INVENTORY_CHANGES_LABEL = 'Inventory changes';
export const OBJECT_CHANGED_ALERT_TYPE = 'object_changed';
export const INVENTORY_CHANGES_ALERT_SOURCE = 'inventory-service';

/** The editor option a stored rule shows as. */
export function ruleSourceOption(rule: { alert_source: string; alert_type?: string | null } | null): string {
  if (!rule) return 'all';
  return rule.alert_type === OBJECT_CHANGED_ALERT_TYPE ? INVENTORY_CHANGES_OPTION : rule.alert_source;
}

/** What an editor option stores: alert_source, and alert_type for Inventory changes. */
export function ruleSelection(option: string): { alert_source: string; alert_type?: string } {
  return option === INVENTORY_CHANGES_OPTION
    ? { alert_source: INVENTORY_CHANGES_ALERT_SOURCE, alert_type: OBJECT_CHANGED_ALERT_TYPE }
    : { alert_source: option };
}

/** The label of an editor option. */
export function ruleSourceLabel(option: string): string {
  return option === INVENTORY_CHANGES_OPTION ? INVENTORY_CHANGES_LABEL : option;
}

/** The one-line summary a rule shows in the Routing Rules list. */
export function ruleSummary(rule: {
  alert_source: string; alert_type?: string | null; severity_filter?: string[] | null;
  change_filter?: { object_kinds?: string[] | null; actions?: string[] | null; include_intake?: boolean; include_sync?: boolean } | null;
}): string {
  if (rule.alert_type === OBJECT_CHANGED_ALERT_TYPE) {
    const f = rule.change_filter;
    const kinds = f?.object_kinds?.length ? f.object_kinds.join(', ') : 'all kinds';
    const actions = f?.actions?.length ? f.actions.join('/') : 'all actions';
    const extra = [f?.include_intake && 'incl. discovery', f?.include_sync && 'incl. sync'].filter(Boolean);
    return [INVENTORY_CHANGES_LABEL, kinds, actions, ...extra].join(' · ');
  }
  return [rule.alert_source, rule.alert_type, rule.severity_filter?.join('/')].filter(Boolean).join(' · ');
}

/** The tenant-track producer set, straight from the generated registry catalog. */
export async function fetchAlertCatalogSources(): Promise<string[]> {
  const { data, error } = await clients.compliance.GET('/alert-catalog', {});
  if (error || !data) throw new Error('Failed to load the alert catalog');
  return data.catalog.map((e) => e.source);
}
