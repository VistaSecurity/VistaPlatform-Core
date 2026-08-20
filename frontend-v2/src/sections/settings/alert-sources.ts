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
//   system           — notification-service's own delivery/config notices
//   digest           — notification-service's periodic digest summaries
//   billing-service  — admin-service's billing-webhook alerts
//
// Kept DOM/network-free so both pieces — the option-list arithmetic and the
// catalog fetch — are unit-testable independently of the modal.
import { clients } from '../../lib/clients';

export const NON_REGISTRY_ALERT_SOURCES = ['system', 'digest', 'billing-service'];

/** The routing-rule "Alert source" options: 'all' + every source that can
 *  actually appear on `alert_source`, plus whatever the rule being edited
 *  already has (so an edit never orphans a value the select can't render). */
export function alertSourceOptions(registrySources: string[], current: string): string[] {
  const sources = new Set([...registrySources, ...NON_REGISTRY_ALERT_SOURCES, current].filter((s) => s !== 'all'));
  return ['all', ...[...sources].sort()];
}

/** The tenant-track producer set, straight from the generated registry catalog. */
export async function fetchAlertCatalogSources(): Promise<string[]> {
  const { data, error } = await clients.compliance.GET('/alert-catalog', {});
  if (error || !data) throw new Error('Failed to load the alert catalog');
  return data.catalog.map((e) => e.source);
}
