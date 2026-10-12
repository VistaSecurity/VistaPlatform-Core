// How a classification rule kind reads to a person.
//
// KIND_LABEL names every rule kind the classifier can emit. It is typed against
// the generated API contract, so a kind added to the OpenAPI enum fails `tsc`
// until it has a label, and `class-rule-labels.test.ts` reads
// shared/classify/rule.go so a kind added to the Go list fails vitest instead
// of showing a raw key in the Approvals queue.
import type { inventoryComponents } from '@vistasecurity/api-contract';

type RuleKind = inventoryComponents['schemas']['ClassificationRuleRef']['kind'];

/** How a rule kind reads to somebody who has never opened the rule table. */
export const KIND_LABEL: Readonly<Record<RuleKind, string>> = {
  oui: 'MAC prefix',
  oui_vendor: 'MAC manufacturer',
  sysobjectid: 'SNMP object ID',
  enip: 'EtherNet/IP vendor',
  cloud_type: 'Cloud resource type',
  banner: 'Service banner',
  port_profile: 'Open ports',
  model: 'Model prefix',
  platform: 'Management API',
  cdp_capabilities: 'CDP capabilities',
  lldp_capability: 'LLDP capabilities',
  mdns_service: 'Advertised service',
  os_name: 'OS name',
  dhcp_vendor_class: 'DHCP vendor class',
};

export function ruleKindLabel(kind: string): string {
  return (KIND_LABEL as Readonly<Record<string, string>>)[kind] ?? kind;
}
