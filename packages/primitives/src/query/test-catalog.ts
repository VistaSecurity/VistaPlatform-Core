import { RISK_BANDS } from '../ratings';
// The static catalogue the cross-language conformance fixtures resolve against.
//
// It is the port of Go's `shared/query/catalog/testcatalog`: the first-class
// tables are `test-fields.ts`, and the namespace vocabulary below is the same
// representative sample Go carries — eleven class attributes, seven fact keys
// and the ADR-0002 D2 class tree.
//
// Any divergence here is a divergence in the contract rather than a local
// choice, which is why the sample is not "improved": `conformance.test.ts`
// resolves 228 fixtures against it, and a key added or renamed would silently
// change what those fixtures prove.

import type { BandLadder, ClassInfo, FieldInfo } from './catalog';
import type { CatalogVocabulary, NamespaceKey } from './base-catalog';
import { BaseCatalog } from './base-catalog';
import { TEST_FIELDS_BY_TARGET } from './test-fields';

export { IDENTIFIER_ANY_KIND, IDENTIFIER_KINDS } from './targets';

/**
 * The risk/severity ladder: the CVSS v3.1/v4.0 qualitative ratings ×10, which
 * is what `models.RiskBands` holds. The production caller passes the real
 * ladder; this adapter uses the generated definitions without importing a
 * service.
 */
export const LADDER: BandLadder = {
  bands: () => RISK_BANDS.map(({ label, min }) => ({ label, min })),
};

/**
 * Representative class attributes (ADR-0002 D2). The generated catalogue
 * carries every class's attribute schema; these are enough to exercise the
 * jsonb shape and every type that reaches it.
 */
const ATTR_KEYS: Readonly<Record<string, NamespaceKey>> = {
  // Types and closed sets are the generated catalogue's, which reads
  // standards/asset-classes.yaml. A `string` attribute there is a `keyword`
  // here — `os_version` was `number`, which made `attr.os_version < 3` legal in
  // the fixtures and `operator_not_allowed` in the product.
  os_version: { type: 'keyword' },
  operating_system: { type: 'keyword' },
  firmware_version: { type: 'keyword' },
  provider: { type: 'keyword', enum: ['aws', 'azure', 'gcp', 'oci', 'other'] },
  region: { type: 'keyword' },
  account_id: { type: 'keyword' },
  model: { type: 'keyword' },
  vendor: { type: 'keyword' },
  cpu_count: { type: 'number' },
  memory_mb: { type: 'number' },
  // `managed` is not an attribute any class declares; `controller_managed` is.
  controller_managed: { type: 'boolean' },
};

/** Representative registered fact keys (standards/fact-keys.yaml). */
const FACT_KEYS_SAMPLE: Readonly<Record<string, NamespaceKey>> = {
  // Keys and types are standards/fact-keys.yaml's. `eol.software.date` is
  // spelled `eol.sw.date` there and `cve.max_cvss` has never existed, so both
  // offered a predicate the production catalogue rejects.
  'os.name': { type: 'keyword' },
  'os.version': { type: 'keyword' },
  'eol.os.date': { type: 'timestamp' },
  'eol.sw.date': { type: 'timestamp' },
  'hw.model': { type: 'keyword' },
  'hw.serial': { type: 'keyword' },
  'sw.package_count': { type: 'number' },
};

/** The ADR-0002 D2 hierarchy: fixed top level, fixed children. */
const CLASS_TREE_SAMPLE: readonly ClassInfo[] = [
  { key: 'hardware', path: 'hardware' },
  { key: 'computer', path: 'hardware.computer' },
  { key: 'server', path: 'hardware.computer.server' },
  { key: 'workstation', path: 'hardware.computer.workstation' },
  { key: 'laptop', path: 'hardware.computer.laptop' },
  { key: 'mobile', path: 'hardware.computer.mobile' },
  { key: 'network_device', path: 'hardware.network_device' },
  { key: 'switch', path: 'hardware.network_device.switch' },
  { key: 'router', path: 'hardware.network_device.router' },
  { key: 'firewall', path: 'hardware.network_device.firewall' },
  { key: 'load_balancer', path: 'hardware.network_device.load_balancer' },
  { key: 'wireless_controller', path: 'hardware.network_device.wireless_controller' },
  { key: 'access_point', path: 'hardware.network_device.access_point' },
  { key: 'vpn_gateway', path: 'hardware.network_device.vpn_gateway' },
  { key: 'storage_device', path: 'hardware.storage_device' },
  { key: 'printer', path: 'hardware.printer' },
  { key: 'ot_device', path: 'hardware.ot_device' },
  { key: 'plc', path: 'hardware.ot_device.plc' },
  { key: 'rtu', path: 'hardware.ot_device.rtu' },
  { key: 'hmi', path: 'hardware.ot_device.hmi' },
  { key: 'ied', path: 'hardware.ot_device.ied' },
  { key: 'iot_device', path: 'hardware.iot_device' },
  { key: 'bmc', path: 'hardware.bmc' },
  { key: 'virtual', path: 'virtual' },
  { key: 'virtual_machine', path: 'virtual.virtual_machine' },
  { key: 'container', path: 'virtual.container' },
  { key: 'cluster', path: 'virtual.cluster' },
  { key: 'hypervisor', path: 'virtual.hypervisor' },
  { key: 'cloud_resource', path: 'cloud_resource' },
  { key: 'compute_instance', path: 'cloud_resource.compute_instance' },
  { key: 'managed_database', path: 'cloud_resource.managed_database' },
  { key: 'object_storage', path: 'cloud_resource.object_storage' },
  { key: 'key_store', path: 'cloud_resource.key_store' },
  { key: 'cloud_load_balancer', path: 'cloud_resource.cloud_load_balancer' },
  { key: 'api_gateway', path: 'cloud_resource.api_gateway' },
  { key: 'cdn_distribution', path: 'cloud_resource.cdn_distribution' },
  { key: 'serverless_function', path: 'cloud_resource.serverless_function' },
  { key: 'virtual_network', path: 'cloud_resource.virtual_network' },
  { key: 'subnet', path: 'cloud_resource.subnet' },
  { key: 'application', path: 'application' },
  { key: 'web_application', path: 'application.web_application' },
  { key: 'database_instance', path: 'application.database_instance' },
  { key: 'service_daemon', path: 'application.service_daemon' },
  { key: 'middleware', path: 'application.middleware' },
  { key: 'service', path: 'service' },
  { key: 'business_service', path: 'service.business_service' },
  { key: 'technical_service', path: 'service.technical_service' },
  { key: 'external', path: 'external' },
  { key: 'unknown_host', path: 'unknown_host' },
];

const VOCABULARY: CatalogVocabulary = {
  attrKeys: ATTR_KEYS,
  factKeys: FACT_KEYS_SAMPLE,
  classes: CLASS_TREE_SAMPLE,
};

/**
 * The static catalogue.
 *
 * It deliberately does NOT implement the optional `classKeys()` extension, and
 * neither does Go's `testcatalog` — its `ClassKeys` is a package function, not
 * a method, so `*Catalog` does not satisfy `validate.ClassLister`. An unknown
 * class key therefore reports `unknown_value` with no "did you mean" on BOTH
 * sides. Adding it here would change a message the fixtures do not pin, but it
 * would also stop this catalogue being a faithful port of that one.
 */
export class TestCatalog extends BaseCatalog {
  protected vocabulary(): CatalogVocabulary {
    return VOCABULARY;
  }

  protected firstClassFields(target: string): readonly FieldInfo[] {
    return TEST_FIELDS_BY_TARGET[target] ?? [];
  }
}

/** Returns the static catalogue. */
export function newTestCatalog(): TestCatalog {
  return new TestCatalog();
}

/** Lists every class key in the sample tree, for tests and suggestions. */
export function testClassKeys(): string[] {
  return CLASS_TREE_SAMPLE.map((ci) => ci.key);
}
