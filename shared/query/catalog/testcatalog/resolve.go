package testcatalog

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// storedIdentifierKinds is the ADR-0002 D3 registry, in precedence order: the
// values the `identifier` target's `kind` COLUMN may hold.
//
// `mac` is deliberately NOT here, and `name` deliberately is. The `mac` alias
// is a spelling of a PATH (`id.mac:aa:bb:*`, the §3 cheat sheet's form) and is
// rewritten to `mac_address` before it reaches the column; publishing it as a
// legal VALUE of `kind` would offer `kind:mac`, which validates and then
// matches no row for ever, because nothing stores that string. That is the
// divergence-from-the-registry the parity test now refuses.
var storedIdentifierKinds = []string{
	"declaration_id",
	"agent_id",
	"sensor_id",
	"cloud_resource_id",
	"serial_number",
	"cmdb_sys_id",
	"ssh_host_key_fingerprint",
	"mac_address",
	"name",
	"fqdn",
	"hostname",
	"ip_address",
}

// identifierKinds is every spelling `id.<kind>` accepts — the stored kinds plus
// the documented `mac` alias.
var identifierKinds = append(append([]string(nil), storedIdentifierKinds...), "mac")

// IdentifierAnyKind is the pseudo-kind that matches an identifier of ANY kind
// (§13 A1). It cannot collide with a real kind: the registry validates kinds
// against shared/assetclass, and "any" is reserved here.
const IdentifierAnyKind = "any"

// identifierKindAliases maps a written kind to the stored one.
var identifierKindAliases = map[string]string{"mac": "mac_address"}

// attrKeys are representative class attributes (ADR-0002 D2). The generated
// catalogue will carry every class's attribute schema; these are enough to
// exercise the jsonb shape and every type that reaches it.
// Every entry's TYPE and closed set are the registry-derived catalogue's, which
// reads `standards/asset-classes.yaml`. A `string` attribute there is a
// `keyword` here — `os_version` was `number`, which made `attr.os_version < 3`
// a legal predicate against a column holding "15.2(4)E10".
var attrKeys = map[string]catalog.FieldInfo{
	"os_version":         {Type: ast.TypeKeyword},
	"operating_system":   {Type: ast.TypeKeyword},
	"firmware_version":   {Type: ast.TypeKeyword},
	"provider":           {Type: ast.TypeKeyword, Enum: []string{"aws", "azure", "gcp", "oci", "other"}},
	"region":             {Type: ast.TypeKeyword},
	"account_id":         {Type: ast.TypeKeyword},
	"model":              {Type: ast.TypeKeyword},
	"vendor":             {Type: ast.TypeKeyword},
	"cpu_count":          {Type: ast.TypeNumber},
	"memory_mb":          {Type: ast.TypeNumber},
	"controller_managed": {Type: ast.TypeBoolean},
}

// factKeys are representative registered fact keys (standards/fact-keys.yaml,
// workstream 0.3).
// Keys and types are `standards/fact-keys.yaml`'s. `eol.software.date` and
// `cve.max_cvss` were here and are not registered keys at all — the first is
// spelled `eol.sw.date`, the second has never existed — so both offered a
// predicate the registry-derived catalogue rejects and the database could never
// answer.
var factKeys = map[string]catalog.FieldInfo{
	"os.name":          {Type: ast.TypeKeyword},
	"os.version":       {Type: ast.TypeKeyword},
	"eol.os.date":      {Type: ast.TypeTimestamp},
	"eol.sw.date":      {Type: ast.TypeTimestamp},
	"hw.model":         {Type: ast.TypeKeyword},
	"hw.serial":        {Type: ast.TypeKeyword},
	"sw.package_count": {Type: ast.TypeNumber},
}

// classTree is the ADR-0002 D2 hierarchy: fixed top level, fixed children.
var classTree = []catalog.ClassInfo{
	{Key: "hardware", Path: "hardware"},
	{Key: "computer", Path: "hardware.computer"},
	{Key: "server", Path: "hardware.computer.server"},
	{Key: "workstation", Path: "hardware.computer.workstation"},
	{Key: "laptop", Path: "hardware.computer.laptop"},
	{Key: "mobile", Path: "hardware.computer.mobile"},
	{Key: "network_device", Path: "hardware.network_device"},
	{Key: "switch", Path: "hardware.network_device.switch"},
	{Key: "router", Path: "hardware.network_device.router"},
	{Key: "firewall", Path: "hardware.network_device.firewall"},
	{Key: "load_balancer", Path: "hardware.network_device.load_balancer"},
	{Key: "wireless_controller", Path: "hardware.network_device.wireless_controller"},
	{Key: "access_point", Path: "hardware.network_device.access_point"},
	{Key: "vpn_gateway", Path: "hardware.network_device.vpn_gateway"},
	{Key: "storage_device", Path: "hardware.storage_device"},
	{Key: "printer", Path: "hardware.printer"},
	{Key: "ot_device", Path: "hardware.ot_device"},
	{Key: "plc", Path: "hardware.ot_device.plc"},
	{Key: "rtu", Path: "hardware.ot_device.rtu"},
	{Key: "hmi", Path: "hardware.ot_device.hmi"},
	{Key: "ied", Path: "hardware.ot_device.ied"},
	{Key: "iot_device", Path: "hardware.iot_device"},
	{Key: "bmc", Path: "hardware.bmc"},
	{Key: "virtual", Path: "virtual"},
	{Key: "virtual_machine", Path: "virtual.virtual_machine"},
	{Key: "container", Path: "virtual.container"},
	{Key: "cluster", Path: "virtual.cluster"},
	{Key: "hypervisor", Path: "virtual.hypervisor"},
	{Key: "cloud_resource", Path: "cloud_resource"},
	{Key: "compute_instance", Path: "cloud_resource.compute_instance"},
	{Key: "managed_database", Path: "cloud_resource.managed_database"},
	{Key: "object_storage", Path: "cloud_resource.object_storage"},
	{Key: "key_store", Path: "cloud_resource.key_store"},
	{Key: "cloud_load_balancer", Path: "cloud_resource.cloud_load_balancer"},
	{Key: "api_gateway", Path: "cloud_resource.api_gateway"},
	{Key: "cdn_distribution", Path: "cloud_resource.cdn_distribution"},
	{Key: "serverless_function", Path: "cloud_resource.serverless_function"},
	{Key: "virtual_network", Path: "cloud_resource.virtual_network"},
	{Key: "subnet", Path: "cloud_resource.subnet"},
	{Key: "application", Path: "application"},
	{Key: "web_application", Path: "application.web_application"},
	{Key: "database_instance", Path: "application.database_instance"},
	{Key: "service_daemon", Path: "application.service_daemon"},
	{Key: "middleware", Path: "application.middleware"},
	{Key: "service", Path: "service"},
	{Key: "business_service", Path: "service.business_service"},
	{Key: "technical_service", Path: "service.technical_service"},
	{Key: "external", Path: "external"},
	{Key: "unknown_host", Path: "unknown_host"},
}

// ClassExists implements catalog.Catalog. A class is nameable by its key or by
// its full path, because §9 example 3 writes `class:hardware.computer.server`
// while example 14 writes `class=hypervisor`.
func (c *Catalog) ClassExists(key string) (catalog.ClassInfo, bool) {
	key = strings.ToLower(key)
	for _, ci := range classTree {
		if ci.Key == key || ci.Path == key {
			return ci, true
		}
	}
	return catalog.ClassInfo{}, false
}

// ClassKeys lists every class key and path, for suggestions.
func ClassKeys() []string {
	out := make([]string, 0, len(classTree))
	for _, ci := range classTree {
		out = append(out, ci.Key)
	}
	return out
}

// Resolve implements catalog.Catalog.
func (c *Catalog) Resolve(target string, path []string) (ast.FieldRef, error) {
	target = strings.ToLower(target)
	tgt, ok := catalog.FindTarget(c, target)
	if !ok {
		return ast.FieldRef{}, &catalog.ResolveError{Target: target, Path: path, Reason: catalog.ReasonUnknownTarget}
	}
	if len(path) == 0 {
		return ast.FieldRef{}, &catalog.ResolveError{Target: target, Path: path, Reason: catalog.ReasonUnknownField}
	}

	// A bare `id` is the ROW's uuid on every target, never the identifier
	// namespace (§13 amendment 1). Taking the namespace branch first made
	// `assets.id` — a first-class uuid column §4.3 lists — unreachable, and
	// published two different fields under one name. The any-kind identifier
	// form is `id.any`.
	if len(path) == 1 && strings.EqualFold(path[0], "id") {
		return c.resolveFirstClass(tgt, path)
	}
	if ns, isNS := ast.IsNamespace(path[0]); isNS && namespaceAllowed(tgt.Name, ns) {
		return c.resolveNamespaced(tgt, ns, path)
	}

	return c.resolveFirstClass(tgt, path)
}

// resolveFirstClass resolves a path against the target's own column catalogue.
func (c *Catalog) resolveFirstClass(tgt catalog.Target, path []string) (ast.FieldRef, error) {
	name := strings.Join(path, ".")
	for _, f := range fieldsByTarget[tgt.Name] {
		if strings.EqualFold(f.Name, name) {
			return fieldRef(path, f, ast.NamespaceNone, f.Name), nil
		}
	}
	return ast.FieldRef{}, &catalog.ResolveError{Target: tgt.Name, Path: path, Reason: catalog.ReasonUnknownField}
}

// resolveNamespaced resolves attr./fact./id./tag. paths, and the bare `tag` and
// `id` forms that mean "any key" and "any kind" (§3 cheat sheet).
func (c *Catalog) resolveNamespaced(tgt catalog.Target, ns ast.Namespace, path []string) (ast.FieldRef, error) {
	key := strings.Join(path[1:], ".")
	if key == "" {
		// Bare `id` never reaches here — it is the row's uuid (§13 A1).
		if ns == ast.NamespaceTag {
			return fieldRef(path, catalog.FieldInfo{
				Name: "tag", Type: ast.TypeText,
				Accessor: ast.Accessor{Kind: ast.AccessorTagAny, JSONColumn: "tags"},
			}, ns, ""), nil
		}
		return ast.FieldRef{}, &catalog.ResolveError{
			Target: tgt.Name, Path: path, Namespace: ns, Reason: catalog.ReasonEmptyKey,
		}
	}

	switch ns {
	case ast.NamespaceAttr:
		info, ok := attrKeys[strings.ToLower(key)]
		if !ok {
			return ast.FieldRef{}, &catalog.ResolveError{
				Target: tgt.Name, Path: path, Namespace: ns, Reason: catalog.ReasonUnknownKey,
			}
		}
		info.Name = "attr." + strings.ToLower(key)
		info.Accessor = ast.Accessor{Kind: ast.AccessorJSONB, JSONColumn: "attributes", Key: strings.ToLower(key)}
		return fieldRef(path, info, ns, strings.ToLower(key)), nil

	case ast.NamespaceFact:
		info, ok := factKeys[strings.ToLower(key)]
		if !ok {
			return ast.FieldRef{}, &catalog.ResolveError{
				Target: tgt.Name, Path: path, Namespace: ns, Reason: catalog.ReasonUnknownKey,
			}
		}
		info.Name = "fact." + strings.ToLower(key)
		info.Accessor = ast.Accessor{Kind: ast.AccessorFact, Column: "value", Key: strings.ToLower(key)}
		return fieldRef(path, info, ns, strings.ToLower(key)), nil

	case ast.NamespaceID:
		kind := strings.ToLower(key)
		if kind == IdentifierAnyKind {
			// `id.any:"aa:bb:…"` is "an identifier of any kind with this
			// value" — what the §3 cheat sheet used to spell `id:"…"`, before
			// that collided with the row's own uuid (§13 A1).
			return fieldRef(path, catalog.FieldInfo{
				Name: "id.any", Type: ast.TypeKeyword,
				Accessor: ast.Accessor{Kind: ast.AccessorIdentifierAny, Column: "value"},
			}, ns, ""), nil
		}
		if !containsFold(identifierKinds, kind) {
			return ast.FieldRef{}, &catalog.ResolveError{
				Target: tgt.Name, Path: path, Namespace: ns, Reason: catalog.ReasonUnknownKey,
			}
		}
		stored := kind
		if alias, ok := identifierKindAliases[kind]; ok {
			stored = alias
		}
		return fieldRef(path, catalog.FieldInfo{
			Name: "id." + kind, Type: ast.TypeKeyword,
			Accessor: ast.Accessor{Kind: ast.AccessorIdentifier, Column: "value", Key: stored},
		}, ns, stored), nil

	default: // tag: any tenant key resolves; tags are free-form by design.
		return fieldRef(path, catalog.FieldInfo{
			Name: "tag." + key, Type: ast.TypeKeyword,
			Accessor: ast.Accessor{Kind: ast.AccessorJSONB, JSONColumn: "tags", Key: key},
		}, ns, key), nil
	}
}

// fieldRef builds the resolved reference the validator hands the translator.
func fieldRef(path []string, info catalog.FieldInfo, ns ast.Namespace, key string) ast.FieldRef {
	return ast.FieldRef{
		Segments:  path,
		Text:      strings.Join(path, "."),
		Namespace: ns,
		Key:       key,
		Type:      info.Type,
		Accessor:  info.Accessor,
		Enum:      info.Enum,
		Resolved:  true,
	}
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
