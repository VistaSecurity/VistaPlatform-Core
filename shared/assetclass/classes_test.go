package assetclass

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests pin the invariants of the generated taxonomy. They deliberately
// restate the allowed vocabularies as literals rather than reading the
// generated IdentifierKinds / CycloneDXTypes / LegacyAssetTypes slices: a test
// that checks generated data against generated data is a test that cannot
// fail. Widening one of these lists means editing both the YAML and this file,
// which is the point — the taxonomy's outer boundary is a decision, not a
// detail.

// ADR-0002 D3, in default precedence order.
var allowedIdentifierKinds = map[string]int{
	"declaration_id":           0,
	"agent_id":                 1,
	"cloud_resource_id":        2,
	"serial_number":            3,
	"cmdb_sys_id":              4,
	"ssh_host_key_fingerprint": 5,
	"mac_address":              6,
	"fqdn":                     7,
	"hostname":                 8,
	"ip_address":               9,
	// The tenth kind, and deliberately NOT in the default precedence order:
	// `name` is declared, scoped by class key, and used only by the service
	// branch (ADR-0002 D3 erratum). A class that does not list it can never
	// match on one.
	"name": 10,
}

// CycloneDX 1.6 component types, plus "service" for classes emitted into the
// CycloneDX services array instead of components.
var allowedCycloneDXTypes = map[string]bool{
	"device": true, "operating-system": true, "application": true,
	"platform": true, "container": true, "data": true, "service": true,
	"machine-learning-model": true, "library": true, "firmware": true,
	"file": true,
}

// The four values of the public.asset_type enum this taxonomy replaces.
var allowedLegacyAssetTypes = map[string]bool{
	"server": true, "endpoint": true, "service": true, "appliance": true,
}

// ADR-0002 D2: the top level is FIXED. Tenants add leaf subclasses beneath
// these; they may not add a top-level class or reparent one. Changing this
// list is a product decision that invalidates the CMDB sync mapping, the map
// colouring and every compliance predicate written against a class prefix.
var fixedTopLevel = []string{
	"hardware", "virtual", "cloud_resource", "application", "service",
	"external", "unknown_host",
}

var iconPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

func TestAllIsNotEmpty(t *testing.T) {
	// Anchors every other test below: each one iterates All, so an empty All
	// would make the whole file a vacuous pass.
	if len(All) < len(fixedTopLevel) {
		t.Fatalf("All has %d classes, fewer than the %d fixed top-level classes", len(All), len(fixedTopLevel))
	}
}

func TestKeysAndPathsAreUnique(t *testing.T) {
	keys := map[string]bool{}
	paths := map[string]bool{}
	for _, c := range All {
		if keys[c.Key] {
			t.Errorf("duplicate class key %q", c.Key)
		}
		keys[c.Key] = true
		if c.Path == "" {
			t.Errorf("%s: empty path", c.Key)
		}
		if paths[c.Path] {
			t.Errorf("duplicate class path %q", c.Path)
		}
		paths[c.Path] = true
		if c.Label == "" {
			t.Errorf("%s: empty label", c.Key)
		}
	}
}

func TestEveryParentExists(t *testing.T) {
	for _, c := range All {
		if c.Parent == "" {
			continue
		}
		if _, ok := Get(c.Parent); !ok {
			t.Errorf("%s: parent %q is not a class", c.Key, c.Parent)
		}
		if c.Parent == c.Key {
			t.Errorf("%s: is its own parent", c.Key)
		}
	}
}

func TestParentPrecedesChild(t *testing.T) {
	// Consumers build the tree in one pass over All (the TS CLASS_TREE
	// generator does, and the seed insert relies on it if 0.2 adds a
	// self-referencing FK).
	seen := map[string]bool{}
	for _, c := range All {
		if c.Parent != "" && !seen[c.Parent] {
			t.Errorf("%s appears before its parent %s", c.Key, c.Parent)
		}
		seen[c.Key] = true
	}
}

func TestPathsMatchTheParentChain(t *testing.T) {
	for _, c := range All {
		// Walking parents must terminate at a root. A cycle shows up here as
		// a walk longer than the whole taxonomy.
		var chain []string
		cur := c
		for i := 0; ; i++ {
			if i > len(All) {
				t.Fatalf("%s: parent chain does not terminate — cycle in the class tree", c.Key)
			}
			chain = append([]string{cur.Key}, chain...)
			if cur.Parent == "" {
				break
			}
			parent, ok := Get(cur.Parent)
			if !ok {
				t.Fatalf("%s: parent %q is not a class", cur.Key, cur.Parent)
			}
			cur = parent
		}
		if want := strings.Join(chain, "."); c.Path != want {
			t.Errorf("%s: path %q, want %q from the parent chain", c.Key, c.Path, want)
		}
		if !strings.HasSuffix(c.Path, c.Key) {
			t.Errorf("%s: path %q does not end in the key", c.Key, c.Path)
		}
	}
}

func TestTopLevelClassesAreFixed(t *testing.T) {
	var got []string
	for _, c := range Roots() {
		got = append(got, c.Key)
	}
	if strings.Join(got, ",") != strings.Join(fixedTopLevel, ",") {
		t.Errorf("top-level classes are %v, want %v — the top level is fixed (ADR-0002 D2)", got, fixedTopLevel)
	}
}

func TestIdentifierPrecedenceIsWellFormed(t *testing.T) {
	for _, c := range All {
		// Empty is a statement ("dependent identity", ADR-0002 D3), so it is
		// an empty slice and never nil: nil would marshal this class's answer
		// as JSON null while the TS mirror says [] and the seed row says
		// ARRAY[]::text[] — three mirrors of one registry disagreeing.
		if c.IdentifierPrecedence == nil {
			t.Errorf("%s: IdentifierPrecedence is nil; an empty precedence must be an empty slice", c.Key)
		}
		seen := map[string]bool{}
		for _, kind := range c.IdentifierPrecedence {
			if _, ok := allowedIdentifierKinds[kind]; !ok {
				t.Errorf("%s: identifier kind %q is not one of the ten in ADR-0002 D3", c.Key, kind)
			}
			if seen[kind] {
				t.Errorf("%s: identifier kind %q listed twice", c.Key, kind)
			}
			seen[kind] = true
		}
	}
}

func TestPerClassIdentifierRules(t *testing.T) {
	// The class-specific drops ADR-0002 D3 calls out by name. Each is a real
	// misidentification if it comes back: a cloud resource's MAC belongs to
	// the hypervisor host, a container's serial to the node it lands on.
	for _, c := range All {
		has := func(kind string) bool {
			for _, k := range c.IdentifierPrecedence {
				if k == kind {
					return true
				}
			}
			return false
		}
		if IsAncestor(KeyCloudResource, c.Key) && has("mac_address") {
			t.Errorf("%s: cloud resources never identify by MAC address", c.Key)
		}
		if c.Key == KeyContainer && has("serial_number") {
			t.Errorf("%s: containers never identify by serial number", c.Key)
		}
		// ADR-0002 D3 erratum: "services identify by (tenant, class, name),
		// realised as the `name` identifier kind". It used to be an EMPTY
		// precedence, which meant nothing could identify a service at all:
		// manual create refused one for having no identifier, and a service
		// given a hostname to get past that could never be matched again.
		if IsAncestor(KeyService, c.Key) {
			if len(c.IdentifierPrecedence) != 1 || c.IdentifierPrecedence[0] != "name" {
				t.Errorf("%s: services identify by name and nothing else — precedence = %v, want [name]",
					c.Key, c.IdentifierPrecedence)
			}
		}
		// The APPLICATION branch is the other dependent-identity family
		// (ADR-0002 D3): an application is identified by its host plus product
		// plus instance, and that tuple is carried in a `name` identifier
		// scoped by the class key — see identity.ResolveDependent and
		// inventory-service's applicationDependentIdentifier.
		//
		// Without `name` these classes had `[cmdb_sys_id]` alone, so an
		// application from any source but a CMDB could never be matched a
		// second time and every poll opened another merge proposal against the
		// asset it already was.
		//
		// hostname/fqdn stay OUT: they would match the HOST asset, and an
		// application is not its host.
		if IsAncestor(KeyApplication, c.Key) {
			if !has("name") {
				t.Errorf("%s: an application has no identity of its own and must carry `name`, which holds "+
					"its (host, product, instance) key — precedence = %v", c.Key, c.IdentifierPrecedence)
			}
			if has("hostname") || has("fqdn") {
				t.Errorf("%s: an application must not identify by hostname or fqdn — those match its HOST",
					c.Key)
			}
		}
		if !IsAncestor(KeyService, c.Key) && !IsAncestor(KeyApplication, c.Key) && has("name") {
			t.Errorf("%s: only the two dependent-identity branches (service, application) identify by a "+
				"declared name; a %s that happens to carry one is still identified by what it IS",
				c.Key, c.Key)
		}
	}
}

func TestCycloneDXAndLegacyTypesAreValid(t *testing.T) {
	for _, c := range All {
		if !allowedCycloneDXTypes[c.CycloneDXType] {
			t.Errorf("%s: cyclonedx_type %q is not a CycloneDX 1.6 component type (or \"service\")", c.Key, c.CycloneDXType)
		}
		if !allowedLegacyAssetTypes[c.LegacyAssetType] {
			t.Errorf("%s: legacy_asset_type %q is not a public.asset_type enum value", c.Key, c.LegacyAssetType)
		}
	}
}

func TestIconsAreLucideExports(t *testing.T) {
	for _, c := range All {
		if !iconPattern.MatchString(c.Icon) {
			t.Errorf("%s: icon %q is not a PascalCase lucide-react export name", c.Key, c.Icon)
		}
	}

	names := lucideIconNames(t)
	if names == nil {
		// Not a silent pass: say what was not checked and where it IS checked.
		t.Skip("lucide-react is not installed (run `npm install` at the repo root) — " +
			"icon names NOT verified here. scripts/generate-asset-classes.mjs checks them at " +
			"`make generate`/`make audit` time, and frontend-v2/src/app/asset-class-icons.test.ts " +
			"imports them for real.")
	}
	for _, c := range All {
		if !names[c.Icon] {
			t.Errorf("%s: icon %q is not exported by lucide-react", c.Key, c.Icon)
		}
	}
}

// lucideIconNames parses the export names out of the installed lucide-react
// typings. Returns nil when the package is not installed.
func lucideIconNames(t *testing.T) map[string]bool {
	t.Helper()
	candidates := []string{
		"../../node_modules/lucide-react/dist/lucide-react.d.ts",
		"../../frontend-v2/node_modules/lucide-react/dist/lucide-react.d.ts",
		"../../admin-ui-v2/node_modules/lucide-react/dist/lucide-react.d.ts",
	}
	// The typings end in one `export { A, B as BIcon, ... };` statement, which
	// is the authoritative export list — it carries the deprecated aliases
	// too, so parsing the `declare const` lines instead would reject names
	// that really do resolve at runtime.
	block := regexp.MustCompile(`(?m)^export \{([^}]*)\};`)
	entry := regexp.MustCompile(`(?:\bas\s+)?([A-Za-z0-9_$]+)\s*$`)
	for _, p := range candidates {
		src, err := os.ReadFile(p) //nolint:gosec // fixed relative paths inside the repo
		if err != nil {
			continue
		}
		m := block.FindStringSubmatch(string(src))
		if m == nil {
			t.Fatalf("%s has no trailing export statement — the lucide typings shape changed, this check has gone inert", p)
		}
		names := map[string]bool{}
		for _, e := range strings.Split(m[1], ",") {
			if sub := entry.FindStringSubmatch(strings.TrimSpace(e)); sub != nil {
				names[sub[1]] = true
			}
		}
		if len(names) < 500 {
			t.Fatalf("%s parsed to %d icon names — the lucide typings shape changed, this check has gone inert", p, len(names))
		}
		return names
	}
	return nil
}

func TestGet(t *testing.T) {
	c, ok := Get(KeyServer)
	if !ok {
		t.Fatal("Get(server) not found")
	}
	if c.Path != "hardware.computer.server" {
		t.Errorf("server path = %q, want hardware.computer.server", c.Path)
	}
	if _, ok := Get("dell_poweredge"); ok {
		t.Error("Get returned a tenant subclass — only the fixed hierarchy is generated")
	}
	if _, ok := Get(""); ok {
		t.Error("Get(\"\") must not resolve")
	}
}

func TestChildren(t *testing.T) {
	var got []string
	for _, c := range Children(KeyComputer) {
		got = append(got, c.Key)
	}
	want := "server,workstation,laptop,mobile"
	if strings.Join(got, ",") != want {
		t.Errorf("Children(computer) = %v, want %s", got, want)
	}
	if len(Children(KeyServer)) != 0 {
		t.Error("Children(server) must be empty — server is a leaf")
	}
	if len(Children("nope")) != 0 {
		t.Error("Children of an unknown key must be empty")
	}
	// The empty string is every root's Parent value; it must not be treated as
	// a key, or Children("") would return the whole top level by accident.
	if len(Children("")) != 0 {
		t.Error(`Children("") must be empty — use Roots()`)
	}
}

func TestIsAncestor(t *testing.T) {
	cases := []struct {
		ancestor, key string
		want          bool
	}{
		{KeyHardware, KeyServer, true},
		{KeyComputer, KeyServer, true},
		{KeyServer, KeyServer, true},
		{KeyServer, KeyHardware, false},
		{KeyVirtual, KeyServer, false},
		{KeyCloudResource, KeySubnet, true},
		{"", KeyServer, false},
		{KeyHardware, "", false},
		{KeyHardware, "made_up", false},
		{"made_up", KeyServer, false},
	}
	for _, tc := range cases {
		if got := IsAncestor(tc.ancestor, tc.key); got != tc.want {
			t.Errorf("IsAncestor(%q, %q) = %v, want %v", tc.ancestor, tc.key, got, tc.want)
		}
	}
}

func TestEmbeddedSchemas(t *testing.T) {
	for _, c := range All {
		s, ok := Schema(c.Key)
		if !ok {
			t.Errorf("%s: no embedded attribute schema", c.Key)
			continue
		}
		if s.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", c.Key, s.Type)
		}
		if s.AdditionalProperties {
			t.Errorf("%s: schema must set additionalProperties: false", c.Key)
		}
		for name, p := range s.Properties {
			switch p.Type {
			case "string", "integer", "number", "boolean":
			case "array":
				if p.Items == nil || p.Items.Type == "" {
					t.Errorf("%s.%s: array attribute without items.type", c.Key, name)
				}
			default:
				t.Errorf("%s.%s: unsupported attribute type %q", c.Key, name, p.Type)
			}
			if p.Description == "" {
				t.Errorf("%s.%s: attribute without a description", c.Key, name)
			}
			if len(p.Enum) > 0 && p.Type != "string" {
				t.Errorf("%s.%s: enum on a non-string attribute", c.Key, name)
			}
		}
		raw, ok := SchemaJSON(c.Key)
		if !ok || !json.Valid(raw) {
			t.Errorf("%s: SchemaJSON is missing or not valid JSON", c.Key)
		}
	}
}

func TestNoAttributeRestatesAnIdentifier(t *testing.T) {
	// An identifier lives in asset_identifiers: unique across assets, with its
	// own source, confidence and first/last-seen (ADR-0002 D3). The same value
	// declared as a class attribute would sit in assets.attributes jsonb as
	// well, with no rule for which of the two wins — the reconciliation bug of
	// ADR-0002 D4 written into the schema. The first draft of the registry did
	// exactly this: cloud_resource declared `resource_id`, which is
	// `cloud_resource_id` under another name.
	//
	// The generator rejects the synonyms too (RESERVED_ATTRIBUTE_NAMES); this
	// test pins the nine kinds themselves against the hand-written list above,
	// so it cannot go vacuous if the YAML vocabulary is widened.
	for _, c := range All {
		attrs, ok := Attributes(c.Key)
		if !ok {
			t.Errorf("%s: no attribute schema", c.Key)
			continue
		}
		for name := range attrs {
			if _, reserved := allowedIdentifierKinds[name]; reserved {
				t.Errorf("%s.%s: an identifier kind is not a class attribute — it belongs in asset_identifiers", c.Key, name)
			}
		}
	}
}

func TestChildSchemasInheritTheirParents(t *testing.T) {
	for _, c := range All {
		if c.Parent == "" {
			continue
		}
		parent, ok := Schema(c.Parent)
		if !ok {
			t.Fatalf("%s: parent %s has no schema", c.Key, c.Parent)
		}
		child, ok := Schema(c.Key)
		if !ok {
			t.Fatalf("%s: no schema", c.Key)
		}
		for name, p := range parent.Properties {
			cp, present := child.Properties[name]
			if !present {
				t.Errorf("%s: does not inherit attribute %q from %s", c.Key, name, c.Parent)
				continue
			}
			if cp.Type != p.Type {
				t.Errorf("%s.%s: type %q disagrees with %s.%s (%q)", c.Key, name, cp.Type, c.Parent, name, p.Type)
			}
		}
	}
}
