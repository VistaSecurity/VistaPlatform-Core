package cryptosurface

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Every crypto-bearing class in the registry must reach the SQL, subtree
// included. Dropping the class rule silently turns every KMS key the collector
// recorded no algorithm for into "No crypto observed".
func TestSQL_CoversEveryCryptoBearingClassSubtree(t *testing.T) {
	paths := ClassPaths()
	if len(paths) == 0 {
		t.Fatal("no class is crypto_bearing — the registry flag stopped reaching the generated Go")
	}
	sql := Inline("a")
	for _, p := range paths {
		if !strings.Contains(sql, "coalesce(a.class_path = '"+p+"'") {
			t.Errorf("class %s is crypto_bearing but SQL does not match it exactly", p)
		}
		if !strings.Contains(sql, "starts_with(a.class_path, '"+p+".')") {
			t.Errorf("class %s is crypto_bearing but SQL does not match its subclasses", p)
		}
	}
	for _, want := range []string{"cloud_resource.key_store", "cloud_resource.secret_store"} {
		found := false
		for _, p := range paths {
			found = found || p == want
		}
		if !found {
			t.Errorf("%s is no longer crypto_bearing; a key or secret store with no measured algorithm would read No crypto observed", want)
		}
	}
}

// A class not marked must not be swept in: an ARP-only phone is the case the
// split exists for.
func TestSQL_DoesNotMatchUnmarkedClasses(t *testing.T) {
	sql := Inline("a")
	for _, c := range assetclass.All {
		if c.CryptoBearing {
			continue
		}
		if strings.Contains(sql, "'"+c.Path+"'") {
			t.Errorf("class %s is not crypto_bearing but appears in the SQL", c.Path)
		}
	}
}

// Every protocol must be a real public.protocol_type value. A misspelt one
// ('IPsec' for 'IPSec') matches nothing and says nothing.
func TestProtocols_AreProtocolTypeEnumValues(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/database/schema.sql")
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	block := regexp.MustCompile(`(?s)CREATE TYPE public\.protocol_type AS ENUM \((.*?)\);`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("public.protocol_type not found in schema.sql")
	}
	var body strings.Builder
	for _, line := range strings.Split(string(block[1]), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		body.WriteString(line)
	}
	values := map[string]bool{}
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(body.String(), -1) {
		values[m[1]] = true
	}
	if !values["TLS"] {
		t.Fatalf("parsed no TLS from protocol_type; the parse is broken: %v", values)
	}
	sql := Inline("a")
	for _, p := range Protocols {
		if !values[p] {
			t.Errorf("protocol %q is not a public.protocol_type value", p)
		}
		if !strings.Contains(sql, "'"+p+"'") {
			t.Errorf("protocol %q does not reach the SQL", p)
		}
	}
}

func TestSQL_ReadsEveryDurableSurface(t *testing.T) {
	sql := Inline("x")
	for _, want := range []string{
		"FROM crypto_implementations cs_ci WHERE cs_ci.asset_id = x.id AND cs_ci.deleted_at IS NULL",
		"FROM crypto_applications cs_ca WHERE cs_ca.asset_id = x.id AND cs_ca.deleted_at IS NULL",
		"FROM asset_endpoints cs_ep WHERE cs_ep.asset_id = x.id AND cs_ep.status <> 'closed'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL lost %q", want)
		}
	}
	if strings.Contains(sql, "sensor_discoveries") {
		t.Error("SQL reads sensor_discoveries, a work queue, not inventory")
	}
}

func TestSQL_RefusesUnsafeAlias(t *testing.T) {
	for _, bad := range []string{"a; DROP", "a.b", "", "1a"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("SQL(%q) did not panic", bad)
				}
			}()
			_ = Inline(bad)
		}()
	}
}

// A binder must see every value: the query translator forbids quoted literals,
// so one value that bypassed bind would break every query using the risk field.
func TestSQL_SendsEveryValueThroughBind(t *testing.T) {
	var bound []string
	sql := SQL("a", func(v string) string { bound = append(bound, v); return "$x" })
	if strings.Contains(sql, "'") {
		t.Errorf("SQL with a binder still contains a literal: %s", sql)
	}
	want := len(Protocols) + 1 + 2*len(ClassPaths())
	if len(bound) != want {
		t.Errorf("bound %d values, want %d: %v", len(bound), want, bound)
	}
}
