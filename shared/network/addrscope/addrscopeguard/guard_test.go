package addrscopeguard

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepositoryHasOneDefinition runs the guard over this checkout. `make
// audit` is the enforcing run (cmd/addrscope-guard); this one catches it in
// the module's own test pass when run with -count=1.
func TestRepositoryHasOneDefinition(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	violations, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("private address space is defined outside shared/network/addrscope:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestScanReportsAStrayDefinition is the mutation, run in the suite: a
// throwaway tree with a stray IsPrivate in a service must be reported by file,
// and the same tree without it must be clean.
func TestScanReportsAStrayDefinition(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range requiredRoots {
		for i := 0; i < minFilesPerRoot; i++ {
			write(filepath.Join(dir, "pkg", "f"+string(rune('a'+i))+".go"), "package pkg\n")
		}
	}
	// addrscope itself and test files may spell the ranges.
	write(filepath.Join(OwnPackage, "addrscope.go"), "package addrscope\nvar r = \"10.0.0.0/8\"\n")
	write(filepath.Join("services", "x", "x_test.go"), "package x\nimport \"net\"\nfunc f(ip net.IP) bool { return ip.IsPrivate() }\n")

	if v, err := Scan(root); err != nil || len(v) != 0 {
		t.Fatalf("clean tree: violations %v, err %v", v, err)
	}

	write(filepath.Join("services", "x", "x.go"), "package x\nimport \"net\"\nfunc f(ip net.IP) bool { return ip.IsPrivate() }\n")
	v, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || !strings.HasPrefix(v[0], filepath.Join("services", "x", "x.go")+":3:") {
		t.Fatalf("stray IsPrivate: got %v, want one violation naming services/x/x.go:3", v)
	}
}

// A scan that finds no Go code is an error, not a pass.
func TestScanRefusesAnEmptyTree(t *testing.T) {
	root := t.TempDir()
	for _, dir := range ScanRoots {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Scan(root); err == nil {
		t.Fatal("Scan of a tree with no Go files must fail")
	}
	if _, err := Scan(filepath.Join(root, "nowhere")); err == nil {
		t.Fatal("Scan of a missing root must fail")
	}
}

func TestFindDefinitions(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"net.IP IsPrivate", `package p
import "net"
func f(ip net.IP) bool { return ip.IsPrivate() }`, 1},
		{"netip IsPrivate on a call result", `package p
import "net/netip"
func f(s string) bool { return netip.MustParseAddr(s).Unmap().IsPrivate() }`, 1},
		{"RFC 1918 literals", `package p
var x = []string{"10.0.0.0/8", "192.168.0.0/16"}`, 2},
		{"172.16 literal", `package p
var x = "172.16.0.0/12"`, 1},
		{"CGNAT literal in SQL", "package p\nconst q = `SELECT 1 WHERE addr << inet '100.64.0.0/10'`", 1},
		{"ULA literal", `package p
var x = "fc00::/7"`, 1},
		{"comment only", `package p
// 10.0.0.0/8 and ip.IsPrivate() are named here in prose only.
func f() {}`, 0},
		{"documentation range", `package p
var x = "192.0.2.0/24"`, 0},
		{"addrscope call", `package p
import "github.com/vistasecurity/vistaplatform/shared/network/addrscope"
func f(s string) bool { return addrscope.ClassifyString(s) == addrscope.Private }`, 0},
		{"IsPrivate with an argument is something else", `package p
func f(r interface{ IsPrivate(string) bool }) bool { return r.IsPrivate("x") }`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FindDefinitions(token.NewFileSet(), "fixture.go", []byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("found %d definitions, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}
