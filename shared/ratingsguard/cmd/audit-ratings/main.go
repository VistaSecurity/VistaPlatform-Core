package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/ratingsguard"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	type row struct {
		Path        string `json:"path"`
		Line        int    `json:"line"`
		Symbol      string `json:"symbol"`
		Reason      string `json:"reason"`
		Fingerprint string `json:"fingerprint"`
	}
	rows := []row{}
	scanned := 0
	for _, dir := range []string{"services", "shared", "sensor", "device-agent"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, "_gen.go") {
				return nil
			}
			rel, e := filepath.Rel(root, p)
			if e != nil {
				return e
			}
			source, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			scanned++
			results, e := ratingsguard.Inspect(rel, source)
			if e != nil {
				return e
			}
			for _, v := range results {
				rows = append(rows, row{filepath.ToSlash(rel), v.Line, v.Symbol, v.Reason, v.Fingerprint})
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if scanned == 0 {
		fmt.Fprintln(os.Stderr, "no Go files scanned")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(rows); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
