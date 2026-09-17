// Command gen-ratings writes React-free TypeScript and machine-readable ratings.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vistasecurity/vistaplatform/shared/ratingsgen"
)

func main() {
	check := flag.Bool("check", false, "fail on generated drift")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	outputs := map[string][]byte{
		"packages/primitives/src/ratings/definitions.gen.ts": ratingsgen.TypeScript(),
		"standards/generated/rating-definitions.json":        ratingsgen.JSON(),
	}
	for relative, wanted := range outputs {
		path := filepath.Join(*root, relative)
		if *check {
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, wanted) {
				fmt.Fprintln(os.Stderr, "rating definitions out of date:", relative)
				os.Exit(1)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, wanted, 0644); err != nil {
			panic(err)
		}
	}
}
