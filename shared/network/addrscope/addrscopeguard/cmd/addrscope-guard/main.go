// Command addrscope-guard fails when Go code under shared/, services/, sensor/
// or device-agent/ defines private address space outside
// shared/network/addrscope ( F3). `make audit` runs it with the repo root
// as its only argument.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/network/addrscope/addrscopeguard"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: addrscope-guard <repo-root>")
		os.Exit(2)
	}
	violations, err := addrscopeguard.Scan(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "addrscope-guard:", err)
		os.Exit(2)
	}
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "❌ private address space is defined outside shared/network/addrscope (#2374 F3):\n  %s\n",
			strings.Join(violations, "\n  "))
		os.Exit(1)
	}
	fmt.Println("✅ one private-address definition (shared/network/addrscope)")
}
