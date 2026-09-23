// Package dialguard holds the dial function every appliance collector's HTTP
// client installs, and nothing else.
//
// It exists as its own package for one reason: the variable has to be
// writable from TWO test surfaces — this module's collector tests, and the
// DB-integration tests of the services that drive a collector end to end — and
// Go's internal-package rule is what keeps it writable from nowhere else. Only
// packages rooted at shared/deviceinterrogation can import it; the one outside
// door is [devicetest.AllowListener], which refuses to run outside a test
// binary.
package dialguard

import "github.com/vistasecurity/vistaplatform/shared/network"

// Dial is the dial guard the device HTTP client installs. Production never
// writes it; see the package comment for who may.
var Dial = network.OnPremDialContext
