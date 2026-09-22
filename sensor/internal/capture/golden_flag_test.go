package capture

import "flag"

// updateGolden rewrites the cross-service discovery-shape fixtures instead of
// asserting against them.
var updateGolden = flag.Bool("update", false, "rewrite discovery-shape golden fixtures")
