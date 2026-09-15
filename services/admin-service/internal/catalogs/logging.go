package catalogs

import "log"

// logger is the package's log sink. It lived in enrich_lookup.go until the
// lookup moved to shared/catalogs (workstream 3.3 part 2); the gap pass still
// needs one, so it stays here rather than being imported from a package whose
// prefix would name the wrong subsystem in the log line.
var logger = log.New(log.Writer(), "[catalogs] ", log.LstdFlags)
