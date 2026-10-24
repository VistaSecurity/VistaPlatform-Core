package main

import "github.com/vistasecurity/vistaplatform/shared/agentlogs"

// agentLogRing holds this process's most recent log lines, tee'd off the
// standard logger in main, for the console's Logs tab. Process-wide because
// the standard logger is.
var agentLogRing = agentlogs.NewRing(agentlogs.MaxLines)
