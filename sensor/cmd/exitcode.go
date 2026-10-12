package main

import "os"

// exitNeedsOperator is the exit status for a start that can only be fixed by a
// person: a registration key the control plane rejected, or a config file that
// cannot be parsed. It is sysexits.h EX_CONFIG. The installer's systemd unit
// names it in RestartPreventExitStatus, so the service stops instead of
// re-trying the same doomed start every RestartSec.
const exitNeedsOperator = 78

// exitProcess is os.Exit, replaceable so tests can observe the status.
var exitProcess = os.Exit
