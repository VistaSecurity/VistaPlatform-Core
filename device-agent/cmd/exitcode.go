package main

import (
	"errors"
	"os"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
)

// exitNeedsOperator is the exit status for a start that can only be fixed by a
// person: a registration key the platform rejected, a config file that cannot
// be parsed, or a data directory the agent cannot write. It is sysexits.h
// EX_CONFIG. The installer's systemd unit names it in RestartPreventExitStatus,
// so the service stops instead of retrying the same doomed start every
// RestartSec.
const exitNeedsOperator = 78

// exitProcess is os.Exit, replaceable so tests can observe the status.
var exitProcess = os.Exit

// registrationFailureExitCode is the exit status for a failed registration. A
// REJECTED key (invalid, expired, already used) never succeeds on retry, so it
// needs a person; any other failure (platform down, network) might, and exits 1
// so the service manager's restart is the retry.
func registrationFailureExitCode(err error) int {
	var rejected *api.RegistrationRejectedError
	if errors.As(err, &rejected) {
		return exitNeedsOperator
	}
	return 1
}
