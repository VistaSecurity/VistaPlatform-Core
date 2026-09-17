package hostinventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The parity rule, asserted rather than asserted-in-a-comment.
//
// One fixture, two runners. The local fake passes argv through as
// exec.Command would; the SSH fake puts every argv through the REAL renderArgv
// first, so a quoting rule that would break on the wire breaks here. The two
// Reports must be byte-identical.
//
// To mutation-test: make any collector consult opts.Mode for something other
// than the documented interface fallback — for example, skip the DMI reads in
// remote mode — and this fails.
func TestTransportParity_LocalAndRemoteProduceIdenticalReports(t *testing.T) {
	opts := Options{Platform: PlatformLinux, Now: fixedNow}

	local := scriptUbuntu(t, newFakeLocal())
	localOpts := opts
	localOpts.Mode = ModeLocal
	localReport, err := Collect(context.Background(), local, localOpts)
	if err != nil {
		t.Fatalf("local collect: %v", err)
	}

	remote := scriptUbuntu(t, newFakeSSH())
	remoteOpts := opts
	remoteOpts.Mode = ModeRemote
	remoteReport, err := Collect(context.Background(), remote, remoteOpts)
	if err != nil {
		t.Fatalf("remote collect: %v", err)
	}

	// Mode is the ONE field that must differ — it is what the two collections
	// are being told apart by. Normalise it, then require everything else to
	// match byte for byte.
	if localReport.Mode != ModeLocal || remoteReport.Mode != ModeRemote {
		t.Fatalf("modes were not recorded: %q / %q", localReport.Mode, remoteReport.Mode)
	}
	remoteReport.Mode = ModeLocal

	localJSON := mustJSON(t, localReport)
	remoteJSON := mustJSON(t, remoteReport)
	if localJSON != remoteJSON {
		t.Errorf("local and remote reports diverged.\nlocal:  %s\nremote: %s", localJSON, remoteJSON)
	}

	// Both must have run the SAME commands. Identical output from different
	// commands would be parity of the fixture rather than of the collector.
	for _, argv := range [][]string{linuxCmdKernel, linuxCmdNodename, linuxCmdIPJ, linuxCmdDpkg, linuxCmdSS} {
		if !local.ran(argv) {
			t.Errorf("local never ran %v", argv)
		}
		if !remote.ran(argv) {
			t.Errorf("remote never ran %v", argv)
		}
	}
}

// A full, realistic Ubuntu collection, asserted end to end.
func TestCollectLinux_Ubuntu(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow, AgentID: "agent-7f2c",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	for _, section := range []string{SectionHost, SectionHardware, SectionInterfaces, SectionPackages, SectionListeners, SectionCertStores} {
		if !rep.SectionOK(section) {
			t.Errorf("section %s = %q, want ok (errors: %+v)", section, rep.SectionState(section), rep.Errors)
		}
	}

	if rep.Host.OS != "Ubuntu" || rep.Host.Kernel != "5.15.0-113-generic" {
		t.Errorf("host: %+v", rep.Host)
	}
	if rep.Host.Hostname != "app-01" || rep.Host.FQDN != "app-01.example.net" || rep.Host.Domain != "example.net" {
		t.Errorf("names: %+v", rep.Host)
	}
	if rep.Hardware.Serial != "7BQ1EX3" || rep.Hardware.Vendor != "Dell Inc." {
		t.Errorf("hardware: %+v", rep.Hardware)
	}
	if len(rep.Packages) != 7 || len(rep.Interfaces) != 4 || len(rep.Listeners) != 5 || len(rep.BoundUDPSockets) != 3 {
		t.Errorf("counts: %d packages / %d interfaces / %d listeners",
			len(rep.Packages), len(rep.Interfaces), len(rep.Listeners))
	}
	if rep.AgentID != "agent-7f2c" {
		t.Errorf("agent id: %q", rep.AgentID)
	}
}

// The agent's own id identifies the agent's own host. Stamping it on a report
// about a DIFFERENT machine would give two assets one identity, and the
// identification engine merges on identity.
//
// To mutation-test: in Collect, replace the `if opts.Mode == ModeLocal` guard
// around `rep.AgentID = opts.AgentID` with an unconditional assignment.
func TestCollect_RemoteModeNeverCarriesTheAgentID(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeSSH()), Options{
		Mode: ModeRemote, Platform: PlatformLinux, Now: fixedNow, AgentID: "agent-7f2c",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rep.AgentID != "" {
		t.Fatalf("a remote report carried the agent's id (%q); that id belongs to the agent's own host", rep.AgentID)
	}
}

// Three-valued honesty: a section that FAILED must not look like a section that
// found nothing. This is the rule the whole Sections map exists for.
func TestCollect_AFailedSectionIsNotAnEmptyOne(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	// Take away every package manager.
	delete(f.commands, strings.Join(linuxCmdDpkg, " "))

	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	if rep.SectionState(SectionPackages) != SectionFailed {
		t.Fatalf("packages section = %q, want %q", rep.SectionState(SectionPackages), SectionFailed)
	}
	if len(rep.Packages) != 0 {
		t.Errorf("a failed section must leave its slice empty, got %d packages", len(rep.Packages))
	}
	if rep.SectionOK(SectionPackages) {
		t.Error("SectionOK reported true for a failed section")
	}
	var found bool
	for _, e := range rep.Errors {
		if e.Step == SectionPackages {
			found = true
		}
	}
	if !found {
		t.Error("a failed section recorded no error; its emptiness is then indistinguishable from an answer")
	}

	// And the rest of the collection must survive: a partial inventory is worth
	// having.
	if !rep.SectionOK(SectionHost) || rep.Host.OS != "Ubuntu" {
		t.Errorf("one failed section took the whole report down: %+v", rep.Host)
	}
}

// DMI is root-only on every mainstream distribution. An unprivileged agent
// must leave the serial ABSENT, never empty-but-present — an empty serial
// shared by the whole estate is one asset.
func TestCollectLinux_UnreadableDMILeavesTheFactAbsent(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	f.missingFile(linuxDMIPaths["serial"])
	f.missingFile(linuxDMIPaths["uuid"])

	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rep.Hardware.Serial != "" || rep.Hardware.UUID != "" {
		t.Fatalf("an unreadable DMI field produced a value: %+v", rep.Hardware)
	}
	// The readable fields still came through, and the section is still ok —
	// an unprivileged read is the expected case, not a broken collector.
	if rep.Hardware.Vendor != "Dell Inc." || !rep.SectionOK(SectionHardware) {
		t.Errorf("hardware: %+v (section %q)", rep.Hardware, rep.SectionState(SectionHardware))
	}

	// And the absent serial must not become an identifier either.
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	for _, fact := range result.Facts {
		if fact.Subject.Identifier("serial_number") != "" {
			t.Fatalf("an unread serial became an identifier: %+v", fact.Subject.Identifiers)
		}
	}
}

// A partial /proc snapshot cannot be treated as a complete listener baseline:
// it would retire unseen endpoints and cannot distinguish accepted connections.
func TestCollectLinux_PartialProcNetTCPFailsClosed(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	delete(f.commands, strings.Join(linuxCmdSS, " "))
	f.file("/proc/net/tcp", fixture(t, "linux", "proc-net-tcp.txt"))
	f.missingFile("/proc/net/tcp6")

	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rep.SectionState(SectionListeners) != SectionFailed {
		t.Fatalf("listeners = %q, want failed: %+v", rep.SectionState(SectionListeners), rep.Errors)
	}
	if len(rep.Listeners) != 0 {
		t.Errorf("partial listener snapshot escaped: %+v", rep.Listeners)
	}
	// The one unreadable source is still reported, so a reader knows the IPv6
	// half is missing rather than empty.
	if len(rep.Errors) == 0 {
		t.Error("the unreadable /proc/net/tcp6 was not recorded")
	}
}

func TestCollectLinux_FallsBackToCompleteProcNetSocketSnapshot(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	delete(f.commands, strings.Join(linuxCmdSS, " "))
	f.file("/proc/net/tcp", fixture(t, "linux", "proc-net-tcp.txt"))
	f.file("/proc/net/tcp6", "  sl  local_address rem_address st\n")
	f.file("/proc/net/udp", "  sl  local_address rem_address st\n")
	f.file("/proc/net/udp6", "  sl  local_address rem_address st\n")
	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.SectionOK(SectionListeners) || !rep.SectionOK(SectionBoundUDP) {
		t.Fatalf("complete fallback states: %+v errors=%+v", rep.Sections, rep.Errors)
	}
	if len(rep.Listeners) != 3 {
		t.Fatalf("listeners=%+v, want three TCP listeners", rep.Listeners)
	}
}

func TestCollectLinux_PartialProcNetUDPFailsClosed(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	delete(f.commands, strings.Join(linuxCmdSS, " "))
	f.file("/proc/net/tcp", "  sl  local_address rem_address st\n")
	f.file("/proc/net/tcp6", "  sl  local_address rem_address st\n")
	f.file("/proc/net/udp", "  sl  local_address rem_address st\n")
	f.missingFile("/proc/net/udp6")
	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SectionState(SectionBoundUDP) != SectionFailed || len(rep.BoundUDPSockets) != 0 {
		t.Fatalf("partial UDP snapshot = state %q, value %#v; want failed and omitted", rep.SectionState(SectionBoundUDP), rep.BoundUDPSockets)
	}
}

// DetectPlatform must probe the same way through either transport, or
// detection becomes the thing that makes the two modes disagree.
func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeRunner)
		want  string
	}{
		{"linux", func(f *fakeRunner) { f.cmd([]string{"uname", "-s"}, "Linux\n") }, PlatformLinux},
		{"darwin", func(f *fakeRunner) { f.cmd([]string{"uname", "-s"}, "Darwin\n") }, PlatformDarwin},
		{
			// Windows PowerShell 5.1 leaves $PSVersionTable.Platform unset, so a
			// SUCCESSFUL command with empty output is itself the signal.
			"windows powershell 5.1",
			func(f *fakeRunner) { f.cmd(powershellArgv(`Write-Output $PSVersionTable.Platform`), "\n") },
			PlatformWindows,
		},
		{
			"windows powershell 7",
			func(f *fakeRunner) { f.cmd(powershellArgv(`Write-Output $PSVersionTable.Platform`), "Win32NT\n") },
			PlatformWindows,
		},
	}

	for _, tc := range tests {
		for _, mk := range []func() *fakeRunner{newFakeLocal, newFakeSSH} {
			f := mk()
			tc.setup(f)
			t.Run(tc.name+"/"+f.label, func(t *testing.T) {
				got, err := DetectPlatform(context.Background(), f)
				if err != nil {
					t.Fatalf("detect: %v", err)
				}
				if got != tc.want {
					t.Errorf("platform = %q, want %q", got, tc.want)
				}
			})
		}
	}
}

// A target that answers neither probe must be an error, not a default. A
// guessed platform runs the wrong command set against a live customer host.
func TestDetectPlatform_UnknownTargetIsAnError(t *testing.T) {
	if _, err := DetectPlatform(context.Background(), newFakeLocal()); err == nil {
		t.Fatal("an unrecognised target was accepted")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
