package hostinventory

import (
	"errors"
	"fmt"
	"strings"
)

// Windows remote collection runs PowerShell over SSH, not over WinRM.
//
// # Why, and what was actually checked
//
// The intended transport was `github.com/masterzen/winrm`. Its own licence is
// Apache-2.0, which is fine. Its dependency graph is not entirely fine, and the
// graph is what gets linked into a binary we ship to customers:
//
//	masterzen/winrm                   Apache-2.0   ok
//	Azure/go-ntlmssp                  MIT          ok
//	ChrisTrenkamp/goxpath             MIT          ok
//	bodgit/ntlmssp, bodgit/windows    BSD-3        ok
//	gofrs/uuid                        MIT          ok
//	masterzen/simplexml               Apache-2.0   ok
//	jcmturner/gokrb5/v8 + 4 siblings  Apache-2.0   ok
//	jcmturner/gofork                  BSD-3        ok
//	go-logr/logr                      Apache-2.0   ok
//	tidwall/transform                 ISC          permissive, not on the list
//	hashicorp/go-cleanhttp            MPL-2.0      NOT on the list
//	hashicorp/go-uuid                 MPL-2.0      NOT on the list
//
// No GPL and no AGPL — the hard stop the brief named is not tripped. But this
// project's dependency policy is MIT / Apache / BSD, and MPL-2.0 is neither
// that nor the thing the policy bans. It is file-level copyleft: redistributing
// a binary containing it obliges us to make those files' source available. That
// is a small obligation and a manageable one — it is also an obligation this
// tree has never taken on (there is no MPL-licensed module anywhere in the
// shipped module graph today), and taking it on for the first time is an
// OWNER's decision, not a collector's.
//
// The cost side made the call easy. WinRM would add sixteen modules — including
// a full Kerberos implementation and two independent NTLM implementations — to
// a cross-compiled agent binary, to do one thing: run a PowerShell command over
// an authenticated channel. Windows Server 2019 and Windows 10 1809 onward ship
// OpenSSH Server as an installable Windows feature, and PowerShell-over-SSH is
// Microsoft's own documented remoting transport. Using it costs zero new
// modules, reuses the [SSHRunner] that remote Linux and macOS already need, and
// keeps the host-key trust policy identical across every target the agent
// touches.
//
// # What this means in practice
//
//   - `transport: ssh` reaches Linux, macOS AND Windows. On Windows the target
//     needs the OpenSSH Server feature enabled; the operator doc says so.
//   - `transport: winrm` is a recognised value that is REFUSED, with
//     [ErrWinRMUnavailable] naming the reason and the alternative. It is not
//     silently accepted and then ignored, and it is not quietly missing from
//     the enum either — an operator who types it gets an answer.
//   - Reviving WinRM means accepting MPL-2.0 into the shipped agent (or writing
//     a WS-Management client, which is a much larger thing than it sounds).
//     Either way it is a new [Runner] implementation and nothing else changes:
//     the command set, the parsers and the Report are transport-agnostic by
//     construction.
//
// See docsv4/internal/developer/standards/HOST_INVENTORY.md.

// Transport names the way a remote collection reaches its target.
type Transport string

const (
	// TransportSSH is the only implemented remote transport. It carries
	// PowerShell to Windows as readily as it carries `ss` to Linux.
	TransportSSH Transport = "ssh"
	// TransportWinRM is recognised and refused. See the file comment.
	TransportWinRM Transport = "winrm"
)

// ErrWinRMUnavailable is returned for a job that asks for the WinRM transport.
// The message is written for the operator reading it in a failed job, not for a
// developer reading a stack trace.
var ErrWinRMUnavailable = errors.New(
	"the winrm transport is not built into this agent: its Go client pulls MPL-2.0 dependencies " +
		"that are outside this product's MIT/Apache/BSD dependency policy. Use transport \"ssh\" — " +
		"it reaches Windows too, via the OpenSSH Server feature (Windows Server 2019+ / Windows 10 1809+)")

// ParseTransport validates a transport name from a job parameter.
//
// An empty value means ssh: it is the only implemented transport, so defaulting
// to it is a default rather than a guess.
func ParseTransport(s string) (Transport, error) {
	switch Transport(strings.ToLower(strings.TrimSpace(s))) {
	case "", TransportSSH:
		return TransportSSH, nil
	case TransportWinRM:
		return "", ErrWinRMUnavailable
	default:
		return "", fmt.Errorf("hostinventory: unknown transport %q; supported: %q", s, TransportSSH)
	}
}
