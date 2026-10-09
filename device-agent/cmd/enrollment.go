package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
)

// Enrollment is one-shot. The registration key is single-use, and the private
// key the agent generates for its CSR never leaves this host — so what
// registration hands back (the agent ID, the signed client certificate, the
// platform CA that signs the mTLS endpoint) exists only in this process until
// it is written to disk. An agent that registers and then cannot save has
// spent the key on an identity nobody holds: it cannot authenticate, and it
// cannot register again.
//
// That is exactly what the console's manual steps did when run as an ordinary
// user: registration succeeded, the save failed on the root-owned default data
// path (/var/lib/crypto-device-agent), the agent logged a WARNING and moved on,
// and the run step then failed every call with "certificate signed by unknown
// authority" — the CA had been lost with the certificate.
//
// So: prove the agent can keep the result BEFORE anything is sent, and treat a
// failed save after registration as the fatal, unrecoverable event it is.

// checkEnrollmentWritable reports whether this process can write the
// certificate directory under dataPath and the config file at configPath (when
// one is named). It creates what is missing — the same directories the save
// would create — and probes each with a file it removes again.
func checkEnrollmentWritable(dataPath, configPath string) error {
	certs := filepath.Join(dataPath, "certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", certs, err)
	}
	if err := probeWritable(certs); err != nil {
		return err
	}
	if configPath == "" {
		return nil
	}
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	if err := probeWritable(dir); err != nil {
		return err
	}
	// The config file itself is rewritten in place after registration.
	if f, err := os.OpenFile(configPath, os.O_WRONLY, 0); err == nil {
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot write %s: %w", configPath, err)
	}
	return nil
}

func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// enrollmentUnwritableMessage is what the operator is told when the check
// fails. Nothing has been sent, so the key is still good — the most useful
// thing to say.
func enrollmentUnwritableMessage(err error, dataPath string) string {
	return fmt.Sprintf("this agent cannot store its enrollment: %v\n"+
		"   Nothing was sent to the platform — the registration key is still unused.\n"+
		"   On Linux, install it with install-device-agent.sh, which runs it as a service with a\n"+
		"   data directory it owns. Otherwise run it as a user that can write %s,\n"+
		"   or set data_path in its config to a directory this user can write.", err, dataPath)
}

// enrollmentLostMessage is what the operator is told when the save fails
// AFTER registration. Unreachable once checkEnrollmentWritable has passed,
// barring a full disk or a race; honest if it happens anyway.
func enrollmentLostMessage(agentID string, err error) string {
	return fmt.Sprintf("registered as agent %s, but could not save its certificate: %v\n"+
		"   The registration key is spent and this enrollment cannot be recovered.\n"+
		"   Delete the agent in the console (Discovery → Sensors & Agents), generate a new key, and install again.",
		agentID, err)
}

// logRegistrationFailure reports a failed registration in the words the
// installers look for. A REJECTED registration (the key is invalid, expired or
// already used) will never succeed on retry; anything else might.
func logRegistrationFailure(err error) {
	var rejected *api.RegistrationRejectedError
	if errors.As(err, &rejected) {
		log.Printf("⛔ Registration was REJECTED by the control plane (HTTP %d): %s", rejected.StatusCode, rejected.Body)
		log.Printf("⛔ The registration key is invalid, expired, or has already been used.")
		log.Printf("⛔ Generate a new key in the web UI (Discovery → Sensors & Agents → Register) and put it in the agent's config.")
		return
	}
	log.Printf("❌ Registration failed: %v", err)
}
