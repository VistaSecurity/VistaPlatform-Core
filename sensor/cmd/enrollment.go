package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// The registration key is single use: the control plane spends it the moment
// it issues this sensor's certificate. A sensor that cannot keep that
// certificate has therefore lost its identity for good — after a restart it
// presents a spent key, is REJECTED, and the service manager loops. So the
// sensor proves it can store the result BEFORE anything is sent, and treats a
// failed save after registration as the fatal event it is.

// checkEnrollmentWritable reports whether this process can write the
// certificate directory under dataPath and, when configPath is named, the
// existing config file there. It creates what is missing (the same directories
// the save would create) and probes each with a file it removes again.
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
	// The config file is rewritten atomically (temp file + rename in its own
	// directory), so the directory must be writable, and the file must exist.
	if err := probeWritable(filepath.Dir(configPath)); err != nil {
		return err
	}
	f, err := os.OpenFile(configPath, os.O_WRONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config file %s does not exist", configPath)
		}
		return fmt.Errorf("cannot write %s: %w", configPath, err)
	}
	return f.Close()
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

// enrollmentUnwritableMessage is what the operator is told when the preflight
// fails. Nothing has been sent, so the key is still good.
func enrollmentUnwritableMessage(err error, dataPath string) string {
	return fmt.Sprintf("this sensor cannot store its enrollment: %v\n"+
		"   Nothing was sent to the control plane — the registration key is still unused.\n"+
		"   Run the sensor as a user that can write %s and its config file,\n"+
		"   or set the data path in its config to a directory this user can write.", err, dataPath)
}

// enrollmentLostMessage is what the operator is told when the save fails AFTER
// registration. Unreachable once checkEnrollmentWritable has passed, barring a
// full disk or a race; honest if it happens anyway.
func enrollmentLostMessage(sensorID, path string, err error) string {
	return fmt.Sprintf("registered as sensor %s, but could not save %s: %v\n"+
		"   The registration key is now SPENT and this enrollment cannot be recovered.\n"+
		"   Delete the sensor in the console (Discovery → Sensors & Agents), generate a new key, and register again.",
		sensorID, path, err)
}

// persistEnrollment writes the certificates and then the sensor ID and
// certificate paths to the config file. The returned error already names the
// path and says the key is spent.
func (s *Sensor) persistEnrollment() error {
	certsDir := filepath.Join(s.config.Storage.DataPath, "certs")
	if err := saveCertificates(s.config); err != nil {
		return errors.New(enrollmentLostMessage(s.config.SensorID, certsDir, err))
	}
	log.Printf("✅ Certificates saved to: %s", certsDir)

	if s.configPath == "" {
		log.Printf("⚠️  No config file is in use, so the sensor ID and certificate paths are not recorded; a restart needs the same environment configuration")
		return nil
	}
	if err := s.saveConfigFile(); err != nil {
		return errors.New(enrollmentLostMessage(s.config.SensorID, s.configPath, err))
	}
	log.Printf("💾 Configuration saved to file with sensor ID")
	return nil
}
