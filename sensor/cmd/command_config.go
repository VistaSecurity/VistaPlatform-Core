package main

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// commandNumber reads a JSON number from a command payload. JSON decodes to
// float64, but a payload built in Go can carry any integer type; strings and
// everything else are rejected rather than coerced.
func commandNumber(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// commandWholePositive accepts a number that is a whole value above zero.
func commandWholePositive(v interface{}) (int, bool) {
	n, ok := commandNumber(v)
	if !ok || n < 1 || n != math.Trunc(n) || n > math.MaxInt32 {
		return 0, false
	}
	return int(n), true
}

func (s *Sensor) commandReply(command models.Command, status, message string, data map[string]interface{}) *models.CommandResponse {
	if data == nil {
		data = make(map[string]interface{})
	}
	return &models.CommandResponse{
		ID:           uuid.New(),
		CommandID:    command.ID,
		SensorID:     s.config.SensorID,
		Status:       status,
		Message:      message,
		ResponseData: data,
		Timestamp:    time.Now(),
	}
}

// handleUpdateConfig applies an operator's configuration change. It never
// reports success for a change that did not happen: a field of the wrong type
// or an unknown field is rejected BY NAME, and a command in which nothing could
// be applied is an error. Applied settings are written to the config file so
// they survive a restart.
func (s *Sensor) handleUpdateConfig(command models.Command) *models.CommandResponse {
	log.Printf("📝 Configuration update command received")

	configData, ok := command.Payload["config"].(map[string]interface{})
	if !ok {
		return s.commandReply(command, "error", "Invalid config payload", nil)
	}

	var applied, rejected []string
	var persistFailures []string
	reject := func(field, why string) { rejected = append(rejected, field+" ("+why+")") }
	persist := func(field string, err error) {
		if err != nil {
			persistFailures = append(persistFailures, fmt.Sprintf("%s: %v", field, err))
		}
	}

	for key := range configData {
		if key != "reporting_interval" && key != "capture_config" {
			reject(key, "unknown setting")
		}
	}

	if raw, present := configData["reporting_interval"]; present {
		if seconds, ok := commandWholePositive(raw); ok {
			persist("reporting_interval", s.applyReportingIntervalPersisted(seconds))
			applied = append(applied, "reporting_interval")
		} else {
			reject("reporting_interval", "want a whole number of seconds above 0")
		}
	}

	if raw, present := configData["capture_config"]; present {
		captureRaw, ok := raw.(map[string]interface{})
		if !ok {
			reject("capture_config", "want an object")
		} else {
			for key := range captureRaw {
				switch key {
				case "active_probing", "network_discovery", "host_observation", "dedup_ttl_minutes":
				default:
					reject("capture_config."+key, "unknown setting")
				}
			}
			s.applyCaptureUpdates(captureRaw, &applied, reject, persist)
		}
	}

	sort.Strings(rejected)
	data := map[string]interface{}{
		"updates_applied": len(applied),
		"applied":         applied,
		"skipped":         rejected,
	}

	switch {
	case len(applied) == 0:
		msg := "No settings changed"
		if len(rejected) > 0 {
			msg += "; rejected: " + strings.Join(rejected, ", ")
		} else {
			msg += ": the config payload contained no settings"
		}
		return s.commandReply(command, "error", msg, data)
	case len(persistFailures) > 0:
		data["persist_errors"] = persistFailures
		return s.commandReply(command, "error",
			fmt.Sprintf("Applied %d setting(s) for this run only; could not save them to the config file, so a restart will revert them: %s",
				len(applied), strings.Join(persistFailures, "; ")), data)
	}

	msg := fmt.Sprintf("Configuration updated (%d settings changed, saved to the config file)", len(applied))
	if len(rejected) > 0 {
		msg += "; skipped: " + strings.Join(rejected, ", ")
	}
	return s.commandReply(command, "success", msg, data)
}

func (s *Sensor) applyCaptureUpdates(captureRaw map[string]interface{}, applied *[]string,
	reject func(field, why string), persist func(field string, err error)) {
	wantBool := func(key string) (bool, bool) {
		raw, present := captureRaw[key]
		if !present {
			return false, false
		}
		b, ok := raw.(bool)
		if !ok {
			reject("capture_config."+key, "want true or false")
			return false, false
		}
		return b, true
	}

	if ap, ok := wantBool("active_probing"); ok {
		s.config.SetActiveProbing(ap)
		persist("active_probing", s.persistCaptureSetting("activeProbing", ap))
		*applied = append(*applied, "capture_config.active_probing")
		log.Printf("📝 Active probing set to: %v", ap)
	}
	if nd, ok := wantBool("network_discovery"); ok {
		s.mu.Lock()
		s.config.Capture.NetworkDiscovery = nd
		s.mu.Unlock()
		persist("network_discovery", s.persistCaptureSetting("networkDiscovery", nd))
		*applied = append(*applied, "capture_config.network_discovery")
	}
	if ho, ok := wantBool("host_observation"); ok {
		// Recorded so the value is reported back and survives a config save.
		// It does NOT take effect on the running capture: the BPF filter is
		// set when the interface handle is opened, so the change lands on the
		// next restart, and the log says so.
		s.mu.Lock()
		changed := ho != s.config.Capture.HostObservation
		s.config.Capture.HostObservation = ho
		s.mu.Unlock()
		if changed {
			log.Printf("📝 Host observation set to: %v (applies on next sensor restart — the capture filter is fixed at interface open)", ho)
		}
		persist("host_observation", s.persistCaptureSetting("hostObservation", ho))
		*applied = append(*applied, "capture_config.host_observation")
	}
	if raw, present := captureRaw["dedup_ttl_minutes"]; present {
		if minutes, ok := commandWholePositive(raw); ok {
			s.applyDedupTTL(minutes)
			persist("dedup_ttl_minutes", s.persistCaptureSetting("dedupTTLMinutes", minutes))
			*applied = append(*applied, "capture_config.dedup_ttl_minutes")
		} else {
			reject("capture_config.dedup_ttl_minutes", "want a whole number of minutes above 0")
		}
	}
}

// applyLogLevel is the one place the sensor's log level is applied. The sensor
// has two real behaviours: debug adds the source file and line to every log
// line; info, warn and error are all the normal format. It returns the level
// actually in effect so a caller can say so instead of echoing the request.
func (s *Sensor) applyLogLevel(level string) (effective string, err error) {
	switch level {
	case "debug":
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		return "debug", nil
	case "info", "warn", "error":
		log.SetFlags(log.LstdFlags)
		return "info", nil
	}
	return "", fmt.Errorf("unknown log level %q (want debug, info, warn or error)", level)
}

// handleSetLogLevel changes the running sensor's log verbosity. The change is
// immediate and is not saved: a restart returns to the configured level.
func (s *Sensor) handleSetLogLevel(command models.Command) *models.CommandResponse {
	log.Printf("📊 Set log level command received")

	level, ok := command.Payload["level"].(string)
	if !ok {
		return s.commandReply(command, "error", "Invalid log level payload", nil)
	}
	effective, err := s.applyLogLevel(level)
	if err != nil {
		return s.commandReply(command, "error", err.Error(), nil)
	}
	msg := fmt.Sprintf("Log level set to %s", effective)
	if effective != level {
		msg = fmt.Sprintf("Log level %q applied as %q: this sensor has two log formats, debug (adds source file:line) and normal", level, effective)
	}
	return s.commandReply(command, "success", msg+" (until the sensor restarts)", map[string]interface{}{
		"log_level":           effective,
		"requested_log_level": level,
		"persisted":           false,
	})
}
