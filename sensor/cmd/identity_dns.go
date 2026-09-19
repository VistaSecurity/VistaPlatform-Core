package main

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/discovery"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func (s *Sensor) handleIdentityDNS(command models.Command) *models.CommandResponse {
	if command.ExpiresAt == nil || !command.ExpiresAt.After(time.Now()) {
		return s.discoveryJobRefusal(command, "DNS command expired or missing expiry")
	}
	req, err := sensordispatch.ParseIdentityDNSRequest(command.Payload)
	if err != nil {
		return s.discoveryJobRefusal(command, "invalid bounded DNS request")
	}
	allowed := append([]string{}, s.config.Capture.Interfaces...)
	if len(allowed) == 0 {
		allowed = append(allowed, s.config.Network.Interfaces...)
	}
	resolver := discovery.NewIdentityDNSResolver()
	result := resolver.Resolve(context.Background(), req, discovery.IdentityDNSInterfaces(allowed), Version)
	status := "success"
	message := "Scoped DNS lookup completed"
	if result.ErrorCode != "" {
		status = "error"
		message = result.ErrorCode
	}
	return &models.CommandResponse{ID: uuid.New(), CommandID: command.ID, SensorID: s.config.SensorID, Status: status, Message: message, ResponseData: result.ToMap(), Timestamp: time.Now()}
}

// queueIdentityDNS keeps DNS latency out of heartbeat/capture processing. Both
// waiting work and parallel network activity are bounded, independently of the
// number of commands returned by a control plane.
func (s *Sensor) queueIdentityDNS(command models.Command) *models.CommandResponse {
	if command.ExpiresAt == nil || !command.ExpiresAt.After(time.Now()) {
		return s.discoveryJobRefusal(command, "DNS command expired or missing expiry")
	}
	if _, err := sensordispatch.ParseIdentityDNSRequest(command.Payload); err != nil {
		return s.discoveryJobRefusal(command, "invalid bounded DNS request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identityDNSQueue == nil {
		s.identityDNSQueue = make(chan models.Command, 8)
		s.identityDNSPending = map[string]bool{}
		go s.runIdentityDNS(s.identityDNSQueue)
	}
	if s.identityDNSPending[command.ID] {
		return nil
	}
	select {
	case s.identityDNSQueue <- command:
		s.identityDNSPending[command.ID] = true
		return nil
	default:
		return s.discoveryJobRefusal(command, "sensor busy: scoped DNS queue is full")
	}
}
func (s *Sensor) runIdentityDNS(queue <-chan models.Command) {
	for command := range queue {
		result := s.handleIdentityDNS(command)
		if s.apiClient != nil {
			if err := s.apiClient.AcknowledgeCommand(command.ID, result); err != nil {
				log.Printf("Scoped DNS command acknowledgement failed: %v", err)
			}
		}
		s.mu.Lock()
		delete(s.identityDNSPending, command.ID)
		s.mu.Unlock()
	}
}

func (s *Sensor) reportedDNSInterfaces() []string {
	allowed := append([]string{}, s.config.Capture.Interfaces...)
	if len(allowed) == 0 {
		allowed = append(allowed, s.config.Network.Interfaces...)
	}
	return discovery.IdentityDNSInterfaces(allowed)
}
