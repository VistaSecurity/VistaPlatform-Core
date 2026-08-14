package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// SensorServiceV2 handles sensor operations using the repository pattern
type SensorServiceV2 struct {
	repo database.SensorRepository
}

// NewSensorServiceV2 creates a new sensor service with repository
func NewSensorServiceV2(repo database.SensorRepository) *SensorServiceV2 {
	return &SensorServiceV2{repo: repo}
}

// CreatePendingSensor creates a new pending sensor registration
func (s *SensorServiceV2) CreatePendingSensor(ctx context.Context, tenantID uuid.UUID, req *models.CreatePendingSensorRequest) (*models.PendingSensorRegistration, error) {
	// Generate unique registration key
	keySuffix := make([]byte, 3)
	rand.Read(keySuffix)
	key := fmt.Sprintf("REG-%s-%s-%s",
		tenantID.String()[:8],
		time.Now().Format("20060102"),
		hex.EncodeToString(keySuffix))

	// Create pending sensor
	pending := &models.PendingSensorRegistration{
		ID:                uuid.New(),
		TenantID:          tenantID,
		RegistrationKey:   key,
		Name:              req.Name,
		IPAddress:         req.IPAddress,
		Profile:           req.Profile,
		NetworkInterfaces: req.NetworkInterfaces,
		Tags:              req.Tags,
		Status:            "pending",
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().Add(24 * time.Hour),
	}

	if req.Description != "" {
		pending.Description = &req.Description
	}

	if err := s.repo.CreatePendingSensor(ctx, pending); err != nil {
		return nil, fmt.Errorf("failed to create pending sensor: %w", err)
	}

	return pending, nil
}

// RegisterSensor registers a sensor with a registration key
func (s *SensorServiceV2) RegisterSensor(ctx context.Context, req *models.RegisterSensorRequest) (*models.Sensor, error) {
	// Verify and get pending sensor
	pending, err := s.repo.GetPendingSensorByKey(ctx, req.RegistrationKey)
	if err != nil {
		return nil, fmt.Errorf("invalid registration key: %w", err)
	}

	// Check if key has expired
	if time.Now().After(pending.ExpiresAt) {
		_ = s.repo.UpdatePendingSensorStatus(ctx, req.RegistrationKey, "expired")
		return nil, fmt.Errorf("registration key has expired")
	}

	// Check if key has already been used
	if pending.Status != "pending" {
		return nil, fmt.Errorf("registration key has already been used")
	}

	// Validate IP address matches if configured
	if pending.IPAddress != req.IPAddress {
		return nil, fmt.Errorf("IP address does not match the registered IP address")
	}

	// Create sensor
	sensor := &models.Sensor{
		ID:                uuid.New(),
		TenantID:          pending.TenantID,
		Name:              req.Name,
		Description:       nil,
		Platform:          req.Platform,
		Version:           req.Version,
		Profile:           req.Profile,
		Status:            "pending",
		NetworkInterfaces: req.NetworkInterfaces,
		Tags:              req.Tags,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if req.Description != "" {
		sensor.Description = &req.Description
	}

	if err := s.repo.CreateSensor(ctx, sensor); err != nil {
		return nil, fmt.Errorf("failed to create sensor: %w", err)
	}

	// Mark pending sensor as used
	if err := s.repo.UpdatePendingSensorStatus(ctx, req.RegistrationKey, "used"); err != nil {
		return nil, fmt.Errorf("failed to update pending sensor status: %w", err)
	}

	return sensor, nil
}

// ListSensors returns all sensors for a tenant
func (s *SensorServiceV2) ListSensors(ctx context.Context, tenantID uuid.UUID) ([]*models.Sensor, error) {
	sensors, err := s.repo.ListSensorsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list sensors: %w", err)
	}
	return sensors, nil
}

// GetSensor returns a sensor by ID
// GetSensor returns a sensor only when it belongs to tenantID.
func (s *SensorServiceV2) GetSensor(ctx context.Context, id, tenantID uuid.UUID) (*models.Sensor, error) {
	sensor, err := s.repo.GetSensorByIDForTenant(ctx, id, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor: %w", err)
	}
	return sensor, nil
}

// UpdateSensorStatus updates a sensor's status, scoped to tenantID.
func (s *SensorServiceV2) UpdateSensorStatus(ctx context.Context, id, tenantID uuid.UUID, status string) error {
	if err := s.repo.UpdateSensorStatus(ctx, id, tenantID, status); err != nil {
		return fmt.Errorf("failed to update sensor status: %w", err)
	}
	return nil
}

// ErrPlatformSensorProtected is returned when a delete targets a
// platform-managed sensor row.
var ErrPlatformSensorProtected = errors.New("platform-managed sensors cannot be deleted")

// DeleteSensor soft deletes a sensor, scoped to tenantID.
//
// Platform-managed rows are refused. Deleting one does not stop the shared
// in-cluster service or affect any other tenant — it severs THIS tenant's handle
// to it, after which their interrogation and scheduled-scan results have no
// attribution target and go nowhere, silently, while the service keeps running
// for everyone else. One click, one workspace's discovery pipeline broken.
//
// This is the authoritative guard. The UI also stops offering the action (see
// frontend-v2 sensors-page), but a hidden button is a convenience, not a
// control: the endpoint is reachable directly.
func (s *SensorServiceV2) DeleteSensor(ctx context.Context, id, tenantID uuid.UUID) error {
	sensor, err := s.repo.GetSensorByIDForTenant(ctx, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete sensor: %w", err)
	}
	if sensor.IsPlatformManaged() {
		return ErrPlatformSensorProtected
	}

	if err := s.repo.DeleteSensor(ctx, id, tenantID); err != nil {
		return fmt.Errorf("failed to delete sensor: %w", err)
	}
	return nil
}

// ListPendingSensors returns all pending sensor registrations for a tenant
func (s *SensorServiceV2) ListPendingSensors(ctx context.Context, tenantID uuid.UUID) ([]*models.PendingSensorRegistration, error) {
	pending, err := s.repo.ListPendingSensorsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending sensors: %w", err)
	}
	return pending, nil
}

// DeletePendingSensor deletes a pending sensor registration
// It validates that the pending sensor belongs to the tenant before deletion
func (s *SensorServiceV2) DeletePendingSensor(ctx context.Context, tenantID uuid.UUID, registrationKey string) error {
	// First verify the pending sensor exists and belongs to the tenant
	pending, err := s.repo.GetPendingSensorByKey(ctx, registrationKey)
	if err != nil {
		return fmt.Errorf("pending sensor not found: %w", err)
	}

	// Verify tenant ownership
	if pending.TenantID != tenantID {
		return fmt.Errorf("pending sensor does not belong to tenant")
	}

	// Delete the pending sensor
	if err := s.repo.DeletePendingSensor(ctx, registrationKey); err != nil {
		return fmt.Errorf("failed to delete pending sensor: %w", err)
	}

	return nil
}
