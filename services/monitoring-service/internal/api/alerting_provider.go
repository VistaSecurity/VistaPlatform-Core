package api

// Seam for the platform alerting handlers (ADR-0001 contract slice).
//
// The alerting handlers depend on *services.AlertingService. This file narrows
// that to the methods the handlers actually call so the real gin handlers can be
// exercised against an in-memory stub — no database — in the spec-first contract
// test. The concrete *services.AlertingService satisfies it unchanged; production
// wiring (NewServer) is unchanged.

import (
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
)

// alertingProvider is the narrow surface of *services.AlertingService the
// alerting handlers (alerting_handlers.go) use.
type alertingProvider interface {
	GetAlertThresholds(serviceName *string, enabled *bool) ([]models.AlertThreshold, error)
	GetAlertThreshold(id uuid.UUID) (*models.AlertThreshold, error)
	CreateAlertThreshold(req *models.CreateAlertThresholdRequest, createdBy *uuid.UUID) (*models.AlertThreshold, error)
	UpdateAlertThreshold(id uuid.UUID, req *models.UpdateAlertThresholdRequest, updatedBy *uuid.UUID) (*models.AlertThreshold, error)
	DeleteAlertThreshold(id uuid.UUID) error
	GetAlertHistory(serviceName *string, status *string, limit int, offset int) ([]models.AlertHistory, int, error)
}
