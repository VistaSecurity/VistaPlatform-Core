package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// A missing DB makes this assert validation ordering, independently of CHECKs.
func TestControlWritersRejectInvalidBeforeDatabase(t *testing.T) {
	svc := &PlatformFrameworkService{}
	for _, value := range []string{"Med", "High", "info", "invalid", ""} {
		input := &models.PlatformFrameworkControlInput{ControlID: "C1", Title: "Control", BaselineSeverity: value}
		if _, err := svc.CreateControl(uuid.New(), input); err == nil {
			t.Fatalf("CreateControl accepted %q", value)
		}
		if _, err := svc.UpdateControl(uuid.New(), input); err == nil {
			t.Fatalf("UpdateControl accepted %q", value)
		}
	}
}
