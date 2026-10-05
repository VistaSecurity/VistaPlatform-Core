package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// intakeObservation is what inventory-service's Intake makes of a sighting
// over the sink's database: the observation the engine would resolve. Tests
// that used to inspect this service's hand-built observation inspect this.
func intakeObservation(t *testing.T, sink *ObservationSink, s identity.Sighting) identity.IntakeResult {
	t.Helper()
	in, err := identity.NewIntake(pgidentity.New(sink.db))
	if err != nil {
		t.Fatal(err)
	}
	res, err := in.Assess(context.Background(), s)
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	return res
}

// peerIntakeObservation is intakeObservation of a peer's sighting.
func peerIntakeObservation(t *testing.T, sink *ObservationSink, tenant uuid.UUID, peer di.PeerRef, source identity.Source) identity.Observation {
	t.Helper()
	s, _, err := sink.peerSighting(context.Background(), tenant, peer, source, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return intakeObservation(t, sink, s).Observation
}
