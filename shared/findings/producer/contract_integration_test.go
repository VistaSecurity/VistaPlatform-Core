package producer_test

// The writer's own run of the contract suite.
//
// Every producer runs [producertest.Run] with its own key and kinds; this runs
// it for two of them, chosen to cover the two shapes the writer treats
// differently:
//
//   - eol: a LADDER kind whose feeds_risk is true, so the registry-rung
//     validation and a non-zero score are both exercised;
//   - hygiene: FIXED kinds whose feeds_risk is false, so the "a kind that feeds
//     no risk writes 0" rule is exercised against real rows.
//
// Running it here as well as in each producer's package is deliberate. A change
// to the writer breaks THIS immediately, in the module that owns it, rather
// than in whichever service's suite happens to run first.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer/producertest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Writer_ContractOnALadderProducer(t *testing.T) {
	owner := testdb.Connect(t)
	// No testdb.ApplySchema here: the runner applies scripts/database/schema.sql
	// once to the database, and re-applying it per fixture takes ACCESS
	// EXCLUSIVE locks across the whole schema while other package binaries of
	// the same `go test ./...` run are querying it. That is the documented
	// deadlock source and it made this package fail
	// intermittently with "could not complete operation in a failed
	// transaction". ApplySchema is for the re-apply/idempotency tests, which
	// these are not.
	app := testdb.ConnectAsAppRole(t, owner)

	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerEOL,
		Kind:        findings.KindOSEndOfLife,
		OtherKind:   findings.KindHardwareEndOfSupport,
		SubjectType: findings.SubjectAsset,
	})
}

func TestIntegration_Writer_ContractOnAFixedNonRiskProducer(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)

	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerHygiene,
		Kind:        findings.KindStale, // hygiene's one ladder kind
		OtherKind:   findings.KindNoOwner,
		SubjectType: findings.SubjectAsset,
	})
}
