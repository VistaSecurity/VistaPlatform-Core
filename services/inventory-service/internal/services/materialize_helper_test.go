package services

import (
	"context"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// materializeForTest is processDiscoveryCryptoData with the endpoint already
// attached, the way production reaches it: the identity engine (or an
// operator's Link / Confirm, or the interrogated-device claim) writes the
// finding's endpoint, and materialisation only LOOKS IT UP (platform ADR-0003
// D2). A test that hands processDiscoveryCryptoData an asset straight from a
// fixture has made no identity decision, so it makes the attachment here.
func materializeForTest(svc *AssetService, tenant, asset uuid.UUID, f IngestFinding,
	risk *[]*events.AssetRiskChangedPayload, crypto *[]*events.CryptoConfigurationAddedPayload, certs *[]*events.CertificateExpiringPayload) error {
	if err := svc.attachDecidedFindingEndpoint(context.Background(), tenant, asset, f, identity.DecidedByLinkedObservation); err != nil {
		return err
	}
	return svc.processDiscoveryCryptoData(tenant, asset, f, risk, crypto, certs)
}
