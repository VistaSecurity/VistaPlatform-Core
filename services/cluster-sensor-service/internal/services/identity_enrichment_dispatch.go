package services

import (
	"database/sql"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

var errIdentityEnrichmentPaused = dispatchguard.ErrPaused

type enrichmentQueryer interface{ QueryRow(string, ...any) *sql.Row }

func authorizeEnrichmentDispatch(tx enrichmentQueryer, payload sensordispatch.Payload, sensor uuid.UUID) error {
	return dispatchguard.AuthorizeProbe(tx, payload, sensor)
}
