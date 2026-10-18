package services

import (
	"context"
	"database/sql"
	"log"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim/orphans"
)

// OrphanSweeper is the per-tenant pass of shared/dcim/orphans: tags, journal
// entries, contact assignments, images and the like that point at an object
// which has since been deleted. A delete path that forgets to clean up after
// itself, or a cascade no service sees, leaves them behind (a polymorphic
// reference has no foreign key to do it).
type OrphanSweeper struct {
	db    *sql.DB
	blobs ImageBlobStore
}

// NewOrphanSweeper returns a sweeper; blobs may be nil, in which case the bytes
// of a swept image are left in storage (and logged).
func NewOrphanSweeper(db *sql.DB, blobs ImageBlobStore) *OrphanSweeper {
	return &OrphanSweeper{db: db, blobs: blobs}
}

// SweepTenant removes the tenant's orphans in one transaction, then removes the
// bytes of any image row it dropped. A blob that cannot be removed is logged:
// the row is already gone, so a retry would not find it.
func (s *OrphanSweeper) SweepTenant(ctx context.Context, tenant uuid.UUID) (orphans.Report, error) {
	var rep orphans.Report
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		rep, err = orphans.Sweep(ctx, tx, tenant, false)
		return err
	})
	if err != nil {
		return rep, err
	}
	for _, ref := range rep.ImageRefs {
		if s.blobs == nil {
			log.Printf("[OrphanSweep] tenant %s: image bytes %q left in storage (no blob store)", tenant, ref)
			continue
		}
		if err := s.blobs.Delete(ctx, tenant, ref); err != nil {
			log.Printf("[OrphanSweep] tenant %s: image row removed but its bytes %q could not be: %v", tenant, ref, err)
		}
	}
	return rep, nil
}
