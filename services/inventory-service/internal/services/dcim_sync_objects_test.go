package services

// Row 2.6's inventory side of the NetBox sync, without a database: the typed
// kinds are answered by their own writers, and the asset is never created or
// deleted by a sync.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/syncauthority"
)

func TestDCIMSync_RowTwoSixTypedKindsHaveWriters(t *testing.T) {
	s := NewDCIMSyncService(nil, nil)
	ctx := context.Background()
	for _, k := range []dcim.ObjectKind{dcim.ObjectKindRegion, dcim.ObjectKindSiteGroup, dcim.ObjectKindSite, dcim.ObjectKindLocation, dcim.ObjectKindAsset} {
		if _, ok := syncauthority.Kind(k); !ok {
			t.Errorf("%s is not a synced kind", k)
		}
		if _, handled, _ := s.createDCIM(ctx, uuid.New(), "netbox", k, SyncWrite{Op: "create"}); !handled {
			t.Errorf("a %s create falls through to the engine path, which has no spec for it", k)
		}
		if handled, _ := s.updateDCIM(ctx, uuid.New(), "netbox", k, SyncWrite{Op: "update", ID: uuid.New()}); !handled {
			t.Errorf("a %s update falls through to the engine path", k)
		}
		if handled, _ := s.deleteDCIM(ctx, uuid.New(), k, uuid.New()); !handled {
			t.Errorf("a %s delete falls through to the engine path", k)
		}
	}
	// The asset: the import creates it and its drift report handles a removed
	// device; a sync write of either is refused.
	if _, _, err := s.createDCIM(ctx, uuid.New(), "netbox", dcim.ObjectKindAsset, SyncWrite{Op: "create"}); !errors.Is(err, ErrSyncInvalid) {
		t.Errorf("an asset create = %v, want refused", err)
	}
	if _, err := s.deleteDCIM(ctx, uuid.New(), dcim.ObjectKindAsset, uuid.New()); !errors.Is(err, ErrSyncInvalid) {
		t.Errorf("an asset delete = %v, want refused", err)
	}
	// A device type is created only from its library document (the importer).
	if _, handled, err := s.createDCIM(ctx, uuid.New(), "netbox", dcim.ObjectKindDeviceType, SyncWrite{Op: "create", Values: map[string]any{}}); !handled || err == nil {
		t.Errorf("a device type create without a library document: handled=%v err=%v, want refused", handled, err)
	}
	// Every row 2.6 engine kind is served by the sync's engines.
	for k := range dcimEngineKinds {
		if sp, eng := s.engineFor(k); sp == nil || eng == nil {
			t.Errorf("%s has no engine writer", k)
		}
	}
}
