package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

type admissionAssets struct {
	prospective bool
	policyErr   error
}

func (a admissionAssets) UsesIdentityAdmission(context.Context, uuid.UUID) (bool, error) {
	return a.prospective, a.policyErr
}

func (admissionAssets) DeclareFor(context.Context, uuid.UUID, uuid.UUID, identity.Sighting) (identity.Resolution, error) {
	return identity.Resolution{}, nil
}

func (admissionAssets) CreateAssetFromSource(uuid.UUID, models.AssetInput, identity.Source) (*models.Asset, identity.Outcome, error) {
	panic("admission must not create anything")
}

type admissionLimits struct {
	res *sharedservices.LimitCheckResult
	err error
}

func (l admissionLimits) CheckAssetLimit(uuid.UUID, int) (*sharedservices.LimitCheckResult, error) {
	return l.res, l.err
}

// A check that cannot be answered is a failed check, typed by its stage, and
// never an allowance. MUTATION: return Allowed:true on a limit lookup error (or
// on a policy error) and this goes red.
func TestSourceAdmission_UnanswerableChecksAreErrors(t *testing.T) {
	tenant := uuid.New()
	ctx := context.Background()

	s := &SourceImportService{assets: admissionAssets{}, limits: admissionLimits{err: errors.New("resolver down")}}
	if adm, err := s.Admission(ctx, tenant, 3); !errors.Is(err, ErrAssetLimit) || adm.Allowed {
		t.Errorf("limit lookup failure: %+v, %v; want ErrAssetLimit and not allowed", adm, err)
	}

	s = &SourceImportService{assets: admissionAssets{policyErr: errors.New("engine down")}, limits: admissionLimits{}}
	if adm, err := s.Admission(ctx, tenant, 3); !errors.Is(err, ErrAdmissionPolicy) || adm.Allowed {
		t.Errorf("policy failure: %+v, %v; want ErrAdmissionPolicy and not allowed", adm, err)
	}

	s = &SourceImportService{assets: admissionAssets{}, limits: admissionLimits{res: &sharedservices.LimitCheckResult{Allowed: false, Message: "cap"}}}
	if adm, err := s.Admission(ctx, tenant, 3); err != nil || adm.Allowed || adm.Message != "cap" {
		t.Errorf("over the cap: %+v, %v; want refused with the cap's message", adm, err)
	}

	// Prospective admission checks each create in the engine; no advance cap.
	s = &SourceImportService{assets: admissionAssets{prospective: true}, limits: admissionLimits{err: errors.New("must not be asked")}}
	if adm, err := s.Admission(ctx, tenant, 3); err != nil || !adm.Prospective || !adm.Allowed {
		t.Errorf("prospective: %+v, %v", adm, err)
	}
}
