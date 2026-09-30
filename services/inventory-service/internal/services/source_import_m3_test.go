package services

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// A refusal carries the WHOLE cap answer, so a caller outside this service
// (the CMDB pull, platform ADR-0002 M3) answers its tenant with the same 402
// body every in-process asset-creating path does. MUTATION: drop any of the
// three fields from the refusal and this goes red.
func TestSourceAdmission_RefusalCarriesTheWholeCapAnswer(t *testing.T) {
	limit := 10
	s := &SourceImportService{assets: admissionAssets{}, limits: admissionLimits{res: &sharedservices.LimitCheckResult{
		Allowed: false, Message: "over the plan", CurrentUsage: 9, Limit: &limit, UpgradePrompt: "upgrade to add more",
	}}}
	adm, err := s.Admission(context.Background(), uuid.New(), 3)
	if err != nil || adm.Allowed {
		t.Fatalf("admission = %+v, %v; want a refusal", adm, err)
	}
	if adm.CurrentUsage != 9 || adm.Limit == nil || *adm.Limit != 10 || adm.UpgradePrompt != "upgrade to add more" {
		t.Errorf("refusal = %+v; want usage 9, limit 10 and the upgrade prompt", adm)
	}
}

// The CI export's field allowlist, spelled out: a field added to the export
// is a decision about what leaves this service, and it must be made here, on
// purpose. MUTATION: add a column to ciExportAssetFields and this goes red.
func TestCIExport_FieldAllowlistIsExactlyTheCanonicalAssetFields(t *testing.T) {
	want := []string{"business_unit", "class_key", "description", "display_name", "environment",
		"hostname", "ip_address", "owner_email", "region", "site", "support_group"}
	got := CIExportAssetFieldNames()
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("exported asset fields = %v\nwant                  %v", got, want)
	}
}
