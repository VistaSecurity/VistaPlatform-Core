package handlers

// Accepting a model's claim into a platform catalogue must reach the audit
// trail, and the record must say WHAT was accepted.
//
// This is the highest-consequence write in the Enricher slice: a date a model
// produced becoming a row every tenant is evaluated against. "A proposal was
// accepted" is not enough — the question asked afterwards is "who put THIS date
// in the catalogue and what did they read before doing it", and only the cited
// source URL settles it.
//
// Each test drives the REAL gin handler and asserts on the body the emitter
// actually POSTed to audit-service, so removing the recordPlatformAudit call
// fails the test rather than merely changing a line nobody checks.

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/catalogs"
)

func TestEOLProposalAudit_AcceptRecordsTheSubjectTheDateAndTheCitation(t *testing.T) {
	got := captureAudit(t)
	accepted := sampleProposal("accepted")
	store := &stubProposalStore{reviewed: &accepted, eolEntryID: "b1b2c3d4-0000-4000-8000-000000000009"}
	eng := proposalEngine(store, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/proposals/"+accepted.ID+"/accept", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	body := awaitAudit(t, got)
	if body["event_type"] != "eol_proposal.accepted" {
		t.Errorf("event_type = %v", body["event_type"])
	}
	if body["action"] != "accept" {
		t.Errorf("action = %v", body["action"])
	}
	if body["resource_type"] != "eol_catalogue_proposal" {
		t.Errorf("resource_type = %v", body["resource_type"])
	}
	meta, _ := body["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("no metadata on %+v", body)
	}
	// The citation is the thing the reviewer was supposed to have read. An
	// audit row without it cannot tell a checked acceptance from a
	// rubber-stamped one.
	if meta["source_url"] != accepted.SourceURL {
		t.Errorf("source_url = %v, want %q", meta["source_url"], accepted.SourceURL)
	}
	if meta["model_id"] != accepted.ModelID {
		t.Errorf("model_id = %v", meta["model_id"])
	}
	if meta["proposed_eol_date"] != "2027-04-30" {
		t.Errorf("proposed_eol_date = %v", meta["proposed_eol_date"])
	}
	if meta["subject_product"] != "IOS-XE" || meta["subject_vendor"] != "Cisco" {
		t.Errorf("subject = %v / %v", meta["subject_vendor"], meta["subject_product"])
	}
	// Which catalogue row it became, so the trail joins up from either end.
	if meta["eol_entry_id"] != store.eolEntryID {
		t.Errorf("eol_entry_id = %v", meta["eol_entry_id"])
	}
}

// A rejection is the record of a model having been wrong, which is what makes
// "how often is this thing right" answerable at all.
func TestEOLProposalAudit_RejectIsRecordedToo(t *testing.T) {
	got := captureAudit(t)
	rejected := sampleProposal("rejected")
	eng := proposalEngine(&stubProposalStore{reviewed: &rejected}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})

	if w := doRequest(eng, http.MethodPost, proposalBase+"/proposals/"+rejected.ID+"/reject", nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := awaitAudit(t, got)
	if body["event_type"] != "eol_proposal.rejected" || body["action"] != "reject" {
		t.Fatalf("recorded %v / %v", body["event_type"], body["action"])
	}
}

// A review that CHANGED NOTHING is not audited. An audit trail padded with
// non-events is one people stop reading.
func TestEOLProposalAudit_ARefusedReviewIsNotAudited(t *testing.T) {
	got := captureAudit(t)
	eng := proposalEngine(&stubProposalStore{reviewErr: catalogs.ErrProposalReviewed},
		&stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})

	if w := doRequest(eng, http.MethodPost, proposalBase+"/proposals/x/accept", nil); w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	expectNoAudit(t, got)
}

func TestEOLProposalAudit_StartingAProposalRunIsRecorded(t *testing.T) {
	got := captureAudit(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{available: true},
		&stubSeamEnricher{}, CatalogEnrichAvailability{Available: true})

	if w := doRequest(eng, http.MethodPost, proposalBase+"/enrich", nil); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	body := awaitAudit(t, got)
	if body["event_type"] != "eol_proposal.enrichment_started" || body["action"] != "enrich" {
		t.Fatalf("recorded %v / %v", body["event_type"], body["action"])
	}
}

// Emitted only on the path that actually STARTED a run.
func TestEOLProposalAudit_ARefusedRunIsNotAudited(t *testing.T) {
	got := captureAudit(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{available: false},
		&stubSeamEnricher{}, CatalogEnrichAvailability{})

	if w := doRequest(eng, http.MethodPost, proposalBase+"/enrich", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	expectNoAudit(t, got)
}

// Reading is not auditable activity, and auditing it would bury the writes.
func TestEOLProposalAudit_ListsAreNotAudited(t *testing.T) {
	got := captureAudit(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	gin.SetMode(gin.TestMode)

	for _, path := range []string{"/proposals", "/misses", "/enrich/availability"} {
		if w := doRequest(eng, http.MethodGet, proposalBase+path, nil); w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, w.Code)
		}
	}
	expectNoAudit(t, got)
}
