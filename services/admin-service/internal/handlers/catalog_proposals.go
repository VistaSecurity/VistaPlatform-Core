package handlers

// Catalog ▸ End-of-life ▸ Proposals and Gaps (ADR-0008 D3, workstream 4.5b).
//
// The review queue for AI-proposed end-of-life catalogue rows, and the gap list
// the proposals are generated from. Every route is gated on catalogs.manage and
// mounted under /admin, exactly like the catalogue browse routes beside them.
//
// The shape rules are the ones catalogs.go states: lists wrapped under their
// resource key with total/page/page_size, arrays always present and never null,
// errors as the legacy single-string {"error": "..."}.
//
// # Why accept is the only way into the catalogue
//
// ADR-0008 D3: AI output is a proposal and proposals go through approval. There
// is no route here that writes `eol_catalogue` except accept, and accept writes
// it with `source_kind = 'inferred'` and records who accepted it. A client that
// wanted to skip the review UI would still have to make one accept call per
// proposal, with a platform admin's cookie, and each one lands in the audit
// trail. That is the same property the author seam has: the review step cannot
// be routed around, only performed quickly.

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// CatalogProposalStore is the review surface the handlers need. Narrower than
// catalogs.Store on purpose: an HTTP handler has no business recording a
// catalogue miss or stamping a gap as proposed-about.
type CatalogProposalStore interface {
	ListProposals(ctx context.Context, q catalogs.ProposalQuery) ([]catalogs.Proposal, int64, error)
	AcceptProposal(ctx context.Context, id string, r catalogs.Reviewer) (*catalogs.Proposal, string, error)
	RejectProposal(ctx context.Context, id string, r catalogs.Reviewer) (*catalogs.Proposal, error)
	ListMisses(ctx context.Context, q catalogs.MissQuery) ([]catalogs.Miss, int64, error)
}

// CatalogLookup is the Enricher seam as this console needs it: the facts, plus
// whether a catalogue row matched at all and whether the gap was counted.
//
// Narrower than [seams.Enricher] in nothing and wider in two booleans, because
// the seam's signature is `[]Fact` and a console has to tell an empty answer's
// causes apart. Implemented by *catalogs.LookupEnricher — the same split that
// package already makes between the seam and catalogs.Proposer.
type CatalogLookup interface {
	Lookup(ctx context.Context, subject seams.EnrichmentSubject) (catalogs.LookupResult, error)
}

// CatalogEnrichRunner is the control surface the "Propose with AI" button
// drives. Implemented by *catalogs.GapRunner.
//
// RunDetached takes NO context, deliberately. A pass outlives the request that
// triggered it by minutes and must descend from the runner's own lifetime so a
// shutdown can end it — handing it the gin context would kill it the instant
// the handler answered 202, and handing it a Background would make shutdown
// wait out the whole batch. Owning that choice inside the runner is what stops
// a caller getting it wrong.
//
// It does take the INVOKER, because D4.7 asks which user or rule made every
// generative call and the answer here is the admin who clicked. It cannot ride
// on a context for the reason above, so it is a parameter.
type CatalogEnrichRunner interface {
	Available() bool
	RunDetached(invoker string) error
}

// --- the lookup ------------------------------------------------------------

// eolLookupRequest is what Catalog ▸ End-of-life ▸ "Check a product" sends.
type eolLookupRequest struct {
	ProductKind string `json:"product_kind"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Version     string `json:"version"`
}

// eolFactResponse is one fact the enricher resolved, with its provenance
// carried through verbatim.
//
// Every field of ADR-0008 D4.1's provenance is on the wire — source_kind,
// source_ref, confidence, model_id — plus the citation. That is not
// decoration: the whole claim this feature makes is that an answer says where
// it came from, and a response that dropped source_ref would leave the console
// showing a date with no way back to the row that stated it.
type eolFactResponse struct {
	Key        string  `json:"key"`
	Value      any     `json:"value"`
	SourceURL  string  `json:"source_url"`
	SourceKind string  `json:"source_kind"`
	SourceRef  string  `json:"source_ref"`
	Confidence float64 `json:"confidence"`
	ModelID    string  `json:"model_id,omitempty"`
}

// eolLookupResponse is the answer, and it answers three questions rather than
// one.
//
// `matched` is NOT `len(facts) > 0`. A catalogue row whose `eol_date` is NULL,
// or which carries no source_url, matches and yields no fact — so "the
// catalogue has never heard of this product" and "the catalogue has it and
// publishes no date" are different answers with different fixes, and only the
// first is a gap. `miss_recorded` is separate again, because the message tells
// an operator their product went on the gap list and saying so when the write
// failed is a claim about something that did not happen.
type eolLookupResponse struct {
	Facts        []eolFactResponse `json:"facts"`
	Matched      bool              `json:"matched"`
	MissRecorded bool              `json:"miss_recorded"`
	Message      string            `json:"message"`
}

// LookupEOL serves POST /admin/catalogs/eol/lookup.
//
// It is the ADR-0008 Enricher seam with a person on the other end: an operator
// asks what the platform can say about a vendor/product/version, and gets back
// the facts with their provenance — or nothing, and a gap-list entry.
//
// It exists for two reasons beyond being useful. It is what makes the seam
// REACHABLE today: the volume caller is the `eol` producer, which matches tenant
// OS and software facts against the catalogue and belongs to workstream 3.4
// part 2 (it depends on the phase-1 asset rewrite). Without this, the seam, the
// gap list and the proposal queue would all ship with no way for anyone to
// exercise them. And it is how an operator fills the gap list deliberately —
// "we are about to onboard a customer running Cisco IOS-XE; does the catalogue
// know about it?" — which is the question that makes a proposal run worth
// starting.
func LookupEOL(enricher CatalogLookup) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req eolLookupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Send a JSON body naming at least a product"})
			return
		}
		// Normalize, not TrimSpace: the lookup normalises before it searches,
		// so a product of "___" is empty to it and would resolve nothing,
		// record nothing, and come back as an unexplained miss. Refusing it
		// here is what keeps the three answers below exhaustive.
		if catalogs.Normalize(req.Product) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "product is required"})
			return
		}
		if req.ProductKind != "" && !catalogs.ValidKind(req.ProductKind) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "product_kind must be one of os, software, hardware"})
			return
		}

		resolved, err := enricher.Lookup(c.Request.Context(), seams.EnrichmentSubject{
			Class:   req.ProductKind,
			Vendor:  req.Vendor,
			Model:   req.Product,
			Version: req.Version,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look the product up"})
			return
		}

		out := eolLookupResponse{
			Facts:        []eolFactResponse{},
			Matched:      resolved.Matched,
			MissRecorded: resolved.MissRecorded,
		}
		for _, f := range resolved.Facts {
			p := f.Provenance()
			out.Facts = append(out.Facts, eolFactResponse{
				Key:        f.Key,
				Value:      f.Value,
				SourceURL:  f.SourceURL,
				SourceKind: p.SourceKind,
				SourceRef:  p.SourceRef,
				Confidence: p.Confidence,
				ModelID:    p.ModelID,
			})
		}
		// Four outcomes, four sentences. The one that used to be missing is the
		// second: a matched row publishing no date was reported as "nothing for
		// this product, it has been added to the gap list" — which named the
		// wrong problem AND asserted a write that had not happened.
		switch {
		case len(out.Facts) > 0:
			out.Message = "Resolved from the platform catalogues."
		case out.Matched:
			out.Message = "The catalogue has this product but publishes no end-of-life date for it, so there is nothing to state. This is not a gap the catalogue can fill — the upstream source has not announced one."
		case out.MissRecorded:
			out.Message = "The catalogues have nothing for this product. It has been added to the gap list."
		default:
			out.Message = "The catalogues have nothing for this product, and the gap list could not be updated — check the admin-service log."
		}
		c.JSON(http.StatusOK, out)
	}
}

// --- responses --------------------------------------------------------------

type eolProposalListResponse struct {
	Proposals []catalogs.Proposal `json:"proposals"`
	Total     int64               `json:"total"`
	Page      int                 `json:"page"`
	PageSize  int                 `json:"page_size"`
}

type catalogMissListResponse struct {
	Misses   []catalogs.Miss `json:"misses"`
	Total    int64           `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

// eolProposalReviewResponse carries the reviewed proposal back so the console
// renders the row it just changed rather than the row it hoped for. On accept
// it also names the catalogue row that was written, which is what makes the
// "where did this row come from" question answerable from either end.
type eolProposalReviewResponse struct {
	Proposal   catalogs.Proposal `json:"proposal"`
	EOLEntryID string            `json:"eol_entry_id,omitempty"`
	Message    string            `json:"message"`
}

type catalogEnrichRunResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// CatalogEnrichAvailability is the answer to "is 'Propose with AI' offered
// here", served in EVERY edition.
//
// Core answers {"available":false,"reason":"edition"}. Letting the console infer
// the capability from a 404 could not tell a Core build from a broken route and
// would put a 404 in every Core operator's console on every visit to the page —
// the reasoning wrote down for the author seam, applied to this one.
type CatalogEnrichAvailability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Provider  string `json:"provider,omitempty"`
}

// EnrichReasonEdition is the honest Core answer: this build has no generative
// enricher. The catalogue lookup, the gap list and the review queue are all
// present; only the thing that FILLS the queue is Enterprise.
const EnrichReasonEdition = "edition"

// --- handlers ---------------------------------------------------------------

// ListEOLProposals serves GET /admin/catalogs/eol/proposals.
func ListEOLProposals(store CatalogProposalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		status := c.Query("status")
		if status != "" && !catalogs.ValidStatus(status) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of pending, accepted, rejected"})
			return
		}
		page, pageSize := pageParams(c)
		proposals, total, err := store.ListProposals(c.Request.Context(), catalogs.ProposalQuery{
			Status: status, Page: page, PageSize: pageSize,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the proposal queue"})
			return
		}
		if proposals == nil {
			proposals = []catalogs.Proposal{}
		}
		normPage, normSize := catalogs.NormalizePage(page, pageSize)
		c.JSON(http.StatusOK, eolProposalListResponse{
			Proposals: proposals, Total: total, Page: normPage, PageSize: normSize,
		})
	}
}

// AcceptEOLProposal serves POST /admin/catalogs/eol/proposals/{id}/accept.
//
// This is the write that matters in this whole slice: a model's claim becoming
// a row in the data every tenant is evaluated against. It is audited with the
// proposal id, the subject, the dates and the source URL — not merely "a
// proposal was accepted" — because the question asked afterwards is "who put
// THIS date in the catalogue and what did they read before doing it", and only
// the cited URL settles it.
func AcceptEOLProposal(store CatalogProposalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		proposal, eolID, err := store.AcceptProposal(c.Request.Context(), id, reviewerFrom(c))
		if err != nil {
			writeProposalError(c, err, "Failed to accept the proposal")
			return
		}
		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "eol_proposal.accepted",
			Action:        "accept",
			EventCategory: "system",
			ResourceType:  "eol_catalogue_proposal",
			ResourceID:    proposal.ID,
			Metadata:      proposalAuditMetadata(proposal, map[string]interface{}{"eol_entry_id": eolID}),
		})
		c.JSON(http.StatusOK, eolProposalReviewResponse{
			Proposal:   *proposal,
			EOLEntryID: eolID,
			Message:    "Accepted. The catalogue row is stored with source_kind 'inferred' and your name on it.",
		})
	}
}

// RejectEOLProposal serves POST /admin/catalogs/eol/proposals/{id}/reject.
//
// Audited as heavily as accept, which is not symmetry for its own sake: a
// rejection is the record of a model having been wrong, and a queue where
// rejections vanished would make the question "how often is this thing right"
// unanswerable — which is the question that decides whether the capability is
// worth running at all.
func RejectEOLProposal(store CatalogProposalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		proposal, err := store.RejectProposal(c.Request.Context(), id, reviewerFrom(c))
		if err != nil {
			writeProposalError(c, err, "Failed to reject the proposal")
			return
		}
		recordPlatformAudit(c, PlatformAuditEntry{
			EventType:     "eol_proposal.rejected",
			Action:        "reject",
			EventCategory: "system",
			ResourceType:  "eol_catalogue_proposal",
			ResourceID:    proposal.ID,
			Metadata:      proposalAuditMetadata(proposal, nil),
		})
		c.JSON(http.StatusOK, eolProposalReviewResponse{
			Proposal: *proposal,
			Message:  "Rejected. Nothing was written to the catalogue.",
		})
	}
}

// ListCatalogMisses serves GET /admin/catalogs/eol/misses — the gap list.
func ListCatalogMisses(store CatalogProposalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, pageSize := pageParams(c)
		misses, total, err := store.ListMisses(c.Request.Context(), catalogs.MissQuery{
			Page: page, PageSize: pageSize,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the catalogue gap list"})
			return
		}
		if misses == nil {
			misses = []catalogs.Miss{}
		}
		normPage, normSize := catalogs.NormalizePage(page, pageSize)
		c.JSON(http.StatusOK, catalogMissListResponse{
			Misses: misses, Total: total, Page: normPage, PageSize: normSize,
		})
	}
}

// RunCatalogEnrichment serves POST /admin/catalogs/eol/enrich.
//
// 202, not 200, and for the same reason the feed sync is: the pass is STARTED,
// not finished. It makes one provider call per gap and a batch of them takes
// minutes, so blocking would time out at the gateway and leave the operator
// unable to tell whether anything happened. The outcome lands in the proposal
// queue, which is what the console reloads.
func RunCatalogEnrichment(runner CatalogEnrichRunner) gin.HandlerFunc {
	return func(c *gin.Context) {
		if runner == nil || !runner.Available() {
			// 503 rather than 404: the route exists in every edition and the
			// capability does not. A 404 here would be indistinguishable from
			// a broken route, which is the ambiguity the availability endpoint
			// exists to remove.
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "AI end-of-life proposals are not available on this deployment"})
			return
		}
		// The acting admin, not the schedule. A run a person asked for that is
		// audited as "catalog-gap-pass" answers D4.7's question with the wrong
		// name, and the audit trail is the only place the answer survives.
		switch err := runner.RunDetached(c.GetString("userID")); {
		case err == nil:
			// Emitted only on the path that actually STARTED a pass. A 409
			// changed nothing, and an audit trail padded with non-events is one
			// people stop reading.
			recordPlatformAudit(c, PlatformAuditEntry{
				EventType:     "eol_proposal.enrichment_started",
				Action:        "enrich",
				EventCategory: "system",
				ResourceType:  "eol_catalogue_proposal",
			})
			c.JSON(http.StatusAccepted, catalogEnrichRunResponse{
				Status:  "running",
				Message: "Proposal run started. Reload the Proposals tab to see what it found.",
			})
		case errors.Is(err, catalogs.ErrEnrichBusy):
			c.JSON(http.StatusConflict, gin.H{"error": "A proposal run is already in flight"})
		case errors.Is(err, catalogs.ErrNoProposer):
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "AI end-of-life proposals are not available on this deployment"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start the proposal run"})
		}
	}
}

// GetCatalogEnrichAvailability serves GET /admin/catalogs/eol/enrich/availability.
//
// Fixed at mount time rather than computed per request: the answer depends on
// which binary is running and on the process's AI_PROVIDER configuration,
// neither of which changes between requests.
func GetCatalogEnrichAvailability(av CatalogEnrichAvailability) gin.HandlerFunc {
	if !av.Available && av.Reason == "" {
		// The zero value is the honest Core answer, so a caller that wires
		// nothing reports unavailable rather than available by omission.
		av.Reason = EnrichReasonEdition
	}
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, av)
	}
}

// --- helpers ----------------------------------------------------------------

// reviewerFrom reads the acting platform admin off the gin context. AuthMiddleware
// + StringifyUserID put the id under "userID" and the email under "email", the
// same place the audit emitter reads them from.
func reviewerFrom(c *gin.Context) catalogs.Reviewer {
	return catalogs.Reviewer{ID: c.GetString("userID"), Email: c.GetString("email")}
}

// writeProposalError maps the store's named errors onto statuses that mean
// different things to a person.
func writeProposalError(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, catalogs.ErrProposalNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "No such proposal"})
	case errors.Is(err, catalogs.ErrProposalReviewed):
		// 409, not 404 and not 200. The row exists; someone else has already
		// decided. Answering 200 would tell two reviewers they each made the
		// decision, and answering 404 would send this one looking for a bad id.
		c.JSON(http.StatusConflict, gin.H{"error": "That proposal has already been reviewed"})
	case errors.Is(err, catalogs.ErrProposalUncitable):
		// Also 409 and also a state refusal: the row exists and cannot be
		// accepted as it stands. 500 would read as "our fault, try again",
		// which would send an operator looking in the wrong place for a
		// proposal that will never be acceptable.
		c.JSON(http.StatusConflict, gin.H{
			"error": "That proposal's cited source is not a checkable public page, so it cannot be accepted"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": fallback})
	}
}

// proposalAuditMetadata records WHAT was decided, not just that a decision
// happened. The source URL in particular: it is the thing the reviewer was
// supposed to have read, and an audit row without it cannot distinguish a
// checked acceptance from a rubber-stamped one.
func proposalAuditMetadata(p *catalogs.Proposal, extra map[string]interface{}) map[string]interface{} {
	meta := map[string]interface{}{
		"product_kind":    p.ProductKind,
		"subject_product": p.Product,
		"proposed_cycle":  p.Cycle,
		"source_url":      p.SourceURL,
		"model_id":        p.ModelID,
		"source_kind":     p.SourceKind,
	}
	if p.Vendor != nil {
		meta["subject_vendor"] = *p.Vendor
	}
	if p.Version != nil {
		meta["subject_version"] = *p.Version
	}
	if p.EOLDate != nil {
		meta["proposed_eol_date"] = p.EOLDate.UTC().Format("2006-01-02")
	}
	for k, v := range extra {
		meta[k] = v
	}
	return meta
}
