package handlers

// Catalog ▸ Classification rules (asset-inventory ADR-0004 D6, workstream
// 2.10a).
//
// The platform-admin surface over public.classification_rules: the evidence
// behind every class proposal. D6's whole argument is that these are DATA an
// admin curates rather than code — so that the fingerprint catalogue grows
// without a release, and so the learned classifier of workstream 4.2 has
// features to train on. This file is where the curation happens; without it the
// table is just a seed nobody can extend, which is the "backend with no UI"
// failure the Feature Implementation Framework exists to prevent.
//
// Every route is gated on catalogs.manage and mounted under /admin, a declared
// admin-plane prefix — the tenant host serves none of it. Tenant-authored rules
// are NOT here: a tenant rule needs a scope column, a precedence rule against
// the platform set and its own approval story, and shipping a column nothing
// reads is how this repo accumulated half-built features.
//
// Shape follows the EOL/vulnerability catalogue handlers beside it: the list is
// wrapped under its resource key with total/page/page_size, the array is ALWAYS
// present (empty, never null), and errors are the legacy single-string
// {"error": "..."} this service uses everywhere.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/classificationrules"
)

// ClassificationRuleStore is the CRUD surface the handlers need. Narrower than
// classificationrules.Store: an HTTP handler has no business loading an engine.
type ClassificationRuleStore interface {
	List(ctx context.Context, q classificationrules.Query) ([]classificationrules.Rule, int64, error)
	Get(ctx context.Context, id string) (classificationrules.Rule, error)
	Create(ctx context.Context, in classificationrules.Input) (classificationrules.Rule, error)
	Update(ctx context.Context, id string, in classificationrules.Input) (classificationrules.Rule, error)
	Delete(ctx context.Context, id string) error
	AcceptUpdate(ctx context.Context, id string) (after, before classificationrules.Rule, err error)
}

type classificationRuleListResponse struct {
	Rules    []classificationrules.Rule `json:"rules"`
	Total    int64                      `json:"total"`
	Page     int                        `json:"page"`
	PageSize int                        `json:"page_size"`
	// Kinds is the rule-kind vocabulary, served with the list so the console's
	// filter and its form cannot drift from the engine's switch. A hard-coded
	// copy in the UI is how a ninth kind ships invisible.
	Kinds []string `json:"kinds"`
}

// ListClassificationRules serves GET /admin/catalogs/classification-rules.
func ListClassificationRules(store ClassificationRuleStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		kind := c.Query("kind")
		if kind != "" && !classificationrules.ValidKind(kind) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "kind must be one of " + strings.Join(classificationrules.Kinds(), ", "),
			})
			return
		}
		page, pageSize := pageParams(c)
		rules, total, err := store.List(c.Request.Context(), classificationrules.Query{
			Search: c.Query("search"), Kind: kind, Page: page, PageSize: pageSize,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the classification rules"})
			return
		}
		if rules == nil {
			rules = []classificationrules.Rule{}
		}
		normPage, normSize := classificationRulePageEcho(page, pageSize)
		c.JSON(http.StatusOK, classificationRuleListResponse{
			Rules: rules, Total: total, Page: normPage, PageSize: normSize,
			Kinds: classificationrules.Kinds(),
		})
	}
}

// GetClassificationRule serves GET /admin/catalogs/classification-rules/:id.
func GetClassificationRule(store ClassificationRuleStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		rule, err := store.Get(c.Request.Context(), c.Param("id"))
		if errors.Is(err, classificationrules.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Classification rule not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the classification rule"})
			return
		}
		c.JSON(http.StatusOK, rule)
	}
}

// CreateClassificationRule serves POST /admin/catalogs/classification-rules.
func CreateClassificationRule(store ClassificationRuleStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		in, ok := bindClassificationRule(c)
		if !ok {
			return
		}
		rule, err := store.Create(c.Request.Context(), in)
		switch {
		case errors.Is(err, classificationrules.ErrDuplicate):
			// 409 and not 500: the admin's next move is to edit the rule that
			// already claims this pattern, and the response says so.
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create the classification rule"})
		default:
			auditClassificationRule(c, "created", "create", rule)
			c.JSON(http.StatusCreated, rule)
		}
	}
}

// UpdateClassificationRule serves PUT /admin/catalogs/classification-rules/:id.
func UpdateClassificationRule(store ClassificationRuleStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		in, ok := bindClassificationRule(c)
		if !ok {
			return
		}
		rule, err := store.Update(c.Request.Context(), c.Param("id"), in)
		switch {
		case errors.Is(err, classificationrules.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "Classification rule not found"})
		case errors.Is(err, classificationrules.ErrDuplicate):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update the classification rule"})
		default:
			auditClassificationRule(c, "updated", "update", rule)
			c.JSON(http.StatusOK, rule)
		}
	}
}

// DeleteClassificationRule serves DELETE
// /admin/catalogs/classification-rules/:id.
func DeleteClassificationRule(store ClassificationRuleStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		// Read before deleting, so the audit record can say WHICH rule went —
		// "deleted 7f3a…" is unreviewable a month later, and the row is gone by
		// the time anyone asks. A failed read does not block the delete: the
		// audit entry falls back to the id alone rather than the operator
		// losing the action.
		existing, _ := store.Get(c.Request.Context(), id)

		err := store.Delete(c.Request.Context(), id)
		switch {
		case errors.Is(err, classificationrules.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "Classification rule not found"})
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete the classification rule"})
		default:
			existing.ID = id
			auditClassificationRule(c, "deleted", "delete", existing)
			c.JSON(http.StatusOK, gin.H{"message": "Classification rule deleted"})
		}
	}
}

// AcceptClassificationRuleUpdate serves POST
// /admin/catalogs/classification-rules/:id/accept-update.
//
// Upgrades keep a platform admin's edits to the rules Vista ships (decision 4,
// RC-12): a new shipped value for an edited rule is stored as an offer rather
// than written. This applies the offer. 409 when there is none — the console
// only offers the action on a rule showing "update available".
func AcceptClassificationRuleUpdate(store ClassificationRuleStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// A malformed id is the caller's error, not a 500 from Postgres (22P02).
		if _, err := uuid.Parse(c.Param("id")); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid classification rule id"})
			return
		}
		after, before, err := store.AcceptUpdate(c.Request.Context(), c.Param("id"))
		switch {
		case errors.Is(err, classificationrules.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "Classification rule not found"})
		case errors.Is(err, classificationrules.ErrNoUpdate):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept the update"})
		default:
			auditClassificationRuleUpdateAccepted(c, before, after)
			c.JSON(http.StatusOK, after)
		}
	}
}

// auditClassificationRuleUpdateAccepted records an accepted shipped update
// with the offered columns' values before and after — the rule changed, and
// "to what, from what" is the question the trail exists to answer.
func auditClassificationRuleUpdateAccepted(c *gin.Context, before, after classificationrules.Rule) {
	fields := make([]string, 0, len(before.OfferedUpdate))
	for k := range before.OfferedUpdate {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	recordPlatformAudit(c, PlatformAuditEntry{
		EventType:     "classification_rule.update_accepted",
		Action:        "update",
		EventCategory: "system",
		ResourceType:  "classification_rule",
		ResourceID:    after.ID,
		ChangedFields: fields,
		NewValues:     before.OfferedUpdate,
		Metadata: map[string]interface{}{
			"rule_kind": after.RuleKind,
			"pattern":   after.Pattern,
			"previous": map[string]interface{}{
				"class_key":  before.ClassKey,
				"vendor":     before.Vendor,
				"model":      before.Model,
				"confidence": before.Confidence,
				"source_url": before.SourceURL,
			},
		},
	})
}

// auditClassificationRule records a curation change.
//
// Recorded like every other platform-catalogue mutation, and for the same
// reason the feed-sync route is: these rows decide what class is PROPOSED for
// every tenant's assets, so "who changed this, and to what" has to be
// answerable. The metadata carries the whole rule rather than just its id,
// because the row itself is what changed and, on a delete, no longer exists to
// go and look at.
//
// Emitted only on the paths that actually changed something. A 404, a 409 or a
// rejected body changed nothing, and an audit trail padded with non-events is
// one people stop reading.
func auditClassificationRule(c *gin.Context, event, action string, rule classificationrules.Rule) {
	recordPlatformAudit(c, PlatformAuditEntry{
		EventType:     "classification_rule." + event,
		Action:        action,
		EventCategory: "system",
		ResourceType:  "classification_rule",
		ResourceID:    rule.ID,
		Metadata: map[string]interface{}{
			"rule_kind":  rule.RuleKind,
			"pattern":    rule.Pattern,
			"class_key":  rule.ClassKey,
			"vendor":     rule.Vendor,
			"model":      rule.Model,
			"confidence": rule.Confidence,
		},
	})
}

// bindClassificationRule parses and validates a create/update body, answering
// 400 with the validator's own message when it does not pass.
//
// The message is the engine's, verbatim: "oui rule pattern "00:80:77" must be 6
// uppercase hex digits with no separators" tells an admin what to type next,
// where "invalid rule" tells them to guess.
func bindClassificationRule(c *gin.Context) (classificationrules.Input, bool) {
	var in classificationrules.Input
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return classificationrules.Input{}, false
	}
	in.RuleKind = strings.TrimSpace(in.RuleKind)
	in.Pattern = strings.TrimSpace(in.Pattern)
	in.ClassKey = trimmedOrNil(in.ClassKey)
	in.Vendor = trimmedOrNil(in.Vendor)
	in.Model = trimmedOrNil(in.Model)
	in.SourceURL = trimmedOrNil(in.SourceURL)

	if err := classificationrules.Validate(in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return classificationrules.Input{}, false
	}
	return in, true
}

// trimmedOrNil folds an empty-after-trim string to NULL. A form that posts ""
// for an untouched optional field must not write an empty string into a column
// whose NULL means "this rule deliberately asserts nothing here" — that
// distinction is the point of the class column being nullable.
func trimmedOrNil(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return nil
	}
	return &v
}

// classificationRulePageEcho mirrors the store's clamping so the response
// reports the page that was actually served, not the one that was asked for.
func classificationRulePageEcho(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = classificationrules.DefaultPageSize
	}
	if pageSize > classificationrules.MaxPageSize {
		pageSize = classificationrules.MaxPageSize
	}
	return page, pageSize
}
