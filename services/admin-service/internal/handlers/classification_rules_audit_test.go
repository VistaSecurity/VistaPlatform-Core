package handlers

// Curating a classification rule must reach the audit trail.
//
// These rows decide what class is PROPOSED for every tenant's assets, so "who
// changed this, and to what" has to be answerable — the same argument that put
// the feed-sync and bundle-import routes in the audit trail beside them. Each
// test drives the REAL gin handler and asserts on the body the emitter actually
// POSTed, so removing the recordPlatformAudit call fails the test rather than
// merely changing a line nobody checks.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/classificationrules"
)

// auditedRuleEngine mounts the real routes behind an actor, the way
// AuthMiddleware leaves one in production. Built with the middleware BEFORE the
// routes: gin fixes a handler chain at registration time, so a later
// engine-level Use() affects nothing and the test would assert an absent actor
// was absent.
func auditedRuleEngine(store ClassificationRuleStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", auditActorID)
		c.Set("email", auditActorEmail)
		c.Next()
	})
	g := r.Group("/admin/catalogs")
	g.POST("/classification-rules", CreateClassificationRule(store))
	g.PUT("/classification-rules/:id", UpdateClassificationRule(store))
	g.DELETE("/classification-rules/:id", DeleteClassificationRule(store))
	return r
}

func ruleRequest(t *testing.T, eng *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		rdr = bytes.NewReader(blob)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

const ruleBase = "/admin/catalogs/classification-rules"

func TestClassificationRuleAudit_CreateRecordsTheRuleNotJustTheID(t *testing.T) {
	events := captureAudit(t)
	eng := auditedRuleEngine(&stubRuleStore{})

	w := ruleRequest(t, eng, http.MethodPost, ruleBase, classificationrules.Input{
		RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell Inc."), Confidence: 0.85,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body)
	}

	body := awaitAudit(t, events)
	assertField(t, body, "user_type", "platform")
	assertField(t, body, "event_type", "classification_rule.created")
	assertField(t, body, "action", "create")
	assertField(t, body, "event_category", "system")
	assertField(t, body, "resource_type", "classification_rule")

	// The rule itself, not just its id. A month later the id alone answers
	// nothing, and after a delete there is no row left to go and look at.
	meta, _ := body["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("no metadata on the audit record: %v", body)
	}
	if meta["pattern"] != "00188B" || meta["rule_kind"] != "oui" {
		t.Errorf("metadata does not carry the rule: %v", meta)
	}
}

func TestClassificationRuleAudit_UpdateAndDeleteAreRecorded(t *testing.T) {
	events := captureAudit(t)
	store := &stubRuleStore{rules: []classificationrules.Rule{
		{ID: "r1", RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell Inc."), Confidence: 0.85},
	}}
	eng := auditedRuleEngine(store)

	w := ruleRequest(t, eng, http.MethodPut, ruleBase+"/r1", classificationrules.Input{
		RuleKind: "oui", Pattern: "00188B", ClassKey: ptr("server"), Vendor: ptr("Dell Inc."), Confidence: 0.75,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status = %d; body=%s", w.Code, w.Body)
	}
	body := awaitAudit(t, events)
	assertField(t, body, "event_type", "classification_rule.updated")
	assertField(t, body, "action", "update")

	w = ruleRequest(t, eng, http.MethodDelete, ruleBase+"/r1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: status = %d; body=%s", w.Code, w.Body)
	}
	body = awaitAudit(t, events)
	assertField(t, body, "event_type", "classification_rule.deleted")
	assertField(t, body, "action", "delete")

	// The DELETE record names what went. The row is gone by the time anyone
	// reads this, so an id-only record is unreviewable by construction.
	meta, _ := body["metadata"].(map[string]interface{})
	if meta == nil || meta["pattern"] != "00188B" {
		t.Errorf("the delete record does not say which rule went: %v", meta)
	}
}

// An action that changed nothing is not audited. A rejected body, a missing
// rule and a duplicate pattern all leave the table exactly as it was, and a
// trail padded with non-events is one people stop reading.
func TestClassificationRuleAudit_NonEventsAreNotRecorded(t *testing.T) {
	t.Run("rejected body", func(t *testing.T) {
		events := captureAudit(t)
		eng := auditedRuleEngine(&stubRuleStore{})
		w := ruleRequest(t, eng, http.MethodPost, ruleBase, classificationrules.Input{
			RuleKind: "oui", Pattern: "not-hex", Vendor: ptr("Dell"), Confidence: 0.85,
		})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		expectNoAudit(t, events)
	})

	t.Run("missing rule", func(t *testing.T) {
		events := captureAudit(t)
		eng := auditedRuleEngine(&stubRuleStore{})
		w := ruleRequest(t, eng, http.MethodDelete, ruleBase+"/nope", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		expectNoAudit(t, events)
	})

	t.Run("duplicate pattern", func(t *testing.T) {
		events := captureAudit(t)
		store := &stubRuleStore{rules: []classificationrules.Rule{
			{ID: "r1", RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell Inc."), Confidence: 0.85},
		}}
		eng := auditedRuleEngine(store)
		w := ruleRequest(t, eng, http.MethodPost, ruleBase, classificationrules.Input{
			RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell Inc."), Confidence: 0.85,
		})
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", w.Code)
		}
		expectNoAudit(t, events)
	})
}
