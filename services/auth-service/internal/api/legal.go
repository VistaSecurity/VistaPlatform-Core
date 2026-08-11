package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// legalDocument is a published, versioned legal document (Terms of Service or
// Privacy Policy). legal_documents is a platform-global table authored by
// platform admins in admin-ui — the same text is shown to every tenant, so it
// carries no tenant scope and is readable unauthenticated (the signup page and
// the standalone /legal/* pages fetch it before a session exists).
type legalDocument struct {
	ID            uuid.UUID `json:"id"`
	DocType       string    `json:"doc_type"`
	Version       int       `json:"version"`
	Title         string    `json:"title"`
	Body          string    `json:"body"`
	ContentHash   string    `json:"content_hash"`
	EffectiveDate time.Time `json:"effective_date"`
}

// fetchCurrentLegalDocuments returns the current published version of every
// legal document type, ordered for stable display (privacy after terms).
func fetchCurrentLegalDocuments(ctx context.Context, db *sql.DB) ([]legalDocument, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, doc_type, version, title, body, content_hash, effective_date
		FROM legal_documents
		WHERE is_current = true
		ORDER BY doc_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var docs []legalDocument
	for rows.Next() {
		var d legalDocument
		if err := rows.Scan(&d.ID, &d.DocType, &d.Version, &d.Title, &d.Body, &d.ContentHash, &d.EffectiveDate); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, rows.Err()
}

// pendingLegalForUser returns the current legal documents the user has not yet
// accepted (either never accepted that doc_type, or accepted an older version).
// Keyed strictly by the authenticated user's own id, so it runs on the bypass
// role without leaking across tenants.
func pendingLegalForUser(ctx context.Context, db *sql.DB, userID uuid.UUID) ([]legalDocument, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT ld.id, ld.doc_type, ld.version, ld.title, ld.body, ld.content_hash, ld.effective_date
		FROM legal_documents ld
		WHERE ld.is_current = true
		  AND NOT EXISTS (
			SELECT 1 FROM legal_acceptances la
			WHERE la.user_id = $1 AND la.document_id = ld.id
		  )
		ORDER BY ld.doc_type`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var docs []legalDocument
	for rows.Next() {
		var d legalDocument
		if err := rows.Scan(&d.ID, &d.DocType, &d.Version, &d.Title, &d.Body, &d.ContentHash, &d.EffectiveDate); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, rows.Err()
}

// recordLegalAcceptances writes an append-only acceptance row for every current
// legal document, stamping the server-observed IP and user agent. Idempotent:
// re-accepting a version the user already accepted is a no-op (ON CONFLICT).
// Returns the number of current documents (i.e. how many the user is now on
// record as having accepted). Keyed by the caller-supplied tenant/user ids,
// which come from a freshly created user (signup) or the JWT (accept) — never
// from untrusted request input — so it runs on the bypass role.
//
// When snapshot is non-nil, those exact documents are recorded (the versions
// the user was gated on at signup). When nil, current documents are loaded
// fresh (the post-login re-acceptance path).
func recordLegalAcceptances(ctx context.Context, db *sql.DB, tenantID, userID uuid.UUID, ip, ua string, snapshot []legalDocument) (int, error) {
	docs := snapshot
	if docs == nil {
		var err error
		docs, err = fetchCurrentLegalDocuments(ctx, db)
		if err != nil {
			return 0, err
		}
	}
	for _, d := range docs {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO legal_acceptances
				(tenant_id, user_id, doc_type, document_id, version, content_hash, accepted_ip, user_agent)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (user_id, document_id) DO NOTHING`,
			tenantID, userID, d.DocType, d.ID, d.Version, d.ContentHash, nullIfEmpty(ip), nullIfEmpty(ua)); err != nil {
			return 0, err
		}
	}
	return len(docs), nil
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// GetCurrentLegalDocuments (public) returns the current version of every legal
// document — consumed by the signup page to render acceptance links.
func GetCurrentLegalDocuments(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		docs, err := fetchCurrentLegalDocuments(c.Request.Context(), db)
		if err != nil {
			logrus.WithError(err).Error("Failed to load current legal documents")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load legal documents"})
			return
		}
		if docs == nil {
			docs = []legalDocument{}
		}
		c.JSON(http.StatusOK, gin.H{"documents": docs})
	}
}

// GetLegalDocumentByType (public) returns the current version of one document
// type — backs the standalone /legal/terms and /legal/privacy pages.
func GetLegalDocumentByType(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		docType := c.Param("docType")
		if docType != "terms_of_service" && docType != "privacy_policy" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown document type"})
			return
		}
		var d legalDocument
		err := db.QueryRowContext(c.Request.Context(), `
			SELECT id, doc_type, version, title, body, content_hash, effective_date
			FROM legal_documents
			WHERE doc_type = $1 AND is_current = true`, docType).
			Scan(&d.ID, &d.DocType, &d.Version, &d.Title, &d.Body, &d.ContentHash, &d.EffectiveDate)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Document not published"})
			return
		}
		if err != nil {
			logrus.WithError(err).Error("Failed to load legal document")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load legal document"})
			return
		}
		c.JSON(http.StatusOK, d)
	}
}

// GetPendingLegalAcceptances (auth) returns the legal documents the signed-in
// user must accept before continuing — empty when they are up to date. The
// frontend shows a blocking modal when this is non-empty (re-acceptance on a
// newly published version).
func GetPendingLegalAcceptances(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}
		docs, err := pendingLegalForUser(c.Request.Context(), db, userID)
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to load pending legal acceptances")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load pending acceptances"})
			return
		}
		if docs == nil {
			docs = []legalDocument{}
		}
		c.JSON(http.StatusOK, gin.H{"documents": docs})
	}
}

// AcceptLegalDocuments (auth) records the signed-in user's acceptance of all
// current legal documents. Used both by the post-login re-acceptance modal and
// any self-service "review terms" flow.
func AcceptLegalDocuments(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}
		tenantID, ok := currentTenantID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant context"})
			return
		}
		var req struct {
			Accepted bool `json:"accepted"`
		}
		// Body is optional; absence is treated as an explicit accept-all click.
		_ = c.ShouldBindJSON(&req)
		if c.Request.ContentLength > 0 && !req.Accepted {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Terms must be accepted"})
			return
		}
		n, err := recordLegalAcceptances(c.Request.Context(), db, tenantID, userID, c.ClientIP(), c.Request.UserAgent(), nil)
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to record legal acceptance")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record acceptance"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Acceptance recorded", "accepted_count": n})
	}
}

// currentUserID / currentTenantID parse the ids RequireAuth sets on the gin
// context (both stored as strings).
func currentUserID(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("userID")
	if !exists {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(v.(string))
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

func currentTenantID(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("tenantID")
	if !exists {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(v.(string))
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}
