package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// legalDocType is the closed set of authorable legal document types. It mirrors
// the CHECK constraint on public.legal_documents.
var legalDocTypes = map[string]bool{
	"terms_of_service": true,
	"privacy_policy":   true,
}

// IsLegalDocType reports whether s is an authorable legal document type.
//
// Exported because the MSP acceptance-ledger read (ee/msp/legal_acceptances.go)
// validates its ?doc_type= filter against the same closed set. Core owns the
// document types because Core owns authoring, so this is the single source of
// truth rather than a copy that can drift out of step with the CHECK
// constraint.
func IsLegalDocType(s string) bool { return legalDocTypes[s] }

type legalDocumentDTO struct {
	ID            uuid.UUID  `json:"id"`
	DocType       string     `json:"doc_type"`
	Version       int        `json:"version"`
	Title         string     `json:"title"`
	Body          string     `json:"body"`
	ContentHash   string     `json:"content_hash"`
	IsCurrent     bool       `json:"is_current"`
	EffectiveDate time.Time  `json:"effective_date"`
	PublishedAt   time.Time  `json:"published_at"`
	PublishedBy   *uuid.UUID `json:"published_by,omitempty"`
}

type legalVersionDTO struct {
	DocType     string    `json:"doc_type"`
	Version     int       `json:"version"`
	Title       string    `json:"title"`
	IsCurrent   bool      `json:"is_current"`
	PublishedAt time.Time `json:"published_at"`
}

// ListLegalDocuments returns the current published version of each legal
// document (with full body for editing) plus the version history metadata.
// legal_documents is a platform-global table, so this reads on the RLS-enforcing
// connection without any tenant scope.
func ListLegalDocuments(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		curRows, err := db.QueryContext(ctx, `
			SELECT id, doc_type, version, title, body, content_hash, is_current, effective_date, published_at, published_by
			FROM legal_documents
			WHERE is_current = true
			ORDER BY doc_type`)
		if err != nil {
			logrus.WithError(err).Error("Failed to list current legal documents")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load legal documents"})
			return
		}
		defer curRows.Close()
		current := []legalDocumentDTO{}
		for curRows.Next() {
			var d legalDocumentDTO
			if err := curRows.Scan(&d.ID, &d.DocType, &d.Version, &d.Title, &d.Body, &d.ContentHash, &d.IsCurrent, &d.EffectiveDate, &d.PublishedAt, &d.PublishedBy); err != nil {
				logrus.WithError(err).Error("Failed to scan legal document")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load legal documents"})
				return
			}
			current = append(current, d)
		}

		histRows, err := db.QueryContext(ctx, `
			SELECT doc_type, version, title, is_current, published_at
			FROM legal_documents
			ORDER BY doc_type, version DESC`)
		if err != nil {
			logrus.WithError(err).Error("Failed to list legal document history")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load legal documents"})
			return
		}
		defer histRows.Close()
		history := []legalVersionDTO{}
		for histRows.Next() {
			var v legalVersionDTO
			if err := histRows.Scan(&v.DocType, &v.Version, &v.Title, &v.IsCurrent, &v.PublishedAt); err != nil {
				logrus.WithError(err).Error("Failed to scan legal document version")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load legal documents"})
				return
			}
			history = append(history, v)
		}

		c.JSON(http.StatusOK, gin.H{"documents": current, "history": history})
	}
}

// PublishLegalDocument publishes a NEW immutable version of a legal document.
// It never mutates an existing version: the previously current row for that
// doc_type is demoted and a fresh row (version = max+1) is inserted as current,
// so every prior acceptance stays pinned to the exact text that was accepted.
func PublishLegalDocument(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}
		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		var req struct {
			DocType string `json:"doc_type" binding:"required"`
			Title   string `json:"title" binding:"required"`
			Body    string `json:"body" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "doc_type, title and body are required"})
			return
		}
		if !legalDocTypes[req.DocType] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown document type"})
			return
		}
		req.Title = strings.TrimSpace(req.Title)
		if req.Title == "" || strings.TrimSpace(req.Body) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Title and body cannot be empty"})
			return
		}

		// content_hash: hex sha256 of the UTF-8 body — identical to the in-SQL
		// encode(sha256(convert_to(body,'UTF8')),'hex') used by the seed, so
		// hashes are comparable across the seed and admin-published versions.
		sum := sha256.Sum256([]byte(req.Body))
		contentHash := hex.EncodeToString(sum[:])

		ctx := c.Request.Context()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			logrus.WithError(err).Error("Failed to begin legal publish tx")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish document"})
			return
		}
		defer func() { _ = tx.Rollback() }()

		var nextVersion int
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(version), 0) + 1 FROM legal_documents WHERE doc_type = $1`, req.DocType).
			Scan(&nextVersion); err != nil {
			logrus.WithError(err).Error("Failed to compute next legal version")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish document"})
			return
		}

		if _, err := tx.ExecContext(ctx,
			`UPDATE legal_documents SET is_current = false WHERE doc_type = $1 AND is_current = true`, req.DocType); err != nil {
			logrus.WithError(err).Error("Failed to demote current legal version")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish document"})
			return
		}

		var out legalDocumentDTO
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO legal_documents
				(doc_type, version, title, body, content_hash, is_current, published_by)
			VALUES ($1, $2, $3, $4, $5, true, $6)
			RETURNING id, doc_type, version, title, body, content_hash, is_current, effective_date, published_at, published_by`,
			req.DocType, nextVersion, req.Title, req.Body, contentHash, userID).
			Scan(&out.ID, &out.DocType, &out.Version, &out.Title, &out.Body, &out.ContentHash, &out.IsCurrent, &out.EffectiveDate, &out.PublishedAt, &out.PublishedBy); err != nil {
			logrus.WithError(err).Error("Failed to insert new legal version")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish document"})
			return
		}

		if err := tx.Commit(); err != nil {
			logrus.WithError(err).Error("Failed to commit legal publish tx")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish document"})
			return
		}

		logrus.WithFields(logrus.Fields{
			"doc_type": out.DocType, "version": out.Version, "published_by": userID,
		}).Info("Published new legal document version")
		c.JSON(http.StatusOK, out)
	}
}
