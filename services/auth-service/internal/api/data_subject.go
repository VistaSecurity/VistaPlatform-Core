package api

// Data subject requests: export and erasure.
//
// The Privacy Policy this platform seeds promises access, rectification,
// erasure and portability. Until this file existed, honouring any of those
// meant an administrator writing SQL against production. That is the gap these
// two handlers close.
//
// The erasure policy below is a set of DELIBERATE decisions, not an
// implementation detail — "delete everything about this person" and "keep an
// audit trail anyone can trust" are in direct conflict, and the resolution is a
// judgement about liability. It is recorded in
// docsv4/internal/developer/standards/features/data-subject-request-export.md
// and described to operators in docsv4/core/operate/legal/.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// auditExportWindowDays bounds the audit slice of an export. The audit trail is
// the only unbounded category — a long-lived tenant can hold years of it — and
// an export nobody can open is not an answer to a subject access request.
const auditExportWindowDays = 365

// erasureTombstoneDomain is the domain used for the anonymized email that
// replaces a person's address. `.invalid` is reserved by RFC 2606 precisely so
// it can never be routed or registered, which matters because the tombstone
// stays in a UNIQUE column forever.
const erasureTombstoneDomain = "erased.invalid"

// tombstoneEmail derives the replacement address. It is derived from the user
// id rather than random so the same erased user is recognisable across the
// tables that reference them, and so re-running an erasure is idempotent.
func tombstoneEmail(userID uuid.UUID) string {
	return fmt.Sprintf("erased-%s@%s", userID.String(), erasureTombstoneDomain)
}

// --- export ---------------------------------------------------------------

type dataExport struct {
	Subject        exportSubject         `json:"subject"`
	GeneratedAt    time.Time             `json:"generated_at"`
	Profile        *exportProfile        `json:"profile"`
	LegalAccepted  []exportLegalAccepted `json:"legal_acceptances"`
	Invitations    []exportInvitation    `json:"invitations"`
	APITokens      []exportAPIToken      `json:"api_tokens"`
	AuditEvents    []exportAuditEvent    `json:"audit_events"`
	AuditWindow    exportWindow          `json:"audit_events_window"`
	NotIncluded    []string              `json:"not_included"`
	SchemaVersion  int                   `json:"schema_version"`
	GeneratedByAPI string                `json:"generated_by"`
}

type exportSubject struct {
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
}

type exportWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type exportProfile struct {
	Email         string     `json:"email"`
	FirstName     *string    `json:"first_name"`
	LastName      *string    `json:"last_name"`
	IsActive      bool       `json:"is_active"`
	EmailVerified bool       `json:"email_verified"`
	Timezone      *string    `json:"timezone"`
	AvatarURL     *string    `json:"avatar_url"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	LoginCount    int        `json:"login_count"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type exportLegalAccepted struct {
	DocType     string    `json:"doc_type"`
	Version     int       `json:"version"`
	ContentHash string    `json:"content_hash"`
	AcceptedAt  time.Time `json:"accepted_at"`
	AcceptedIP  *string   `json:"accepted_ip"`
	UserAgent   *string   `json:"user_agent"`
}

type exportInvitation struct {
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	CreatedAt  *time.Time `json:"created_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
}

type exportAPIToken struct {
	Name       string     `json:"name"`
	Prefix     string     `json:"token_prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

type exportAuditEvent struct {
	OccurredAt   time.Time `json:"occurred_at"`
	EventType    string    `json:"event_type"`
	Action       string    `json:"action"`
	ResourceType *string   `json:"resource_type"`
	Success      bool      `json:"success"`
	IPAddress    *string   `json:"ip_address"`
}

// notIncludedNotice is shipped INSIDE the export. A subject access request is
// answered by what you hand over and by being straight about what you did not,
// and the two exclusions below are both deliberate.
func notIncludedNotice() []string {
	return []string{
		"Discovery and inventory data. That describes the organization's estate " +
			"(hosts, certificates, cryptographic configurations), not this person. " +
			"Personal data that arrives inside it — an email address in a certificate " +
			"subject, a name in an SSH key comment — belongs to the organization's own " +
			"controller-side process, not to this export.",
		"Secret material of any kind: password hashes, password history, " +
			"verification and reset tokens, API token values, and session state. " +
			"These are held about the account but handing them over would create a " +
			"far greater risk than withholding them.",
		"Tickets and comments this person authored. Those records carry only the " +
			"author's user id, so they identify this person via the profile above " +
			"rather than duplicating it.",
	}
}

// buildExport assembles the payload. It takes a *sql.Tx so the caller controls
// the RLS-scoped transaction — every read here must run under the tenant scope,
// not on a plain connection.
func buildExport(ctx context.Context, tx *sql.Tx, tenantID, userID uuid.UUID, now time.Time) (*dataExport, error) {
	from := now.AddDate(0, 0, -auditExportWindowDays)

	out := &dataExport{
		Subject:        exportSubject{UserID: userID, TenantID: tenantID},
		GeneratedAt:    now,
		LegalAccepted:  []exportLegalAccepted{},
		Invitations:    []exportInvitation{},
		APITokens:      []exportAPIToken{},
		AuditEvents:    []exportAuditEvent{},
		AuditWindow:    exportWindow{From: from, To: now},
		NotIncluded:    notIncludedNotice(),
		SchemaVersion:  1,
		GeneratedByAPI: "vista-platform-data-export",
	}

	// Profile. Column list is an explicit allowlist: `SELECT *` here would
	// export the password hash the first time someone adds a column.
	var p exportProfile
	err := tx.QueryRowContext(ctx, `
		SELECT `+profileExportColumns+`
		FROM users
		WHERE id = $1 AND tenant_id = $2`, userID, tenantID).
		Scan(&p.Email, &p.FirstName, &p.LastName, &p.IsActive, &p.EmailVerified,
			&p.Timezone, &p.AvatarURL, &p.LastLoginAt, &p.LoginCount,
			&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	out.Profile = &p

	rows, err := tx.QueryContext(ctx, `
		SELECT doc_type, version, content_hash, accepted_at, accepted_ip, user_agent
		FROM legal_acceptances
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY accepted_at`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("legal acceptances: %w", err)
	}
	for rows.Next() {
		var a exportLegalAccepted
		if err := rows.Scan(&a.DocType, &a.Version, &a.ContentHash, &a.AcceptedAt, &a.AcceptedIP, &a.UserAgent); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("legal acceptance scan: %w", err)
		}
		out.LegalAccepted = append(out.LegalAccepted, a)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("legal acceptances: %w", err)
	}
	_ = rows.Close()

	invRows, err := tx.QueryContext(ctx, `
		SELECT email, role, status, created_at, accepted_at
		FROM invitations
		WHERE tenant_id = $1 AND (accepted_user_id = $2 OR email = (SELECT email FROM users WHERE id = $2))
		ORDER BY created_at`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("invitations: %w", err)
	}
	for invRows.Next() {
		var i exportInvitation
		if err := invRows.Scan(&i.Email, &i.Role, &i.Status, &i.CreatedAt, &i.AcceptedAt); err != nil {
			_ = invRows.Close()
			return nil, fmt.Errorf("invitation scan: %w", err)
		}
		out.Invitations = append(out.Invitations, i)
	}
	_ = invRows.Close()

	// API tokens: metadata only. token_hash is never selected.
	tokRows, err := tx.QueryContext(ctx, `
		SELECT name, token_prefix, created_at, last_used_at, expires_at, revoked_at
		FROM api_tokens
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY created_at`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("api tokens: %w", err)
	}
	for tokRows.Next() {
		var tkn exportAPIToken
		if err := tokRows.Scan(&tkn.Name, &tkn.Prefix, &tkn.CreatedAt, &tkn.LastUsedAt, &tkn.ExpiresAt, &tkn.RevokedAt); err != nil {
			_ = tokRows.Close()
			return nil, fmt.Errorf("api token scan: %w", err)
		}
		out.APITokens = append(out.APITokens, tkn)
	}
	_ = tokRows.Close()

	audRows, err := tx.QueryContext(ctx, `
		SELECT created_at, event_type, action, resource_type, success, host(ip_address)
		FROM audit.activity_logs
		WHERE user_id = $1 AND tenant_id = $2 AND created_at >= $3
		ORDER BY created_at DESC`, userID, tenantID, from)
	if err != nil {
		return nil, fmt.Errorf("audit events: %w", err)
	}
	for audRows.Next() {
		var e exportAuditEvent
		if err := audRows.Scan(&e.OccurredAt, &e.EventType, &e.Action, &e.ResourceType, &e.Success, &e.IPAddress); err != nil {
			_ = audRows.Close()
			return nil, fmt.Errorf("audit event scan: %w", err)
		}
		out.AuditEvents = append(out.AuditEvents, e)
	}
	_ = audRows.Close()

	return out, nil
}

func writeExport(c *gin.Context, db *sql.DB, tenantID, userID uuid.UUID) {
	ctx := c.Request.Context()
	var payload *dataExport
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		var err error
		payload, err = buildExport(ctx, tx, tenantID, userID, time.Now().UTC())
		return err
	})
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Failed to build data export")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build data export"})
		return
	}

	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		logrus.WithError(err).Error("Failed to encode data export")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build data export"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="data-export-%s.json"`, userID))
	c.Data(http.StatusOK, "application/json", body)
}

// ExportMyData handles GET /me/data-export. No permission beyond being signed
// in: everyone can ask what is held about them.
func ExportMyData(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, userID, ok := subjectFromSession(c)
		if !ok {
			return
		}
		writeExport(c, db, tenantID, userID)
	}
}

// ExportUserData handles GET /users/:id/data-export, gated on users.manage.
//
// The tenant comes from the SESSION and is applied as an explicit predicate as
// well as through RLS. Belt and braces on purpose: this endpoint hands over one
// named person's data, so an IDOR here is the whole ballgame.
func ExportUserData(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantFromSession(c)
		if !ok {
			return
		}
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}
		writeExport(c, db, tenantID, userID)
	}
}

// --- erasure --------------------------------------------------------------

// erasureProfileUpdate anonymizes the profile in one statement. Every secret
// and free-text column is cleared here; the audit's credential-column checker
// exempts this file precisely because it CLEARS these columns rather than
// storing anything, and TestEraseUser_ClearsEverySecretColumn holds that claim
// to the statement below.
const erasureProfileUpdate = `
				UPDATE users SET
					email = $3,
					first_name = NULL,
					last_name = NULL,
					avatar_url = NULL,
					password_hash = NULL,
					password_history = '[]'::jsonb,
					password_reset_token = NULL,
					password_reset_expires = NULL,
					email_verification_token = NULL,
					email_verification_expires = NULL,
					preferences = '{}'::jsonb,
					is_active = false,
					deleted_at = COALESCE(deleted_at, now()),
					updated_at = now()
				WHERE id = $1 AND tenant_id = $2`

// erasureVerify re-reads the rows that must no longer identify anyone. A
// non-zero result rolls the whole erasure back: reporting success for an
// erasure that did nothing would have an operator tell a data subject their
// data was removed when it was not.
const erasureVerify = `
				SELECT
					(SELECT count(*) FROM users
					  WHERE id = $1 AND tenant_id = $2
					    AND (email <> $3 OR first_name IS NOT NULL OR last_name IS NOT NULL))
				  + (SELECT count(*) FROM api_tokens WHERE user_id = $1 AND tenant_id = $2)
				  + (SELECT count(*) FROM audit.activity_logs
					  WHERE user_id = $1 AND tenant_id = $2 AND user_email IS DISTINCT FROM $3)`

// profileExportColumns is an explicit allowlist. `SELECT *` here would export
// the password hash the first time somebody adds a column, which is the exact
// mistake this feature exists to avoid making.
const profileExportColumns = `email, first_name, last_name, is_active, email_verified,
		       timezone, avatar_url, last_login_at, COALESCE(login_count, 0),
		       created_at, updated_at`

// erasureResult reports what actually happened, per category. Returned to the
// caller so an operator answering a request has something to file, and logged
// so the erasure itself is auditable.
type erasureResult struct {
	UserID            uuid.UUID `json:"user_id"`
	TombstoneEmail    string    `json:"tombstone_email"`
	ErasedAt          time.Time `json:"erased_at"`
	ProfileAnonymized bool      `json:"profile_anonymized"`
	APITokensDeleted  int64     `json:"api_tokens_deleted"`
	InvitationsPurged int64     `json:"invitations_deleted"`
	AuditEventsPseudo int64     `json:"audit_events_pseudonymized"`
	Retained          []string  `json:"retained"`
	Limitations       []string  `json:"limitations"`
}

// retainedCategories is the half of the policy that says NO. Each entry is a
// deliberate decision with a reason, because "we kept some of your data" needs
// to be defensible, not silent.
func retainedCategories() []string {
	return []string{
		"Legal acceptance records — which document version was accepted, its " +
			"content hash, when, and from what address. This is the evidence that " +
			"this person agreed to the terms; erasing it would destroy the " +
			"organization's proof of the agreement at the request of the one person " +
			"who might later dispute it. Retained for the establishment and defence " +
			"of legal claims.",
		"Audit trail entries, with the identity removed. The events remain so the " +
			"record stays complete and countable — a log that can be selectively " +
			"rewritten on request proves nothing, including that nobody else " +
			"rewrote it. The actor is now the tombstone rather than a person.",
		"Tickets and comments this person authored, with authorship anonymized. " +
			"They carry only a user id, so tombstoning the profile anonymizes them " +
			"automatically; the text is an operational record about the estate.",
	}
}

// erasureLimitations is what this does NOT reach. Stated in the response rather
// than discovered later: an operator who believes erasure was total, when it
// was not, will tell a data subject something untrue.
func erasureLimitations() []string {
	return []string{
		"Audit event payloads (old/new value snapshots) are not swept. An event " +
			"recording a profile change may still contain the previous email address " +
			"inside its payload. Sweeping arbitrary JSON payloads safely is separate " +
			"work.",
		"Personal data inside discovery data — an email address in a certificate " +
			"subject, a name in an SSH key comment — is not touched. It describes the " +
			"estate, and removing it would corrupt the inventory.",
		"Backups are not rewritten. Data ages out of them on the operator's backup " +
			"retention schedule.",
	}
}

// EraseUser handles POST /users/:id/erase, gated on users.manage.
//
// Anonymize-in-place, not DELETE: the user row is referenced by tickets,
// comments and audit events, so removing it would either cascade into unrelated
// operational history or leave dangling references.
func EraseUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantFromSession(c)
		if !ok {
			return
		}
		actorID := c.GetString("userID")

		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}
		if actorID == userID.String() {
			// Erasing yourself would revoke the session mid-request and leave the
			// tenant potentially without an administrator. A second admin does it.
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "You cannot erase your own account. Ask another administrator.",
			})
			return
		}

		ctx := c.Request.Context()
		now := time.Now().UTC()
		result := erasureResult{
			UserID:         userID,
			TombstoneEmail: tombstoneEmail(userID),
			ErasedAt:       now,
			Retained:       retainedCategories(),
			Limitations:    erasureLimitations(),
		}

		err = shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
			var exists bool
			if err := tx.QueryRowContext(ctx,
				`SELECT true FROM users WHERE id = $1 AND tenant_id = $2`, userID, tenantID).
				Scan(&exists); err != nil {
				return err
			}

			// 1. Profile → tombstone. Every free-text and secret column is cleared
			//    in the same statement, so there is no window in which the account
			//    is half-erased.
			if _, err := tx.ExecContext(ctx, erasureProfileUpdate, userID, tenantID, result.TombstoneEmail); err != nil {
				return fmt.Errorf("anonymize profile: %w", err)
			}
			result.ProfileAnonymized = true

			// 2. API tokens → delete outright. No evidentiary value, and a live
			//    token belonging to an erased account is a security problem.
			if res, err := tx.ExecContext(ctx,
				`DELETE FROM api_tokens WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID); err != nil {
				return fmt.Errorf("delete api tokens: %w", err)
			} else {
				result.APITokensDeleted, _ = res.RowsAffected()
			}

			// 3. Invitations → delete. The row is an email address and nothing else
			//    of value once the account exists.
			if res, err := tx.ExecContext(ctx,
				`DELETE FROM invitations WHERE tenant_id = $1 AND accepted_user_id = $2`, tenantID, userID); err != nil {
				return fmt.Errorf("delete invitations: %w", err)
			} else {
				result.InvitationsPurged, _ = res.RowsAffected()
			}

			// 4. Audit trail → keep the events, remove the identity. user_email is a
			//    DENORMALIZED copy of the address: tombstoning the users row alone
			//    would leave it sitting in every event this person generated.
			if res, err := tx.ExecContext(ctx, `
				UPDATE audit.activity_logs SET user_email = $3
				WHERE user_id = $1 AND tenant_id = $2 AND user_email IS DISTINCT FROM $3`,
				userID, tenantID, result.TombstoneEmail); err != nil {
				return fmt.Errorf("pseudonymize audit trail: %w", err)
			} else {
				result.AuditEventsPseudo, _ = res.RowsAffected()
			}

			// 5. Prove it. A guard that cannot fail is worse than no guard, and an
			//    erasure that silently did nothing is the worst outcome here: the
			//    operator would tell a data subject their data was removed when it
			//    was not. Re-read and refuse to commit if anything identifying
			//    survives.
			var leaked int
			if err := tx.QueryRowContext(ctx, erasureVerify,
				userID, tenantID, result.TombstoneEmail).Scan(&leaked); err != nil {
				return fmt.Errorf("verify erasure: %w", err)
			}
			if leaked > 0 {
				return fmt.Errorf("erasure verification failed: %d identifying row(s) survived; rolled back", leaked)
			}
			return nil
		})

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			logrus.WithError(err).WithField("user_id", userID).Error("Failed to erase user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to erase user data"})
			return
		}

		// The erasure itself is auditable — you have to be able to show you
		// honoured the request — and it records the TOMBSTONE, not the identity
		// that was just removed.
		logrus.WithFields(logrus.Fields{
			"tenant_id": tenantID, "subject": result.TombstoneEmail,
			"actor": actorID, "audit_events_pseudonymized": result.AuditEventsPseudo,
		}).Info("Erased user data on a data subject request")

		c.JSON(http.StatusOK, result)
	}
}

// --- session helpers ------------------------------------------------------

func tenantFromSession(c *gin.Context) (uuid.UUID, bool) {
	tenantIDStr := c.GetString("tenantID")
	if tenantIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return tenantID, true
}

func subjectFromSession(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, ok := tenantFromSession(c)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	userID, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}
