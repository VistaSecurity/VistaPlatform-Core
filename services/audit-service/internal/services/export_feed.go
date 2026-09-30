package services

// The export feed: persisted audit events read forward from a cursor, for a
// consumer that ships the audit trail somewhere else (a SIEM exporter).
//
// This is the "the audit log IS the outbox" half of platform ADR-0002 D4/D5.
// The consumer keeps its own durable cursor and pages forward from it; nothing
// is buffered in this service, so a consumer that dies, restarts or falls
// behind resumes where it stopped and loses nothing.
//
// # Order
//
// Events are ordered by (created_at, id). created_at is assigned by the
// DATABASE at insert (clock_timestamp() — see LogActivity), not by this
// process, so replicas with skewed clocks cannot interleave out of order. id
// breaks ties: two events stamped in the same microsecond still have one
// stable, total order, and a cursor that sits between them is unambiguous.
//
// # The settle window
//
// A row becomes visible when its transaction COMMITS, but its created_at was
// taken at INSERT. A reader that pages right up to "now" could advance its
// cursor past a created_at whose transaction has not committed yet, and never
// see that row. So a page only ever reaches rows stamped at least
// ExportSettleWindow ago: every audit write is a single-row transaction whose
// INSERT is its last statement, so the gap between its created_at and its
// commit is the commit itself — far below the window. The cost is that an
// event reaches the feed ExportSettleWindow after it is stored.
//
// # What leaves
//
// Each event is ExportEvent's projection, never the whole row: change diffs,
// metadata, user agent and session id stay here.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
)

// ExportSettleWindow is how old an event must be before the feed returns it.
// See the file comment.
const ExportSettleWindow = 5 * time.Second

// Page-size bounds for ExportPage.
const (
	ExportPageDefault = 500
	ExportPageMax     = 1000
)

// ExportBackfillMax bounds how far back a new consumer may ask to start.
const ExportBackfillMax = 7 * 24 * time.Hour

// maxEventID sorts after every real id, so a cursor (t, maxEventID) means
// "after everything stamped at or before t".
var maxEventID = uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")

// ExportCursor is a position in the feed: the (created_at, id) of the last
// event a consumer has taken. The next page starts strictly after it.
type ExportCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

// ExportItem is one event and the cursor that points just past it.
type ExportItem struct {
	Cursor ExportCursor           `json:"cursor"`
	Event  map[string]interface{} `json:"event"`
}

// ExportPage is one page of the feed.
type ExportPage struct {
	Items []ExportItem `json:"items"`
	// Next is where the following page starts: the last item's cursor, or the
	// request's own cursor when the page is empty.
	Next ExportCursor `json:"next"`
	// More is true when the page was full, so more settled events may follow.
	More bool `json:"more"`
	// Horizon is the settle boundary this page was read against: no event
	// stamped after it was considered.
	Horizon time.Time `json:"horizon"`
}

// ErrInvalidExportRequest marks a caller error (bad cursor, limit, backfill).
var ErrInvalidExportRequest = errors.New("invalid export request")

// ExportPage returns up to limit events stored strictly after `after`, oldest
// first, platform-wide. It runs on the BYPASSRLS handle: the feed is the whole
// platform's audit trail (SIEM export is platform-global configuration), and
// the only callers are HMAC-authenticated services.
func (s *ActivityLogService) ExportPage(ctx context.Context, after ExportCursor, limit int, settle time.Duration) (ExportPage, error) {
	if limit < 1 || limit > ExportPageMax {
		return ExportPage{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidExportRequest, ExportPageMax)
	}
	if after.CreatedAt.IsZero() {
		return ExportPage{}, fmt.Errorf("%w: a cursor is required (ask for the head first)", ErrInvalidExportRequest)
	}
	if settle < 0 {
		settle = 0
	}
	page := ExportPage{Next: after, Items: []ExportItem{}}

	// RLS: cross-tenant — the platform-wide export feed, bypass role; see ExportPage.
	rows, err := s.bypassDB.QueryContext(ctx, `
		WITH h AS (SELECT clock_timestamp() - make_interval(secs => $4) AS horizon)
		SELECT a.id, a.tenant_id, a.user_id, a.user_type, a.user_email,
		       a.event_type, a.event_category, a.action, a.resource_type, a.resource_id,
		       host(a.ip_address), a.request_id, COALESCE(a.success, true), a.error_code,
		       a.compliance_tags, COALESCE(a.requires_attention, false),
		       a.occurred_at, a.created_at, h.horizon
		FROM h, audit.activity_logs a
		WHERE (a.created_at, a.id) > ($1, $2)
		  AND a.created_at <= h.horizon
		ORDER BY a.created_at, a.id
		LIMIT $3`,
		after.CreatedAt, after.ID, limit, settle.Seconds())
	if err != nil {
		return ExportPage{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			e                                  models.ActivityLog
			userEmail, resourceType, ip, reqID sql.NullString
			errCode                            sql.NullString
			tenantID, userID, resourceID       uuid.NullUUID
			tags                               pq.StringArray
			horizon                            time.Time
		)
		if err := rows.Scan(&e.ID, &tenantID, &userID, &e.UserType, &userEmail,
			&e.EventType, &e.EventCategory, &e.Action, &resourceType, &resourceID,
			&ip, &reqID, &e.Success, &errCode,
			&tags, &e.RequiresAttention,
			&e.OccurredAt, &e.CreatedAt, &horizon); err != nil {
			return ExportPage{}, err
		}
		e.TenantID = nullUUIDPtr(tenantID)
		e.UserID = nullUUIDPtr(userID)
		e.ResourceID = nullUUIDPtr(resourceID)
		e.UserEmail = nullStringPtr(userEmail)
		e.ResourceType = nullStringPtr(resourceType)
		e.IPAddress = nullStringPtr(ip)
		e.RequestID = nullStringPtr(reqID)
		e.ErrorCode = nullStringPtr(errCode)
		e.ComplianceTags = []string(tags)
		e.OccurredAt = e.OccurredAt.UTC()
		cur := ExportCursor{CreatedAt: e.CreatedAt.UTC(), ID: e.ID}
		page.Items = append(page.Items, ExportItem{Cursor: cur, Event: ExportEvent(&e)})
		page.Next = cur
		page.Horizon = horizon.UTC()
	}
	if err := rows.Err(); err != nil {
		return ExportPage{}, err
	}
	page.More = len(page.Items) == limit
	if page.Horizon.IsZero() {
		// Empty page: still report the boundary it was read against.
		// RLS: none — reads the database clock only.
		if err := s.bypassDB.QueryRowContext(ctx,
			`SELECT clock_timestamp() - make_interval(secs => $1)`, settle.Seconds()).Scan(&page.Horizon); err != nil {
			return ExportPage{}, err
		}
		page.Horizon = page.Horizon.UTC()
	}
	return page, nil
}

// ExportHead returns the cursor a NEW consumer starts from. With no backfill it
// is "now" by the database clock: the consumer receives only events stored
// from here on. With a backfill it is that long ago, bounded by
// ExportBackfillMax, so a new consumer can pick up a recent window without
// flooding its receiver with the whole retained trail.
func (s *ActivityLogService) ExportHead(ctx context.Context, backfill time.Duration) (ExportCursor, error) {
	if backfill < 0 || backfill > ExportBackfillMax {
		return ExportCursor{}, fmt.Errorf("%w: backfill must be between 0 and %s", ErrInvalidExportRequest, ExportBackfillMax)
	}
	var now time.Time
	// RLS: none — reads the database clock only.
	if err := s.bypassDB.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return ExportCursor{}, err
	}
	now = now.UTC()
	if backfill == 0 {
		return ExportCursor{CreatedAt: now, ID: maxEventID}, nil
	}
	return ExportCursor{CreatedAt: now.Add(-backfill), ID: uuid.Nil}, nil
}

func nullUUIDPtr(v uuid.NullUUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := v.UUID
	return &id
}

func nullStringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

// ExportEvent is the exported shape of one audit entry: who, what, on what,
// from where, and how it ended. old_values / new_values, metadata, user agent
// and session id are left out — a change diff can carry whatever the audited
// object held, and a copy shipped to another system should not be the place
// such values leak to. Absent optional fields are omitted rather than sent as
// null.
func ExportEvent(e *models.ActivityLog) map[string]interface{} {
	ev := map[string]interface{}{
		"id":                 e.ID,
		"event_type":         e.EventType,
		"event_category":     e.EventCategory,
		"action":             e.Action,
		"success":            e.Success,
		"user_type":          e.UserType,
		"requires_attention": e.RequiresAttention,
		"occurred_at":        e.OccurredAt,
	}
	if e.TenantID != nil {
		ev["tenant_id"] = *e.TenantID
	}
	if e.UserID != nil {
		ev["user_id"] = *e.UserID
	}
	if e.UserEmail != nil && *e.UserEmail != "" {
		ev["user_email"] = *e.UserEmail
	}
	if e.ResourceType != nil && *e.ResourceType != "" {
		ev["resource_type"] = *e.ResourceType
	}
	if e.ResourceID != nil {
		ev["resource_id"] = *e.ResourceID
	}
	if e.IPAddress != nil && *e.IPAddress != "" {
		ev["ip_address"] = *e.IPAddress
	}
	if e.RequestID != nil && *e.RequestID != "" {
		ev["request_id"] = *e.RequestID
	}
	if e.ErrorCode != nil && *e.ErrorCode != "" {
		ev["error_code"] = *e.ErrorCode
	}
	if len(e.ComplianceTags) > 0 {
		ev["compliance_tags"] = e.ComplianceTags
	}
	return ev
}
