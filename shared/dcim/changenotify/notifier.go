// Package changenotify raises `object_changed` (standards/alert-registry.yaml)
// for the inventory changes a request (or another unit of work) committed —
// DCIM gap 5, "notify me when a cable or a prefix changes", through the
// existing alert → routing rule → channel machinery rather than a second
// notification path.
//
// # How a change becomes an event
//
//  1. [Notifier.Middleware] (mounted once on the router) puts a
//     changes.Collector and a request id on the request context.
//  2. Every change the service layer records through changes.InTx notes its
//     (tenant, request id, kind, object, action) on that collector — the
//     recorder, never a trigger, so the same code path that writes the
//     Changes tab is the one that feeds notifications.
//  3. When the handler has returned, the notifier re-reads the request's
//     COMMITTED object_changes rows (a rolled-back transaction leaves nothing
//     to find), folds them to at most one event per (tenant, kind, object,
//     action), and publishes alerts.raise. compliance-engine's alert engine
//     routes an event-lifecycle type once, with no alerts row, to
//     notifications.send, where notification-service evaluates each rule's
//     change_filter.
//
// # Work outside a request
//
// A background job's pass, a consumed message or a platform agent's job has no
// request around it; [Notifier.Unit] stands in for the middleware there (see
// unit.go). The services that write DCIM tables mount the middleware and open
// units: inventory-service, and device-interrogation-service, whose cloud
// enumeration writes sites, locations and clusters through
// shared/identity/postgres and shared/dcim/sites.
//
// # Delivery
//
// [FallbackPublisher] publishes onto alerts.raise and, when NATS cannot carry
// the event, POSTs it to compliance-engine's HMAC-only alert intake
// ([AlertIntakePath]). A notification is logged as lost only when both fail.
//
// # What it never sends
//
// The pre/post images and custom-field values (they may hold secrets): only the
// changed field NAMES, the object's label and a link.
//
// # Bursts
//
// Discovery intake and sync connections can write thousands of rows in one
// request. Changes whose source is `intake:*` or `sync:*` are left out unless
// at least one of the tenant's enabled Inventory-changes rules includes them,
// and nothing at all is read or raised for a tenant with no such rule. A
// request raises at most [MaxEventsPerRequest] events; the rest are logged.
// notification-service remains the authority on which rule routes what — this
// pre-check only avoids raising events no rule could take.
package changenotify

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// AlertType is the registry id this package raises.
const AlertType = "object_changed"

// MaxEventsPerRequest bounds what one request can raise.
const MaxEventsPerRequest = 250

// lookback bounds the object_changes read to recent partitions; a request
// longer than this loses only the notifications of its oldest changes.
const lookback = time.Hour

// Publisher raises one alert event.
type Publisher interface {
	Raise(events.AlertRaiseEvent) error
}

// PublisherFunc adapts a function to [Publisher].
type PublisherFunc func(events.AlertRaiseEvent) error

// Raise implements [Publisher].
func (f PublisherFunc) Raise(ev events.AlertRaiseEvent) error { return f(ev) }

// NATSPublisher publishes onto alerts.raise, with no fallback. Production
// uses [FallbackPublisher].
func NATSPublisher(c *events.NATSClient) Publisher {
	return PublisherFunc(func(ev events.AlertRaiseEvent) error {
		return events.PublishJSON(c, events.SubjectAlertsRaise, ev)
	})
}

// Notifier turns committed changes into object_changed events.
type Notifier struct {
	db  *sql.DB
	pub atomic.Pointer[Publisher]
	// Synchronous flushes before the request returns instead of in a
	// goroutine after it. Tests set it; production leaves it false so the
	// response is never held up by the notification.
	Synchronous bool
}

// New returns a notifier reading object_changes through db. It raises nothing
// until [Notifier.SetPublisher] is called.
func New(db *sql.DB) *Notifier { return &Notifier{db: db} }

// SetPublisher sets (or, with nil, clears) where events go.
func (n *Notifier) SetPublisher(p Publisher) {
	if p == nil {
		n.pub.Store(nil)
		return
	}
	n.pub.Store(&p)
}

func (n *Notifier) publisher() Publisher {
	if p := n.pub.Load(); p != nil {
		return *p
	}
	return nil
}

// Middleware collects the changes a request records and, once the handler has
// returned, raises the events for the committed ones. Mount it on the router
// before any route group, so every recorder call site — the DCIM routes, the
// HMAC-only sync and import surfaces, posted sightings — is covered without
// each one being edited.
//
// A nil notifier's middleware passes every request through untouched (a
// process, or a test, that installed none).
func (n *Notifier) Middleware() gin.HandlerFunc {
	if n == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		// A request id is what ties a change row to this request. The
		// changes.Middleware on a DCIM group replaces it with its own (the
		// caller's X-Request-ID or a fresh one); routes without that
		// middleware — the internal sync surface — get this one.
		if _, ok := changes.RequestIDFrom(ctx); !ok {
			ctx = changes.WithRequestID(ctx, uuid.New())
		}
		ctx, col := changes.WithCollector(ctx)
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		noted := col.Drain()
		if len(noted) == 0 || n.publisher() == nil {
			return
		}
		flushCtx := context.WithoutCancel(ctx)
		if n.Synchronous {
			n.Flush(flushCtx, noted)
			return
		}
		go n.Flush(flushCtx, noted)
	}
}

// Flush raises the events for what a collector noted. Errors are logged: a
// notification that cannot be raised must never fail the change it describes.
func (n *Notifier) Flush(ctx context.Context, noted []changes.Noted) {
	pub := n.publisher()
	if pub == nil {
		return
	}
	for _, req := range noted {
		evs, err := n.Events(ctx, req)
		if err != nil {
			log.Printf("[changenotify] tenant=%s request=%s: %v", req.TenantID, req.RequestID, err)
			continue
		}
		for _, ev := range evs {
			if err := pub.Raise(ev); err != nil {
				// The publisher has already tried every rail it has (NATS,
				// then the HTTP fallback): this notification reached nobody,
				// and nothing retries it.
				log.Printf("[changenotify] CHANGE NOTIFICATION LOST (tenant=%s %s/%s %s request=%s): %v",
					ev.TenantID, ev.SubjectType, ev.SubjectID, ev.Metadata["action"], req.RequestID, err)
			}
		}
	}
}

// ruleDemand is what the tenant's enabled Inventory-changes rules can take.
type ruleDemand struct {
	rules         int
	includeIntake bool
	includeSync   bool
}

// changeRow is one committed object_changes row, without its images.
type changeRow struct {
	kind          dcim.ObjectKind
	objectID      uuid.UUID
	action        changes.Action
	source        string
	userID        *uuid.UUID
	userName      string
	changedFields []string
	label         string
	relatedKind   dcim.ObjectKind
	relatedID     *uuid.UUID
}

// labelKeys are the image fields that name an object, best first. Read from
// the images in SQL so the images themselves never leave the database.
var labelKeys = []string{"name", "label", "display_name", "hostname", "prefix", "address", "cid", "vid", "slug"}

func labelExpr() string {
	parts := make([]string, 0, 2*len(labelKeys))
	for _, k := range labelKeys {
		parts = append(parts, fmt.Sprintf("NULLIF(postchange_data->>'%s', '')", k), fmt.Sprintf("NULLIF(prechange_data->>'%s', '')", k))
	}
	return "COALESCE(" + strings.Join(parts, ", ") + ", '')"
}

// Events builds the object_changed events for one noted request: committed
// rows only, the noted keys only, one event per (kind, object, action), intake
// and sync changes only when a rule includes them, at most
// MaxEventsPerRequest.
func (n *Notifier) Events(ctx context.Context, req changes.Noted) ([]events.AlertRaiseEvent, error) {
	var demand ruleDemand
	var rows []changeRow
	err := database.WithTenantTx(ctx, n.db, req.TenantID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*),
			       COALESCE(bool_or(COALESCE((change_filter->>'include_intake')::boolean, false)), false),
			       COALESCE(bool_or(COALESCE((change_filter->>'include_sync')::boolean, false)), false)
			  FROM public.tenant_notification_rules
			 WHERE tenant_id = $1 AND enabled = true AND alert_type = $2`,
			req.TenantID, AlertType).Scan(&demand.rules, &demand.includeIntake, &demand.includeSync); err != nil {
			return fmt.Errorf("read routing rules: %w", err)
		}
		if demand.rules == 0 {
			return nil // nothing could route an event: read nothing, raise nothing
		}
		q, err := tx.QueryContext(ctx, `
			SELECT object_kind, object_id, action, source, user_id, COALESCE(user_name, ''), changed_fields,
			       `+labelExpr()+`, COALESCE(related_kind, ''), related_id
			  FROM public.object_changes
			 WHERE tenant_id = $1 AND request_id = $2 AND created_at >= now() - $3::interval
			 ORDER BY created_at, id`,
			req.TenantID, req.RequestID, fmt.Sprintf("%d seconds", int(lookback.Seconds())))
		if err != nil {
			return fmt.Errorf("read object_changes: %w", err)
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var r changeRow
			var kind, action, related string
			var uid, rid uuid.NullUUID
			if err := q.Scan(&kind, &r.objectID, &action, &r.source, &uid, &r.userName,
				pq.Array(&r.changedFields), &r.label, &related, &rid); err != nil {
				return fmt.Errorf("scan object_changes: %w", err)
			}
			r.kind, r.action, r.relatedKind = dcim.ObjectKind(kind), changes.Action(action), dcim.ObjectKind(related)
			if uid.Valid {
				u := uid.UUID
				r.userID = &u
			}
			if rid.Valid {
				u := rid.UUID
				r.relatedID = &u
			}
			rows = append(rows, r)
		}
		return q.Err()
	})
	if err != nil || demand.rules == 0 {
		return nil, err
	}
	return buildEvents(req, rows, demand), nil
}

// buildEvents folds committed rows into events. Pure, so the folding rules are
// unit-tested without a database.
func buildEvents(req changes.Noted, rows []changeRow, demand ruleDemand) []events.AlertRaiseEvent {
	wanted := make(map[changes.NotedKey]bool, len(req.Keys))
	for _, k := range req.Keys {
		wanted[k] = true
	}
	type group struct {
		last   changeRow
		fields map[string]bool
		label  string
	}
	groups := map[changes.NotedKey]*group{}
	var order []changes.NotedKey
	for _, r := range rows {
		k := changes.NotedKey{Kind: r.kind, ObjectID: r.objectID, Action: r.action}
		if !wanted[k] || !demand.admits(r.source) {
			continue
		}
		g := groups[k]
		if g == nil {
			g = &group{fields: map[string]bool{}}
			groups[k] = g
			order = append(order, k)
		}
		g.last = r
		for _, f := range r.changedFields {
			g.fields[f] = true
		}
		if r.label != "" {
			g.label = r.label
		}
	}

	out := make([]events.AlertRaiseEvent, 0, len(order))
	for i, k := range order {
		if i == MaxEventsPerRequest {
			log.Printf("[changenotify] tenant=%s request=%s: %d changed objects, raising the first %d",
				req.TenantID, req.RequestID, len(order), MaxEventsPerRequest)
			break
		}
		g := groups[k]
		fields := make([]string, 0, len(g.fields))
		for f := range g.fields {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		out = append(out, eventFor(req, k, g.last, g.label, fields))
	}
	return out
}

// admits reports whether a change from source is wanted by any rule.
func (d ruleDemand) admits(source string) bool {
	switch {
	case strings.HasPrefix(source, "intake:"):
		return d.includeIntake
	case strings.HasPrefix(source, "sync:"):
		return d.includeSync
	}
	return true
}

// eventNamespace keys the deterministic event id, so re-raising the same
// change (a retried flush) carries the same id end to end.
var eventNamespace = uuid.MustParse("6b0d1c57-58a4-4c1e-9d0e-3f7a4c2e8b11")

var actionVerb = map[changes.Action]string{
	changes.ActionCreate: "created",
	changes.ActionUpdate: "updated",
	changes.ActionDelete: "deleted",
}

func eventFor(req changes.Noted, k changes.NotedKey, last changeRow, label string, fields []string) events.AlertRaiseEvent {
	kindLabel := k.Kind.Label()
	if kindLabel == "" {
		kindLabel = string(k.Kind)
	}
	verb := actionVerb[k.Action]
	subject := label
	if subject == "" {
		subject = k.ObjectID.String()
	}

	var actor any // JSON null when nobody is behind the change
	who := last.source
	if last.userID != nil {
		actor = map[string]any{"user_id": last.userID.String(), "user_name": last.userName}
		if last.userName != "" {
			who = last.userName
		} else {
			who = "a user"
		}
	}

	var objectLabel any
	if label != "" {
		objectLabel = label
	}
	var link any
	if l := Link(k.Kind, k.ObjectID, k.Action, last.relatedKind, last.relatedID); l != "" {
		link = l
	}

	msg := fmt.Sprintf("%s %s %s %s", who, verb, strings.ToLower(kindLabel), subject)
	if k.Action == changes.ActionUpdate && len(fields) > 0 {
		shown := fields
		more := ""
		if len(shown) > 10 {
			more = fmt.Sprintf(" and %d more", len(shown)-10)
			shown = shown[:10]
		}
		msg += " — changed " + strings.Join(shown, ", ") + more
	}

	id := k.ObjectID
	return events.AlertRaiseEvent{
		EventID: uuid.NewSHA1(eventNamespace, []byte(strings.Join([]string{
			req.TenantID.String(), req.RequestID.String(), string(k.Kind), k.ObjectID.String(), string(k.Action)}, "|"))),
		TenantID:     req.TenantID,
		AlertType:    AlertType,
		Source:       "inventory-service",
		SubjectType:  string(k.Kind),
		SubjectID:    &id,
		SubjectLabel: label,
		Severity:     "info",
		Title:        fmt.Sprintf("%s %s: %s", kindLabel, verb, subject),
		Message:      msg,
		Metadata: map[string]any{
			"object_kind":    string(k.Kind),
			"object_id":      k.ObjectID.String(),
			"action":         string(k.Action),
			"actor":          actor,
			"source":         last.source,
			"request_id":     req.RequestID.String(),
			"changed_fields": fields,
			"object_label":   objectLabel,
			"link":           link,
		},
		Timestamp: time.Now().UTC(),
	}
}

// detailPages are the object kinds with a page of their own in the web UI,
// keyed to its path prefix (frontend-v2's App.tsx routes; the five object pages
// are frontend-v2/src/sections/inventory/object-pages/object-links.ts).
// detail_pages_test.go pins this table against those two files.
var detailPages = map[dcim.ObjectKind]string{
	dcim.ObjectKindAsset:     "/inventory/assets/",
	dcim.ObjectKindRack:      "/inventory/racks/",
	dcim.ObjectKindSite:      "/inventory/sites/",
	dcim.ObjectKindCluster:   "/inventory/clusters/",
	dcim.ObjectKindPrefix:    "/inventory/prefixes/",
	dcim.ObjectKindVlan:      "/inventory/vlans/",
	dcim.ObjectKindCircuit:   "/inventory/circuits/",
	dcim.ObjectKindCable:     "/inventory/cables/",
	dcim.ObjectKindInterface: "/inventory/interfaces/",
}

// Link is the web-UI path a notification about a change points at: the
// object's own page; for a kind without one (an IP address, a MAC address, a
// journal entry) the page of the object it belongs to; for a deleted
// object, which has no page any more, its parent's. Empty when there is no
// page to point at — the event then says so with a null link rather than a
// path that 404s.
func Link(kind dcim.ObjectKind, id uuid.UUID, action changes.Action, relatedKind dcim.ObjectKind, relatedID *uuid.UUID) string {
	if p, ok := detailPages[kind]; ok && action != changes.ActionDelete {
		return p + id.String()
	}
	if relatedID != nil {
		if p, ok := detailPages[relatedKind]; ok {
			return p + relatedID.String()
		}
	}
	return ""
}
