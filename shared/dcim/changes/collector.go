package changes

import (
	"context"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// A Collector remembers which objects a unit of work (one HTTP request, one
// background job's pass, one consumed message) recorded changes for, so that
// something can act on them once the work is over — the change notifier
// (shared/dcim/changenotify) raises `object_changed`
// (standards/alert-registry.yaml) from it.
//
// It is filled by the Postgres recorder ([InTx]) after each successful
// INSERT, and it deliberately remembers only WHICH object changed, never the
// images: a consumer that wants to say what changed re-reads the committed
// rows. That re-read is also how a consumer knows the change COMMITTED — the
// recorder writes inside the caller's transaction and cannot see the outcome,
// so a noted key whose transaction rolled back simply has no row to find.
//
// Keys are deduplicated per (tenant, request id, kind, object, action): a
// request that updates one cable five times notes it once. A change recorded
// without a request id is not noted — nothing could later tell its row apart.
type Collector struct {
	mu   sync.Mutex
	seen map[NotedRequest]map[NotedKey]struct{}
}

// NotedRequest is one (tenant, request id) a collector saw changes for.
type NotedRequest struct {
	TenantID  uuid.UUID
	RequestID uuid.UUID
}

// NotedKey is one object and what happened to it.
type NotedKey struct {
	Kind     dcim.ObjectKind
	ObjectID uuid.UUID
	Action   Action
}

// Noted is everything a collector saw for one (tenant, request id).
type Noted struct {
	NotedRequest
	Keys []NotedKey
}

type collectorKey struct{}

// WithCollector returns ctx carrying a fresh collector. Every change recorded
// through [InTx] under the returned context is noted on it.
func WithCollector(ctx context.Context) (context.Context, *Collector) {
	c := &Collector{seen: map[NotedRequest]map[NotedKey]struct{}{}}
	return context.WithValue(ctx, collectorKey{}, c), c
}

func collectorFrom(ctx context.Context) *Collector {
	c, _ := ctx.Value(collectorKey{}).(*Collector)
	return c
}

// HasCollector reports whether ctx already carries a collector — an enclosing
// unit of work (an HTTP request, a job's unit) that will act on what is noted.
// A nested unit uses that one rather than opening its own, so a change is
// never acted on twice.
func HasCollector(ctx context.Context) bool { return collectorFrom(ctx) != nil }

func (c *Collector) note(row Row) {
	if c == nil || row.RequestID == nil || *row.RequestID == uuid.Nil {
		return
	}
	req := NotedRequest{TenantID: row.TenantID, RequestID: *row.RequestID}
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := c.seen[req]
	if keys == nil {
		keys = map[NotedKey]struct{}{}
		c.seen[req] = keys
	}
	keys[NotedKey{Kind: row.Kind, ObjectID: row.ObjectID, Action: row.Action}] = struct{}{}
}

// Drain returns what the collector noted, in a stable order, and empties it.
func (c *Collector) Drain() []Noted {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	seen := c.seen
	c.seen = map[NotedRequest]map[NotedKey]struct{}{}
	c.mu.Unlock()

	out := make([]Noted, 0, len(seen))
	for req, keys := range seen {
		n := Noted{NotedRequest: req, Keys: make([]NotedKey, 0, len(keys))}
		for k := range keys {
			n.Keys = append(n.Keys, k)
		}
		sort.Slice(n.Keys, func(i, j int) bool {
			a, b := n.Keys[i], n.Keys[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.ObjectID != b.ObjectID {
				return a.ObjectID.String() < b.ObjectID.String()
			}
			return a.Action < b.Action
		})
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID.String() < out[j].TenantID.String()
		}
		return out[i].RequestID.String() < out[j].RequestID.String()
	})
	return out
}
