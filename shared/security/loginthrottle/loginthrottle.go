// Package loginthrottle throttles credential-checking endpoints by client
// address and by account, BEFORE the handler runs.
//
// It exists for the platform-admin login (admin-service), the front door of the
// cross-tenant control plane. Account lockout alone is not a defence there: it
// is also a lock-out denial of service, because anyone who can reach the form
// can lock the real administrator out by guessing wrong passwords. Throttling
// in front of the handler means a flood is refused (429) without ever reaching
// password verification or the lockout counter.
//
// Two independent fixed-window counters are kept:
//
//   - per client IP: stops one source from spraying many accounts;
//   - per account (lower-cased email): stops many sources from hammering one.
//
// The IP window is charged first. A request refused for its address is NOT
// charged to the account, so a single noisy source cannot burn the victim's
// per-account budget and shut the real administrator out through the limiter.
//
// Counters live in Redis when a client is supplied. If Redis is absent, or a
// call to it fails, the same decision is taken from an in-process counter, so
// the limiter degrades to a per-pod limit instead of vanishing (a silent bypass)
// or refusing every sign-in (a self-inflicted outage).
package loginthrottle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/shared/cache"
)

const (
	// DefaultEmailLimit is the attempts per window allowed against one account.
	DefaultEmailLimit = 5
	// DefaultWindow is the fixed window both counters use.
	DefaultWindow = time.Minute

	// maxBodyPeek bounds how much of a request body is read to find the email.
	maxBodyPeek = 64 << 10

	keyPrefix = "admin_login_rl:"

	// memSweepThreshold: when the in-process map grows past this many keys,
	// expired entries are dropped on the next hit.
	memSweepThreshold = 4096
)

// Limiter counts attempts per IP and per account.
type Limiter struct {
	rdb        *redis.Client
	ipLimit    int
	emailLimit int
	window     time.Duration

	mu  sync.Mutex
	mem map[string]*memEntry
	now func() time.Time
}

type memEntry struct {
	count   int64
	expires time.Time
}

// New builds a Limiter. rdb may be nil (in-process counters only). emailLimit
// <= 0 and window <= 0 select the defaults. The per-IP limit is twice the
// per-account limit, because several administrators can share one egress
// address while an account is only ever one person's.
func New(rdb *redis.Client, emailLimit int, window time.Duration) *Limiter {
	if emailLimit <= 0 {
		emailLimit = DefaultEmailLimit
	}
	if window <= 0 {
		window = DefaultWindow
	}
	return &Limiter{
		rdb:        rdb,
		ipLimit:    emailLimit * 2,
		emailLimit: emailLimit,
		window:     window,
		mem:        map[string]*memEntry{},
		now:        time.Now,
	}
}

// NewFromCache builds a Limiter over the service's cache client, which may be
// nil when Redis was unavailable at start-up.
func NewFromCache(c *cache.Client, emailLimit int, window time.Duration) *Limiter {
	var rdb *redis.Client
	if c != nil {
		rdb = c.Redis()
	}
	return New(rdb, emailLimit, window)
}

// AllowIP charges one attempt to the client address.
func (l *Limiter) AllowIP(ctx context.Context, ip string) (bool, time.Duration) {
	if strings.TrimSpace(ip) == "" {
		ip = "unknown"
	}
	return l.allow(ctx, keyPrefix+"ip:"+ip, l.ipLimit)
}

// AllowEmail charges one attempt to the account. An empty email is not charged.
func (l *Limiter) AllowEmail(ctx context.Context, email string) (bool, time.Duration) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return true, 0
	}
	return l.allow(ctx, keyPrefix+"email:"+email, l.emailLimit)
}

func (l *Limiter) allow(ctx context.Context, key string, limit int) (bool, time.Duration) {
	count, retry, err := l.hit(ctx, key)
	if err != nil {
		logrus.WithError(err).Warn("login throttle: Redis unavailable, using the in-process counter")
		count, retry = l.hitMemory(key)
	}
	if count > int64(limit) {
		return false, retry
	}
	return true, 0
}

// hit counts one request in a FIXED window: the expiry is set only when the key
// is created (SET NX), so retrying under a 429 does not extend the lock. See
// auth-service's rate limiter for the history of that bug.
func (l *Limiter) hit(ctx context.Context, key string) (int64, time.Duration, error) {
	if l.rdb == nil {
		return 0, 0, fmt.Errorf("no redis client")
	}
	pipe := l.rdb.TxPipeline()
	pipe.SetNX(ctx, key, 0, l.window)
	incr := pipe.Incr(ctx, key)
	pttl := pipe.PTTL(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, 0, err
	}
	retry := (pttl.Val() + time.Second - 1).Truncate(time.Second)
	if pttl.Val() <= 0 {
		retry = l.window
	}
	return incr.Val(), retry, nil
}

func (l *Limiter) hitMemory(key string) (int64, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.mem) > memSweepThreshold {
		for k, e := range l.mem {
			if !e.expires.After(now) {
				delete(l.mem, k)
			}
		}
	}
	e, ok := l.mem[key]
	if !ok || !e.expires.After(now) {
		e = &memEntry{expires: now.Add(l.window)}
		l.mem[key] = e
	}
	e.count++
	retry := e.expires.Sub(now).Truncate(time.Second)
	if e.expires.Sub(now)%time.Second != 0 {
		retry += time.Second
	}
	return e.count, retry
}

// Middleware throttles a credential endpoint. It charges the client IP and,
// when byEmail is set, the account named by the JSON body's "email" field.
// Both charges happen before the handler, so a refused request never reaches
// password verification or the lockout counter.
//
// The body is restored for the handler; a body that is not JSON, or has no
// email, is charged to the IP only (the handler will reject it).
func (l *Limiter) Middleware(byEmail bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ok, retry := l.AllowIP(c.Request.Context(), c.ClientIP()); !ok {
			refuse(c, retry)
			return
		}
		if byEmail {
			if ok, retry := l.AllowEmail(c.Request.Context(), peekEmail(c)); !ok {
				refuse(c, retry)
				return
			}
		}
		c.Next()
	}
}

func refuse(c *gin.Context, retry time.Duration) {
	secs := int(retry.Seconds())
	if secs < 1 {
		secs = 1
	}
	c.Header("Retry-After", strconv.Itoa(secs))
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error":       "Too many sign-in attempts. Please try again later.",
		"retry_after": secs,
	})
}

// peekEmail reads the "email" field of a JSON body and puts the body back.
func peekEmail(c *gin.Context) string {
	if c.Request.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyPeek+1))
	// Restore everything we consumed plus whatever was not read.
	c.Request.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(raw), c.Request.Body), c.Request.Body}
	if err != nil || len(raw) > maxBodyPeek {
		return ""
	}
	var b struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(raw, &b) != nil {
		return ""
	}
	return b.Email
}
