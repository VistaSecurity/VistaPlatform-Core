package ssostate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// RFC 7636 Appendix B.
func TestS256Challenge_RFC7636Vector(t *testing.T) {
	got := S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; got != want {
		t.Fatalf("S256Challenge = %q, want %q", got, want)
	}
}

func TestBeginFinish(t *testing.T) {
	ctx := context.Background()
	const prefix = "test:state:"

	begin := func(t *testing.T, s Store) Attempt {
		t.Helper()
		a, err := Begin(ctx, s, prefix, Record{Nonce: "n", Data: map[string]string{"k": "v"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(a.State) < 43 || len(a.Binding) < 43 || a.State == a.Binding {
			t.Fatalf("weak or reused tokens: %+v", a)
		}
		return a
	}

	t.Run("happy path returns the record with the verifier behind the challenge", func(t *testing.T) {
		s := NewMemoryStore()
		a := begin(t, s)
		rec, err := Finish(ctx, s, prefix, a.State, a.Binding)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Nonce != "n" || rec.Data["k"] != "v" {
			t.Fatalf("record lost its context: %+v", rec)
		}
		if len(rec.CodeVerifier) < 43 || S256Challenge(rec.CodeVerifier) != a.CodeChallenge {
			t.Fatalf("challenge %q is not S256 of the stored verifier %q", a.CodeChallenge, rec.CodeVerifier)
		}
		if strings.Contains(rec.BindingHash, a.Binding) {
			t.Fatal("the binding is stored in clear")
		}
	})

	t.Run("no cookie is refused without consuming the state", func(t *testing.T) {
		s := NewMemoryStore()
		a := begin(t, s)
		if _, err := Finish(ctx, s, prefix, a.State, ""); !errors.Is(err, ErrNoBinding) {
			t.Fatalf("err = %v, want ErrNoBinding", err)
		}
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); err != nil {
			t.Fatalf("the real browser was locked out: %v", err)
		}
	})

	t.Run("another attempt's binding is refused and burns the state", func(t *testing.T) {
		s := NewMemoryStore()
		victim := begin(t, s)
		attacker := begin(t, s)
		if _, err := Finish(ctx, s, prefix, attacker.State, victim.Binding); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("err = %v, want ErrBindingMismatch", err)
		}
		if _, err := Finish(ctx, s, prefix, attacker.State, attacker.Binding); !errors.Is(err, ErrUnknownState) {
			t.Fatalf("state survived a refused callback: %v", err)
		}
	})

	t.Run("replay is refused", func(t *testing.T) {
		s := NewMemoryStore()
		a := begin(t, s)
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); err != nil {
			t.Fatal(err)
		}
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); !errors.Is(err, ErrUnknownState) {
			t.Fatalf("replay err = %v, want ErrUnknownState", err)
		}
	})

	t.Run("a record without a binding (pre-upgrade) is refused", func(t *testing.T) {
		s := NewMemoryStore()
		legacy, _ := json.Marshal(map[string]string{"tenant_id": "t", "nonce": "n"})
		_ = s.Put(ctx, prefix+"old", legacy, TTL)
		if _, err := Finish(ctx, s, prefix, "old", "anything"); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("err = %v, want ErrBindingMismatch", err)
		}
	})

	t.Run("expired attempt is refused", func(t *testing.T) {
		s := NewMemoryStore()
		a := begin(t, s)
		s.now = func() time.Time { return time.Now().Add(TTL + time.Second) }
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); !errors.Is(err, ErrUnknownState) {
			t.Fatalf("err = %v, want ErrUnknownState", err)
		}
	})

	t.Run("redis store", func(t *testing.T) {
		f := &hookRedis{vals: map[string]string{}}
		rdb := redis.NewClient(&redis.Options{Addr: "unused:0"})
		rdb.AddHook(f)
		s := NewRedisStore(rdb)
		a := begin(t, s)
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); err != nil {
			t.Fatal(err)
		}
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); !errors.Is(err, ErrUnknownState) {
			t.Fatalf("redis replay err = %v", err)
		}
		f.failing = true
		if _, err := Begin(ctx, s, prefix, Record{}); err == nil {
			t.Fatal("a store outage did not fail Begin")
		}
		if _, err := Finish(ctx, s, prefix, a.State, a.Binding); err == nil || IsRefusal(err) {
			t.Fatalf("a store outage must surface as a store error, got %v", err)
		}
	})

	t.Run("nil store fails closed", func(t *testing.T) {
		if _, err := Begin(ctx, NewRedisStore(nil), prefix, Record{}); err == nil {
			t.Fatal("Begin succeeded without a store")
		}
	})
}

func TestCookie(t *testing.T) {
	ck := Cookie{Name: "b", Path: CallbackPath("https://app.example.test/api/v1/x/sso/My%20IdP/callback?z=1"), Secure: true}
	if ck.Path != "/api/v1/x/sso/My%20IdP/callback" {
		t.Fatalf("path = %q", ck.Path)
	}
	w := httptest.NewRecorder()
	ck.Set(w, "v")
	set := w.Header().Get("Set-Cookie")
	for _, want := range []string{"b=v", "Path=/api/v1/x/sso/My%20IdP/callback", "Max-Age=600", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(set, want) {
			t.Fatalf("Set-Cookie %q lacks %q", set, want)
		}
	}
	w = httptest.NewRecorder()
	ck.Clear(w)
	if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Fatalf("Clear did not expire the cookie: %v", w.Header().Get("Set-Cookie"))
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if ck.Read(r) != "" {
		t.Fatal("Read invented a value")
	}
	r.AddCookie(&http.Cookie{Name: "b", Value: "v"})
	if ck.Read(r) != "v" {
		t.Fatal("Read missed the cookie")
	}
	if CallbackPath("::") != "/" {
		t.Fatal("unparseable URI must fall back to /")
	}
}

// hookRedis answers SET and GETDEL in process (never dials).
type hookRedis struct {
	mu      sync.Mutex
	vals    map[string]string
	failing bool
}

func (f *hookRedis) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("never dials") }
}
func (f *hookRedis) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (f *hookRedis) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failing {
			cmd.SetErr(errors.New("connection refused"))
			return cmd.Err()
		}
		args := cmd.Args()
		switch strings.ToLower(cmd.Name()) {
		case "set":
			v := fmt.Sprint(args[2])
			if b, ok := args[2].([]byte); ok {
				v = string(b)
			}
			f.vals[fmt.Sprint(args[1])] = v
			cmd.(*redis.StatusCmd).SetVal("OK")
		case "getdel":
			k := fmt.Sprint(args[1])
			v, ok := f.vals[k]
			delete(f.vals, k)
			if !ok {
				cmd.SetErr(redis.Nil)
			} else {
				cmd.(*redis.StringCmd).SetVal(v)
			}
		default:
			cmd.SetErr(fmt.Errorf("unsupported %q", cmd.Name()))
		}
		return cmd.Err()
	}
}
