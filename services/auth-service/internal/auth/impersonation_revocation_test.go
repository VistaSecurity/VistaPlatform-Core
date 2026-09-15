package auth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

type redisCommandRecorder struct {
	commands [][]interface{}
}

func (r *redisCommandRecorder) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (r *redisCommandRecorder) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		r.commands = append(r.commands, append([]interface{}(nil), cmd.Args()...))
		return nil
	}
}

func (r *redisCommandRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func newRecordingRedisClient(t *testing.T) (*redis.Client, *redisCommandRecorder) {
	t.Helper()
	recorder := &redisCommandRecorder{}
	client := redis.NewClient(&redis.Options{
		Addr: net.JoinHostPort("127.0.0.1", "0"),
	})
	client.AddHook(recorder)
	t.Cleanup(func() { _ = client.Close() })
	return client, recorder
}

// requireSingleRevocationSetCommand pins the wire shape of a revocation write:
// `SET <key> "1" EX <seconds>` — the modern spelling of SETEX (go-redis
// deprecated SetEx; SET ... EX is what Redis has recommended since 2.6.12).
// What matters to the readers is the KEY format and that a TTL is set, so
// those are asserted exactly.
func requireSingleRevocationSetCommand(t *testing.T, recorder *redisCommandRecorder, wantKey string, wantSeconds int64) {
	t.Helper()
	if len(recorder.commands) != 1 {
		t.Fatalf("recorded Redis commands = %v, want exactly one", recorder.commands)
	}
	got := recorder.commands[0]
	if len(got) != 5 {
		t.Fatalf("Redis command args = %#v, want SET <key> <value> EX <seconds> (5 args)", got)
	}
	if got[0] != "set" {
		t.Fatalf("Redis command = %v, want set", got[0])
	}
	if got[1] != wantKey {
		t.Fatalf("Redis key = %v, want %q", got[1], wantKey)
	}
	if got[2] != "1" {
		t.Fatalf("Redis value = %v, want %q", got[2], "1")
	}
	if got[3] != "ex" {
		t.Fatalf("Redis expiry mode = %v, want ex", got[3])
	}
	if got[4] != wantSeconds {
		t.Fatalf("Redis TTL seconds = %v (%T), want %d", got[4], got[4], wantSeconds)
	}
}

func TestRevokeJTIWritesSharedRevocationKey(t *testing.T) {
	client, recorder := newRecordingRedisClient(t)
	svc := NewAuthService(nil, nil, client, nil)

	const jti = "impersonation-session-jti"
	if err := svc.RevokeJTI(context.Background(), jti, 15*time.Minute); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	requireSingleRevocationSetCommand(t, recorder, sharedmw.RevokedTokenKey(jti), int64(15*time.Minute/time.Second))
}
func TestRevokeUserAccessWithoutRedisIsNoop(t *testing.T) {
	svc := &AuthService{jwt: NewJWTService("test-secret-key-32-chars-minimum!", time.Minute, time.Hour)}
	if err := svc.RevokeUserAccess(t.Context(), uuid.New()); err != nil {
		t.Fatalf("RevokeUserAccess without Redis returned error: %v", err)
	}
}
