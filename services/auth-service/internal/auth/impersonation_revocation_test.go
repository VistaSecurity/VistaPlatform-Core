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

func requireSingleSetExCommand(t *testing.T, recorder *redisCommandRecorder, wantKey string, wantSeconds int64) {
	t.Helper()
	if len(recorder.commands) != 1 {
		t.Fatalf("recorded Redis commands = %v, want exactly one", recorder.commands)
	}
	got := recorder.commands[0]
	if len(got) != 4 {
		t.Fatalf("Redis command args = %#v, want SETEX with 4 args", got)
	}
	if got[0] != "setex" {
		t.Fatalf("Redis command = %v, want setex", got[0])
	}
	if got[1] != wantKey {
		t.Fatalf("Redis key = %v, want %q", got[1], wantKey)
	}
	if got[2] != wantSeconds {
		t.Fatalf("Redis TTL seconds = %v (%T), want %d", got[2], got[2], wantSeconds)
	}
	if got[3] != "1" {
		t.Fatalf("Redis value = %v, want %q", got[3], "1")
	}
}

func TestRevokeJTIWritesSharedRevocationKey(t *testing.T) {
	client, recorder := newRecordingRedisClient(t)
	svc := NewAuthService(nil, nil, client, nil)

	const jti = "impersonation-session-jti"
	if err := svc.RevokeJTI(context.Background(), jti, 15*time.Minute); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	requireSingleSetExCommand(t, recorder, sharedmw.RevokedTokenKey(jti), int64(15*time.Minute/time.Second))
}
func TestRevokeUserAccessWithoutRedisIsNoop(t *testing.T) {
	svc := &AuthService{jwt: NewJWTService("test-secret-key-32-chars-minimum!", time.Minute, time.Hour)}
	if err := svc.RevokeUserAccess(t.Context(), uuid.New()); err != nil {
		t.Fatalf("RevokeUserAccess without Redis returned error: %v", err)
	}
}
