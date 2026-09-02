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

type captureRedisCommandsHook struct {
	args [][]interface{}
}

func (h *captureRedisCommandsHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *captureRedisCommandsHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.args = append(h.args, cmd.Args())
		return nil
	}
}

func (h *captureRedisCommandsHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			h.args = append(h.args, cmd.Args())
		}
		return nil
	}
}

func newCapturingRedisClient(t *testing.T) (*redis.Client, *captureRedisCommandsHook) {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	t.Cleanup(func() { _ = rdb.Close() })
	hook := &captureRedisCommandsHook{}
	rdb.AddHook(hook)
	return rdb, hook
}

func TestRevokeUserAccessUsesPermanentDenylist(t *testing.T) {
	rdb, hook := newCapturingRedisClient(t)
	svc := &AuthService{
		redis: rdb,
		jwt:   NewJWTService("secret", time.Minute, 7*24*time.Hour),
	}
	userID := uuid.New()

	if err := svc.RevokeUserAccess(context.Background(), userID); err != nil {
		t.Fatalf("RevokeUserAccess: %v", err)
	}

	if len(hook.args) != 1 {
		t.Fatalf("captured %d Redis commands, want 1: %#v", len(hook.args), hook.args)
	}
	want := []interface{}{"set", sharedmw.RevokedUserKey(userID), "1"}
	if got := hook.args[0]; !redisArgsEqual(got, want) {
		t.Fatalf("Redis command = %#v, want %#v", got, want)
	}
}

func TestClearUserAccessRevocationDeletesDenylistKey(t *testing.T) {
	rdb, hook := newCapturingRedisClient(t)
	svc := &AuthService{redis: rdb}
	userID := uuid.New()

	if err := svc.ClearUserAccessRevocation(context.Background(), userID); err != nil {
		t.Fatalf("ClearUserAccessRevocation: %v", err)
	}

	if len(hook.args) != 1 {
		t.Fatalf("captured %d Redis commands, want 1: %#v", len(hook.args), hook.args)
	}
	want := []interface{}{"del", sharedmw.RevokedUserKey(userID)}
	if got := hook.args[0]; !redisArgsEqual(got, want) {
		t.Fatalf("Redis command = %#v, want %#v", got, want)
	}
}

func redisArgsEqual(got, want []interface{}) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
