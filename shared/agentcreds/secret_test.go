package agentcreds

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestGenerateSecret_IsRandom32Bytes(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateSecret()
	if a == b {
		t.Fatal("two generated secrets are equal")
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(raw) != SecretBytes {
		t.Fatalf("secret decodes to %d bytes (err %v), want %d", len(raw), err, SecretBytes)
	}
}

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func sealWith(t *testing.T, job, secret string) map[string]interface{} {
	t.Helper()
	env, err := Seal(map[string]interface{}{"password": "pw"}, job, secret)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// A collector that has not rotated opens with its registration key — the
// pre-change behaviour, and the migration path.
func TestCandidates_RegistrationKeyFallbackWhenNoAgentSecret(t *testing.T) {
	var s SecretState
	got := s.Candidates("reg-key", t0)
	if len(got) != 1 || got[0] != "reg-key" {
		t.Fatalf("Candidates = %v, want [reg-key]", got)
	}
	env := sealWith(t, "job-1", "reg-key")
	if _, err := OpenAny(env, "job-1", got); err != nil {
		t.Fatalf("pre-change collector cannot open a registration-key envelope: %v", err)
	}
}

// Once an agent secret exists the registration key is no longer a candidate,
// even if it is still in an environment variable.
func TestCandidates_AgentSecretReplacesRegistrationKey(t *testing.T) {
	s := SecretState{Secret: "agent-secret", Version: 1}
	got := s.Candidates("spent-reg-key", t0)
	if len(got) != 1 || got[0] != "agent-secret" {
		t.Fatalf("Candidates = %v, want only the agent secret", got)
	}
	env := sealWith(t, "job-1", "spent-reg-key")
	if _, err := OpenAny(env, "job-1", got); err == nil {
		t.Fatal("an envelope sealed under the spent registration key opened on a collector that holds an agent secret")
	}
	env = sealWith(t, "job-1", "agent-secret")
	if _, err := OpenAny(env, "job-1", got); err != nil {
		t.Fatalf("agent-secret envelope: %v", err)
	}
}

func TestRotate_PreviousStaysValidForTheWindowThenNot(t *testing.T) {
	s := SecretState{Secret: "old", Version: 1}
	s = s.Rotate("new", 2, "ignored-reg-key", t0)
	if s.Secret != "new" || s.Version != 2 || s.Previous != "old" {
		t.Fatalf("Rotate = %+v", s)
	}
	oldEnv := sealWith(t, "j", "old")
	newEnv := sealWith(t, "j", "new")

	inside := t0.Add(PreviousSecretWindow - time.Second)
	for name, env := range map[string]map[string]interface{}{"old": oldEnv, "new": newEnv} {
		if _, err := OpenAny(env, "j", s.Candidates("", inside)); err != nil {
			t.Errorf("%s envelope inside the window: %v", name, err)
		}
	}
	after := t0.Add(PreviousSecretWindow)
	if _, err := OpenAny(oldEnv, "j", s.Candidates("", after)); err == nil {
		t.Error("the replaced secret still opens an envelope after the window")
	}
	if _, err := OpenAny(newEnv, "j", s.Candidates("", after)); err != nil {
		t.Errorf("the current secret stopped working after the window: %v", err)
	}
}

// The first rotation of a pre-change collector keeps its registration key as
// the previous secret, so a job sealed just before the migration still opens.
func TestRotate_FromRegistrationKeyMigration(t *testing.T) {
	var s SecretState
	s = s.Rotate("first-secret", 1, "reg-key", t0)
	if s.Previous != "reg-key" {
		t.Fatalf("Previous = %q, want the registration key", s.Previous)
	}
	env := sealWith(t, "j", "reg-key")
	if _, err := OpenAny(env, "j", s.Candidates("", t0.Add(time.Hour))); err != nil {
		t.Fatalf("in-flight registration-key envelope after migration: %v", err)
	}
	if _, err := OpenAny(env, "j", s.Candidates("", t0.Add(PreviousSecretWindow+time.Second))); err == nil {
		t.Fatal("registration key still opens envelopes after the migration window")
	}
}

func TestPrune(t *testing.T) {
	s := SecretState{Secret: "new", Version: 2}.Rotate("newer", 3, "", t0)
	if _, changed := s.Prune(t0.Add(time.Hour)); changed {
		t.Error("Prune dropped a secret still inside its window")
	}
	p, changed := s.Prune(t0.Add(PreviousSecretWindow))
	if !changed || p.Previous != "" || p.Secret != "newer" {
		t.Errorf("Prune = %+v, %v", p, changed)
	}
}

func TestSecretStateMarshalRoundTrip(t *testing.T) {
	s := SecretState{Secret: "a", Version: 4}.Rotate("b", 5, "", t0)
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSecretState(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "b" || got.Version != 5 || got.Previous != "a" || !got.PreviousUntil.Equal(s.PreviousUntil) {
		t.Fatalf("round trip = %+v, want %+v", got, s)
	}
	if _, err := ParseSecretState([]byte("{")); err == nil {
		t.Error("garbage parsed")
	}
}

func TestOpenAny_NotSealedAndNoSecret(t *testing.T) {
	if _, err := OpenAny(map[string]interface{}{"password": "x"}, "j", []string{"s"}); err != ErrNotSealed {
		t.Fatalf("unsealed payload: %v, want ErrNotSealed", err)
	}
	env := sealWith(t, "j", "")
	if _, err := OpenAny(env, "j", nil); err != nil {
		t.Fatalf("job-id-only envelope with no secrets: %v", err)
	}
}
