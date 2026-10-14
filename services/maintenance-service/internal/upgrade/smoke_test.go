package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCheckVersions(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"all on target", `{"self":{"chart":"4.6.0"},"services":[{"service":"auth-service","chart":"4.6.0","status":"healthy"},{"service":"web","chart":"unknown","status":"healthy"}]}`, ""},
		{"one behind", `{"self":{"chart":"4.6.0"},"services":[{"service":"auth-service","chart":"4.5.0","status":"healthy"}]}`, "auth-service on 4.5.0"},
		{"one unreachable", `{"self":{"chart":"4.6.0"},"services":[{"service":"cbom-service","chart":"unknown","status":"unreachable"}]}`, "cbom-service unreachable"},
		{"aggregator itself behind", `{"self":{"chart":"4.5.0"},"services":[]}`, "monitoring-service on 4.5.0"},
		{"nothing reports", `{"self":{"chart":"unknown"},"services":[{"service":"a","chart":"unknown","status":"healthy"}]}`, "no service reported"},
		{"garbage", `[1]`, "cannot read"},
	} {
		err := CheckVersions(json.RawMessage(tc.body), "v4.6.0")
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

type seqVersions struct {
	mu     sync.Mutex
	bodies []string
	n      int
}

func (s *seqVersions) Versions(context.Context) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.n
	s.n++
	if i >= len(s.bodies) {
		i = len(s.bodies) - 1
	}
	if s.bodies[i] == "" {
		return nil, errors.New("monitoring-service unreachable")
	}
	return json.RawMessage(s.bodies[i]), nil
}

func TestVersionSmoke_PollsUntilAligned(t *testing.T) {
	src := &seqVersions{bodies: []string{"",
		`{"self":{"chart":"4.6.0"},"services":[{"service":"a","chart":"4.5.0","status":"healthy"}]}`,
		`{"self":{"chart":"4.6.0"},"services":[{"service":"a","chart":"4.6.0","status":"healthy"}]}`}}
	if err := (VersionSmoke{Source: src, Interval: time.Millisecond, Timeout: time.Second}).Smoke(context.Background(), "4.6.0"); err != nil {
		t.Fatal(err)
	}
	stuck := &seqVersions{bodies: []string{`{"self":{"chart":"4.6.0"},"services":[{"service":"a","chart":"4.5.0","status":"healthy"}]}`}}
	err := (VersionSmoke{Source: stuck, Interval: time.Millisecond, Timeout: 30 * time.Millisecond}).Smoke(context.Background(), "4.6.0")
	if err == nil || !strings.Contains(err.Error(), "a on 4.5.0") {
		t.Fatalf("stuck: %v", err)
	}
	if err := (VersionSmoke{}).Smoke(context.Background(), "4.6.0"); err == nil {
		t.Fatal("no source must fail")
	}
}
