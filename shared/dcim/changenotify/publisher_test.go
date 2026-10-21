package changenotify

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type link bool

func (l link) IsConnected() bool { return bool(l) }

type capture struct {
	evs []events.AlertRaiseEvent
	err error
}

func (c *capture) Raise(ev events.AlertRaiseEvent) error {
	c.evs = append(c.evs, ev)
	return c.err
}

func sampleEvent() events.AlertRaiseEvent {
	id := uuid.New()
	return events.AlertRaiseEvent{EventID: uuid.New(), TenantID: uuid.New(), AlertType: AlertType,
		SubjectType: "cable", SubjectID: &id, Severity: "info", Title: "Cable updated: C-1"}
}

// The two rails in order: NATS when it takes the event, HTTP only when NATS
// cannot, an error only when both failed. Mutations: return natsErr instead of
// calling the intake → "NATS refuses" and "no NATS" go red; return nil after a
// failed intake → "both fail" goes red.
func TestFallbackPublisher_Rails(t *testing.T) {
	natsDown := errors.New("nats: no responders")
	cases := []struct {
		name       string
		f          func(intake *capture) fallback
		intakeErr  error
		wantNATS   int
		wantIntake int
		wantErr    string
	}{
		{"NATS takes it", func(in *capture) fallback {
			return fallback{link: link(true), publish: func(events.AlertRaiseEvent) error { return nil }, intake: in}
		}, nil, 1, 0, ""},
		{"NATS refuses", func(in *capture) fallback {
			return fallback{link: link(true), publish: func(events.AlertRaiseEvent) error { return natsDown }, intake: in}
		}, nil, 1, 1, ""},
		{"NATS disconnected", func(in *capture) fallback {
			return fallback{link: link(false), publish: func(events.AlertRaiseEvent) error { t.Fatal("published on a disconnected client"); return nil }, intake: in}
		}, nil, 0, 1, ""},
		{"no NATS", func(in *capture) fallback { return fallback{intake: in} }, nil, 0, 1, ""},
		{"both fail", func(in *capture) fallback {
			return fallback{link: link(true), publish: func(events.AlertRaiseEvent) error { return natsDown }, intake: in}
		}, errors.New("compliance-engine answered 503"), 1, 1, "NATS and HTTP both failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			intake := &capture{err: c.intakeErr}
			f := c.f(intake)
			natsCalls := 0
			if f.publish != nil {
				inner := f.publish
				f.publish = func(ev events.AlertRaiseEvent) error { natsCalls++; return inner(ev) }
			}
			err := f.Raise(sampleEvent())
			if natsCalls != c.wantNATS || len(intake.evs) != c.wantIntake {
				t.Fatalf("NATS calls = %d (want %d), HTTP calls = %d (want %d)", natsCalls, c.wantNATS, len(intake.evs), c.wantIntake)
			}
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
		})
	}
}

// With no HTTP intake a NATS failure is a loss, and says so.
func TestFallbackPublisher_NoIntake(t *testing.T) {
	err := FallbackPublisher(nil, nil).Raise(sampleEvent())
	if err == nil || !strings.Contains(err.Error(), "no HTTP fallback") {
		t.Fatalf("err = %v", err)
	}
}

// The HTTP rail posts the event, unchanged, to compliance-engine's intake,
// names the tenant in X-Tenant-ID and signs the request after setting it (the
// header is covered by the signature). Mutations: drop the X-Tenant-ID header
// → the verifier refuses; skip Sign → 401.
func TestHTTPAlertIntake_PostsASignedEvent(t *testing.T) {
	const secret = "changenotify-test-secret"
	verifier := serviceauth.NewVerifier(secret)
	var got events.AlertRaiseEvent
	var gotTenant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != AlertIntakePath {
			http.Error(w, "wrong route "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		gotTenant = r.Header.Get(serviceauth.HeaderTenantID)
		if !verifyRequest(verifier, w, r) {
			http.Error(w, `{"error":"a signed service call is required"}`, http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"outcome":"notified"}`))
	}))
	defer srv.Close()

	ev := sampleEvent()
	h := &HTTPAlertIntake{BaseURL: srv.URL + "/", Client: srv.Client(), Sign: serviceauth.NewSigner(secret).SignRequest}
	if err := h.Raise(ev); err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if gotTenant != ev.TenantID.String() {
		t.Fatalf("X-Tenant-ID = %q, want %s", gotTenant, ev.TenantID)
	}
	if got.EventID != ev.EventID || got.TenantID != ev.TenantID || got.AlertType != AlertType || got.SubjectID == nil || *got.SubjectID != *ev.SubjectID {
		t.Fatalf("intake received %+v, want %+v", got, ev)
	}

	unsigned := &HTTPAlertIntake{BaseURL: srv.URL, Client: srv.Client()}
	if err := unsigned.Raise(ev); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an unsigned post: err = %v, want the 401", err)
	}
}

func TestHTTPAlertIntake_Non2xxIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"the alert could not be raised"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	h := &HTTPAlertIntake{BaseURL: srv.URL, Client: srv.Client(), Sign: func(*http.Request) {}}
	if err := h.Raise(sampleEvent()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want the 500", err)
	}
}

// verifyRequest runs the service-auth verifier the receiving route uses.
func verifyRequest(v *serviceauth.Verifier, w http.ResponseWriter, r *http.Request) bool {
	c, _ := gin.CreateTestContext(w)
	c.Request = r
	return v.Verify(c)
}
