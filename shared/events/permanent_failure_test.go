package events

import (
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
)

// A poison message must not be redelivered. pcap-processor subscribes with
// MaxDeliver=3, so before this every unprocessable capture cost the
// single-replica, all-tenant pod three full processing passes — one tenant's
// bad upload became a cross-tenant outage three times over (H11).
//
// This drives settleMessage, the code that actually chooses between Ack, Nak
// and Term. Testing IsPermanent on its own would stay green with that choice
// deleted, which is the wiring-vs-helper trap.

type settleRecorder struct{ acked, naked, termed int }

func (r *settleRecorder) Ack(...nats.AckOpt) error  { r.acked++; return nil }
func (r *settleRecorder) Nak(...nats.AckOpt) error  { r.naked++; return nil }
func (r *settleRecorder) Term(...nats.AckOpt) error { r.termed++; return nil }

func TestSettleMessage(t *testing.T) {
	transient := errors.New("database is down")

	cases := []struct {
		name                       string
		err                        error
		panicked                   bool
		wantAck, wantNak, wantTerm int
	}{
		{name: "success acks", wantAck: 1},
		{name: "transient error is redelivered", err: transient, wantNak: 1},
		{name: "permanent error is terminated", err: Permanent(transient), wantTerm: 1},
		{name: "wrapped permanent error is still terminated", err: fmtWrap(Permanent(transient)), wantTerm: 1},
		{name: "panic is terminated", panicked: true, wantTerm: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &settleRecorder{}
			settleMessage(r, "test.subject", tc.err, tc.panicked)
			if r.acked != tc.wantAck || r.naked != tc.wantNak || r.termed != tc.wantTerm {
				t.Errorf("ack=%d nak=%d term=%d, want ack=%d nak=%d term=%d",
					r.acked, r.naked, r.termed, tc.wantAck, tc.wantNak, tc.wantTerm)
			}
		})
	}
}

// The polarity that matters in the other direction: a transient failure must
// STILL be retried. Terminating everything would be the same bug facing the
// other way — a NATS blip or a restarting database would silently drop work.
func TestSettleMessage_TransientFailuresAreNotDropped(t *testing.T) {
	r := &settleRecorder{}
	settleMessage(r, "test.subject", errors.New("dial tcp: connection refused"), false)
	if r.termed != 0 {
		t.Error("a transient error was terminated; work would be lost on a restart")
	}
	if r.naked != 1 {
		t.Errorf("nak count = %d, want 1", r.naked)
	}
}

func TestPermanent_NilStaysNil(t *testing.T) {
	if Permanent(nil) != nil {
		t.Error("Permanent(nil) must be nil, or every success would be terminated")
	}
	if IsPermanent(nil) {
		t.Error("IsPermanent(nil) must be false")
	}
	if IsPermanent(errors.New("ordinary")) {
		t.Error("an unmarked error must not read as permanent")
	}
}

func fmtWrap(err error) error {
	return errors.Join(errors.New("submit results"), err)
}
