package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestChannelRateLimiter_CapsPerChannel(t *testing.T) {
	r := &ChannelRateLimiter{hits: map[uuid.UUID][]time.Time{}, max: 3, window: time.Minute}
	ch := uuid.New()
	other := uuid.New()

	for i := 0; i < 3; i++ {
		if !r.Allow(ch) {
			t.Fatalf("delivery %d should be allowed (under cap)", i+1)
		}
	}
	if r.Allow(ch) {
		t.Errorf("4th delivery should be rate-limited")
	}
	// A different channel has its own budget.
	if !r.Allow(other) {
		t.Errorf("other channel should be allowed independently")
	}
}

func TestChannelRateLimiter_WindowSlides(t *testing.T) {
	r := &ChannelRateLimiter{hits: map[uuid.UUID][]time.Time{}, max: 1, window: time.Minute}
	ch := uuid.New()
	// Pre-seed a hit that's already outside the window.
	r.hits[ch] = []time.Time{time.Now().Add(-2 * time.Minute)}
	if !r.Allow(ch) {
		t.Errorf("stale hit should have aged out of the window")
	}
	if r.Allow(ch) {
		t.Errorf("second hit within window should be limited")
	}
}

func TestChannelRateLimiter_Disabled(t *testing.T) {
	r := &ChannelRateLimiter{hits: map[uuid.UUID][]time.Time{}, max: 0, window: time.Minute}
	ch := uuid.New()
	for i := 0; i < 100; i++ {
		if !r.Allow(ch) {
			t.Fatalf("max<=0 disables limiting; call %d was blocked", i)
		}
	}
}
