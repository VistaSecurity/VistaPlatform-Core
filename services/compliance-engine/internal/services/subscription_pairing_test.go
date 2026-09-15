package services

// Each subject in the subscription plan must reach the handler it is FOR.
//
// The plan pairs two slices by index, and the only assertion on that pairing was
// that the slices are the same LENGTH. Swapping two handlers keeps the lengths
// identical and leaves every test green — a certificate event would be handed to
// the asset handler, and nothing would say so until production, where it looks
// like a reconcile that quietly does the wrong work.
//
// Pairing by name is the assertion a length check cannot make. It is done by
// reflection over the function VALUE, so a handler renamed in one place and not
// the other fails here rather than drifting.

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

// wantHandler maps each subscribed subject to the method name that must handle
// it. Written out by hand ON PURPOSE: deriving it from the plan would compare
// the plan with itself.
var wantHandler = map[string]string{
	"compliance.asset.changed":               "handleAssetChanged",
	"compliance.asset.deleted":               "handleAssetDeleted",
	"compliance.certificate.changed":         "handleCertificateChanged",
	"compliance.bulk.asset.changed":          "handleBulkAssetChanged",
	events.SubjectLifecycleCryptoConfigAdded: "handleCryptoConfigAdded",
	events.SubjectLifecycleAssetMerged:       "handleAssetMerged",
}

// handlerName is the method name behind a bound method value, e.g.
// "…(*EventSubscriberService).handleAssetMerged-fm" → "handleAssetMerged".
func handlerName(h events.MessageHandler) string {
	full := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	name := full[strings.LastIndex(full, ".")+1:]
	return strings.TrimSuffix(name, "-fm")
}

func TestSubscriptionPlanPairsEverySubjectWithItsHandler(t *testing.T) {
	s := &EventSubscriberService{}
	subscriptions, handlers := s.subscriptionPlan()

	if len(subscriptions) != len(handlers) {
		t.Fatalf("%d subjects and %d handlers: the plan pairs them by index",
			len(subscriptions), len(handlers))
	}
	if len(subscriptions) == 0 {
		t.Fatal("the plan is empty; this guard would pass over nothing")
	}

	for i, cfg := range subscriptions {
		want, known := wantHandler[cfg.Subject]
		if !known {
			t.Errorf("subject %q is subscribed and this test does not say which handler it is for. "+
				"Add it to wantHandler — a subject nobody has written down is a subject nobody "+
				"has checked is wired to the right function.", cfg.Subject)
			continue
		}
		if got := handlerName(handlers[i]); got != want {
			t.Errorf("subject %q is handled by %s, want %s.\n"+
				"The plan pairs by INDEX, so a handler inserted or removed on one side shifts every "+
				"pair after it — silently, with both slices still the same length.",
				cfg.Subject, got, want)
		}
	}

	// The other direction: a handler this test names must actually be
	// subscribed. Otherwise the entry rots into a claim about nothing.
	subscribed := map[string]bool{}
	for _, cfg := range subscriptions {
		subscribed[cfg.Subject] = true
	}
	for subject := range wantHandler {
		if !subscribed[subject] {
			t.Errorf("wantHandler names %q and nothing subscribes to it", subject)
		}
	}
}
