// Package eventstest provides a recording stand-in for a NATS client, for
// tests that must prove a code path PUBLISHES — the wiring, not the helper.
package eventstest

import (
	"encoding/json"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/events"
)

// Message is one recorded publish.
type Message struct {
	Subject string
	Data    []byte
	MsgID   string
}

// Recorder satisfies events.MessagePublisher and keeps every message.
// Err, when set, is returned from Publish (after recording).
type Recorder struct {
	mu       sync.Mutex
	messages []Message
	Err      error
}

// Publish records the message.
func (r *Recorder) Publish(subject string, data []byte, msgID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, Message{Subject: subject, Data: append([]byte(nil), data...), MsgID: msgID})
	return r.Err
}

// Messages returns a copy of everything recorded so far.
func (r *Recorder) Messages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Message(nil), r.messages...)
}

// QueueReady returns the decoded discovery.queue.ready events recorded so far,
// in publish order. A message on that subject that does not decode is
// returned as a zero event, so a count assertion still sees it.
func (r *Recorder) QueueReady() []events.DiscoveryQueueReadyEvent {
	var out []events.DiscoveryQueueReadyEvent
	for _, m := range r.Messages() {
		if m.Subject != events.SubjectDiscoveryQueueReady {
			continue
		}
		var ev events.DiscoveryQueueReadyEvent
		_ = json.Unmarshal(m.Data, &ev)
		out = append(out, ev)
	}
	return out
}
