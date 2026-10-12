package capture

import (
	"container/list"
	"errors"
	"sort"
	"sync"
	"time"
)

// Bounds on QUIC Initial CRYPTO reassembly. A ClientHello with a hybrid
// post-quantum key share is ~1.7 KB and spans two Initials; 16 KB is far past
// any legitimate hello, so a flow that wants more is dropped, not buffered.
const (
	quicReassemblyMaxFlowBytes = 16 * 1024
	quicReassemblyMaxFlows     = 4096
	quicReassemblyTTL          = 5 * time.Second
)

// errQUICClientHelloIncomplete means the CRYPTO data seen so far is a valid
// prefix of a ClientHello whose remainder has not arrived yet.
var errQUICClientHelloIncomplete = errors.New("QUIC ClientHello incomplete, awaiting further Initial packets")

// quicFlowKey identifies one client's Initial CRYPTO stream.
type quicFlowKey struct {
	srcIP, dstIP     string
	srcPort, dstPort int
	dcid             string
}

type quicByteRange struct{ start, end int }

type quicFlowState struct {
	key     quicFlowKey
	created time.Time
	buf     []byte
	ranges  []quicByteRange // sorted, non-overlapping, non-adjacent
	elem    *list.Element
}

// quicReassembler rebuilds the client's Initial CRYPTO stream across packets.
// The capture loop runs several workers, so all state sits behind a mutex.
// Entries are kept in creation order; expiry and eviction pop the oldest.
type quicReassembler struct {
	mu       sync.Mutex
	now      func() time.Time
	maxFlows int
	maxBytes int
	ttl      time.Duration
	flows    map[quicFlowKey]*quicFlowState
	order    *list.List // front = oldest
}

func newQUICReassembler(maxFlows, maxBytes int, ttl time.Duration) *quicReassembler {
	return &quicReassembler{
		now:      time.Now,
		maxFlows: maxFlows,
		maxBytes: maxBytes,
		ttl:      ttl,
		flows:    make(map[quicFlowKey]*quicFlowState),
		order:    list.New(),
	}
}

// quicReassembly is the capture path's shared reassembler.
var quicReassembly = newQUICReassembler(quicReassemblyMaxFlows, quicReassemblyMaxFlowBytes, quicReassemblyTTL)

func (r *quicReassembler) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}

func (r *quicReassembler) remove(st *quicFlowState) {
	if st.elem != nil {
		r.order.Remove(st.elem)
		st.elem = nil
	}
	delete(r.flows, st.key)
}

// add merges frags into the flow's stream and parses the ClientHello once its
// declared length is covered, dropping the flow's state. Until then it returns
// errQUICClientHelloIncomplete.
func (r *quicReassembler) add(key quicFlowKey, frags []quicCryptoFragment) (*QUICClientHelloInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	for e := r.order.Front(); e != nil; e = r.order.Front() {
		old := e.Value.(*quicFlowState)
		if now.Sub(old.created) <= r.ttl {
			break
		}
		r.remove(old)
	}

	st, tracked := r.flows[key]
	if !tracked {
		st = &quicFlowState{key: key, created: now}
	}
	for _, f := range frags {
		if f.offset > uint64(r.maxBytes) || uint64(len(f.data)) > uint64(r.maxBytes)-f.offset {
			if tracked {
				r.remove(st)
			}
			return nil, errors.New("QUIC CRYPTO stream exceeds reassembly limit")
		}
		st.insert(int(f.offset), f.data)
	}

	need, known := st.helloLen()
	if known && need > r.maxBytes {
		if tracked {
			r.remove(st)
		}
		return nil, errors.New("QUIC ClientHello exceeds reassembly limit")
	}
	if known && len(st.ranges) > 0 && st.ranges[0].start == 0 && st.ranges[0].end >= need {
		if tracked {
			r.remove(st)
		}
		return parseQUICClientHello(st.buf[:need])
	}

	if !tracked {
		for len(r.flows) >= r.maxFlows {
			r.remove(r.order.Front().Value.(*quicFlowState))
		}
		st.elem = r.order.PushBack(st)
		r.flows[key] = st
	}
	return nil, errQUICClientHelloIncomplete
}

// helloLen returns the total handshake message length (header included) once
// the first 4 stream bytes are present.
func (st *quicFlowState) helloLen() (int, bool) {
	if len(st.ranges) == 0 || st.ranges[0].start != 0 || st.ranges[0].end < 4 {
		return 0, false
	}
	return 4 + (int(st.buf[1])<<16 | int(st.buf[2])<<8 | int(st.buf[3])), true
}

// insert places data at off, tolerating out-of-order, duplicate and
// overlapping fragments. The first copy of any byte wins.
func (st *quicFlowState) insert(off int, data []byte) {
	if len(data) == 0 {
		return
	}
	end := off + len(data)
	if end > len(st.buf) {
		st.buf = append(st.buf, make([]byte, end-len(st.buf))...)
	}
	// Copy only the bytes not already held.
	pos := off
	for _, rg := range st.ranges {
		if rg.end <= pos {
			continue
		}
		if rg.start >= end {
			break
		}
		if rg.start > pos {
			copy(st.buf[pos:rg.start], data[pos-off:rg.start-off])
		}
		if rg.end > pos {
			pos = rg.end
		}
	}
	if pos < end {
		copy(st.buf[pos:end], data[pos-off:])
	}
	st.ranges = append(st.ranges, quicByteRange{off, end})
	sort.Slice(st.ranges, func(i, j int) bool { return st.ranges[i].start < st.ranges[j].start })
	merged := st.ranges[:1]
	for _, rg := range st.ranges[1:] {
		last := &merged[len(merged)-1]
		if rg.start <= last.end {
			if rg.end > last.end {
				last.end = rg.end
			}
		} else {
			merged = append(merged, rg)
		}
	}
	st.ranges = merged
}
