package server

import (
	"container/list"
	"log"
	"sync"

	"github.com/yahoo/coname/proto"
)

const verifierBroadcastBufferSize = 1

// verifierBroadcast acts as a publish-subscribe message broker for verifiers
// waiting for updates. The keyserver main calls Send each time a new log entry
// is available for verifiers. A grpc handler would call Read with the
// verifier's request data and use the returned channel to keep the verifier up
// to date.
type verifierBroadcast struct {
	sync.Mutex
	nextIndex   uint64
	subscribers list.List // value type: verifierSubscription
}
type verifierSubscription struct {
	ch           chan<- *proto.VerifierStep
	start, limit uint64 // not inclusive
}

// NewVerifierBroadcast(i( initializes a verifierBroadcast such that the next
// call to send will be interpreted as the value of verifierLog[i].
func NewVerifierBroadcast(nextIndexVerifier uint64) *verifierBroadcast {
	return &verifierBroadcast{nextIndex: nextIndexVerifier}
}

// Send broadcasts m to all subscribers registered with vmb. Send is a network
// boundary: all inputs that are required to reproduce m MUST be synced to
// stable storage before Send(m) is called.
func (vmb *verifierBroadcast) Send(m *proto.VerifierStep) {
	vmb.Lock()
	defer vmb.Unlock()
	idx := vmb.nextIndex
	vmb.nextIndex++
	for e := vmb.subscribers.Front(); e != nil; e = e.Next() {
		s := (e.Value).(verifierSubscription)
		if idx < s.start {
			continue
		}
		remove := false
		select {
		case s.ch <- m:
			remove = s.limit == vmb.nextIndex
		default:
			// No channel in vmb.subscribers is allowed to block.
			// Slow clients should just resubscribe.
			remove = true
		}
		if remove {
			close(s.ch)
			vmb.subscribers.Remove(e)
		}
	}
}

// Receive requests access to broadcasts for indexes [start, receive). If the
// broadcast for start has already been sent, Receive returns nil. When there
// are no more broadcasts left in the subscription (after limit-1 in the common
// case), the channel returned by Receive is closed. The caller is expected to
// consume the values from the returned channel quickly, if it blocks, the
// channel may be closed before the limit is reached.
func (vmb *verifierBroadcast) Receive(start, limit uint64) <-chan *proto.VerifierStep {
	if start > limit {
		log.Panicf("vmb.Receive(%d, %d) (start > limit", start, limit)
	}
	ch := make(chan *proto.VerifierStep, verifierBroadcastBufferSize)
	if start == limit {
		close(ch)
		return ch
	}

	vmb.Lock()
	defer vmb.Unlock()
	if start < vmb.nextIndex {
		return nil // already broadcast, will never be sent again
	}
	vmb.subscribers.PushBack(verifierSubscription{ch: ch, start: start, limit: limit})
	return ch
}
