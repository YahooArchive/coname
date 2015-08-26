package concurrent

import (
	"container/list"
	"log"
	"sync"
)

const sequenceBroadcastBufferSize = 1

// SequenceBroadcast acts as an asynchronous message broker for verifiers
// waiting for updates. It manages an ordered stream of messages, where each
// message is assigned a uint64 index, but does not remember old messages.
// Subscribers request to listen for messages in a particular range of indices,
// but if those indices have already gone by, the subscription fails, and
// clients must find the messages elsewhere. Also, subscription channels can be
// closed at any time if the receivers block, so clients must be capable of
// retrying. This enables Send to be non-blocking: it never waits for receivers
// and is guaranteed not to block indefinitely.
// The keyserver main calls Send each time a new log entry is available for
// verifiers. A grpc handler would call Read with the verifier's request data
// and use the returned channel to keep the verifier up to date.
type SequenceBroadcast struct {
	sync.Mutex
	nextIndex   uint64
	subscribers list.List // value type: sequenceSubscription
}
type sequenceSubscription struct {
	ch           chan<- interface{}
	start, limit uint64 // [start, limit)
}

// NewSequenceBroadcast initializes a sequenceBroadcast such that the next
// call to send will be interpreted as the value of sequenceLog[nextIndex].
func NewSequenceBroadcast(nextIndex uint64) *SequenceBroadcast {
	return &SequenceBroadcast{nextIndex: nextIndex}
}

// Send broadcasts m to all subscribers registered with sb. Send is a network
// boundary: all inputs that are required to reproduce m MUST be synced to
// stable storage before Send(m) is called.
func (sb *SequenceBroadcast) Send(m interface{}) {
	sb.Lock()
	defer sb.Unlock()
	idx := sb.nextIndex
	sb.nextIndex++
	for e := sb.subscribers.Front(); e != nil; {
		s := (e.Value).(sequenceSubscription)
		if idx < s.start {
			e = e.Next()
			continue
		}
		remove := false
		select {
		case s.ch <- m:
			remove = s.limit == sb.nextIndex
		default:
			// No channel in sb.subscribers is allowed to block.
			// Slow clients should just resubscribe.
			remove = true
		}
		// Advance first, then remove (or else e.Next() will always be nil)
		prev := e
		e = e.Next()
		if remove {
			close(s.ch)
			sb.subscribers.Remove(prev)
		}
	}
}

// Receive requests access to broadcasts for indexes [start, limit). If the
// broadcast for start has already been sent, Receive returns nil. When there
// are no more broadcasts left in the subscription (after limit-1 in the common
// case), the channel returned by Receive is closed. The caller is expected to
// consume the values from the returned channel quickly, if it blocks, the
// channel may be closed before the limit is reached.
func (sb *SequenceBroadcast) Receive(start, limit uint64) <-chan interface{} {
	if start > limit {
		log.Panicf("sb.Receive(%d, %d) (start > limit", start, limit)
	}
	ch := make(chan interface{}, sequenceBroadcastBufferSize)
	if start == limit {
		close(ch)
		return ch
	}

	sb.Lock()
	defer sb.Unlock()
	if start < sb.nextIndex {
		return nil // already broadcast, will never be sent again
	}
	sb.subscribers.PushBack(sequenceSubscription{ch: ch, start: start, limit: limit})
	return ch
}
