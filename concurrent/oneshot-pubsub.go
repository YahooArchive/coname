package concurrent

import "sync"

// OneShotPubSub is used to return replies to the clients whose requests are
// handled through the replication log. It's a sort of one-shot asynchronous
// publish-subscribe system: Only one subscriber can wait on a particular uid,
// and only one message can be sent on any given uid. Once the message is sent,
// the subscriber is notified asynchronously and the channel associated with
// that uid closes. Any further Notify calls on the same uid will return false
// and have no effect. A uid should never be reused.
type OneShotPubSub struct {
	sync.Mutex
	waiters map[uint64]chan<- interface{}
}

// NewOneShotPubSub initializes a OneShotPubSub.
func NewOneShotPubSub() *OneShotPubSub {
	return &OneShotPubSub{waiters: make(map[uint64]chan<- interface{})}
}

// Wait waits for a value to be sent by Notify.
func (p *OneShotPubSub) Wait(uid uint64) <-chan interface{} {
	p.Lock()
	defer p.Unlock()
	ch := make(chan interface{}, 1)
	p.waiters[uid] = ch
	return ch
}

// Notify tries to send v to the waiter uid and returns whether it did.
func (p *OneShotPubSub) Notify(uid uint64, v interface{}) bool {
	p.Lock()
	defer p.Unlock()
	ch, ok := p.waiters[uid]
	if !ok {
		return false
	}
	ch <- v // never blocks because the waiter channels have a buffer of 1
	close(ch)
	delete(p.waiters, uid)
	return true
}
