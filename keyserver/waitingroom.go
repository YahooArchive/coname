package keyserver

import "sync"

// WaitingRoom is used to return replies to the clients whose requests are
// handled through the replication log.
type WaitingRoom struct {
	sync.Mutex
	waiters map[uint64]chan<- interface{}
}

// NewWaitingRoom initiailizes a WaitingRoom.
func NewWaitingRoom() *WaitingRoom {
	return &WaitingRoom{waiters: make(map[uint64]chan<- interface{})}
}

// Wait waits for a value to be sent by Notfiy.
func (wr *WaitingRoom) Wait(uid uint64) <-chan interface{} {
	wr.Lock()
	defer wr.Unlock()
	ch := make(chan interface{}, 1)
	wr.waiters[uid] = ch
	return ch
}

// Notify tries to send  v to the waiter uid and returns whether it did.
func (wr *WaitingRoom) Notify(uid uint64, v interface{}) bool {
	wr.Lock()
	defer wr.Unlock()
	ch, ok := wr.waiters[uid]
	if !ok {
		return false
	}
	ch <- v // never blocks because the waiter channels have a buffer of 1
	close(ch)
	delete(wr.waiters, uid)
	return true
}
