package concurrent

import (
	"testing"
)

func TestSequenceBroadcastSendDoesntBlockButCloses(t *testing.T) {
	sb := NewSequenceBroadcast(11)
	ch1 := sb.Receive(11, 1<<40)
	// fill the buffer
	for i := 0; i < sequenceBroadcastBufferSize; i++ {
		sb.Send(nil)
	}
	// overfill the buffer
	sb.Send(nil)
	// receive the filled values
	for i := 0; i < sequenceBroadcastBufferSize; i++ {
		if _, ok := <-ch1; !ok {
			t.Errorf("sequenceBroadcast.Send closed ch too early (%d < %d)", i, sequenceBroadcastBufferSize)
		}
	}
	// underflow (because overflowed and discarded before)
	select {
	case _, ch1Open := <-ch1:
		if ch1Open {
			t.Errorf("sequenceBroadcast.Send did not close ch even though it blocked (got a value instead)")
		}
	default:
		t.Errorf("sequenceBroadcast.Send did not close ch even though it blocked (channel left open)")
	}
}

func TestSequenceBroadcastPastReceiveNil(t *testing.T) {
	sb := NewSequenceBroadcast(13)
	ch := sb.Receive(7, 1<<40)
	if ch != nil {
		t.Errorf("NewSequenceBroadcast(13).Receive(7, 1<<40) = %#v, expected nil", ch)
	}
}

func TestSequenceBroadcastFutureReceiveBlocks(t *testing.T) {
	sb := NewSequenceBroadcast(7)
	ch := sb.Receive(13, 1<<40)
	if ch == nil {
		t.Errorf("NewSequenceBroadcast(7).Receive(13, 1<<40) = nil, expected a channel")
	}
	for i := 7; i < 13; i++ {
		sb.Send(nil)
		select {
		case <-ch:
			t.Errorf("NewSequenceBroadcast(7).Receive(13, 1<<40) returned a value after send number %d", i)
		default:
		}
	}
	sb.Send(nil)
	if _, ok := <-ch; !ok {
		t.Errorf("NewSequenceBroadcast(7).Receive(13, 1<<40) did not return a value after send number 13")
	}
}

func TestSequenceBroadcastRespectsLimits(t *testing.T) {
	sb := NewSequenceBroadcast(5)
	ch := sb.Receive(7, 13)
	msgs := make([]interface{}, 17)
	for i := 7; i < 13; i++ {
		msgs[i] = i
	}
	for i := 5; i < 17; i++ {
		sb.Send(msgs[i])
		select {
		case got, ok := <-ch:
			if i < 7 {
				if ok {
					t.Errorf("sequenceBroadcast: got non-subscribed message %d", i)
				} else {
					t.Errorf("sequenceBroadcast: closed before beginning of subscription %d", i)
				}
			}
			if 7 <= i && i < 13 {
				if !ok {
					t.Errorf("sequenceBroadcast: closed instead of message %d", i)
				}
				if got != msgs[i] {
					t.Errorf("sequenceBroadcast: got wrong message %d", i)
				}
			}
			if i >= 14 && ok {
				t.Errorf("sequenceBroadcast: not closed after subscription end (got a value for %d instead)", i)
			}
		default:
			if 7 <= i && i < 13 {
				t.Errorf("sequenceBroadcast: missed message %d", i)
			}
			if i >= 14 {
				t.Errorf("sequenceBroadcast: not closed after subscription end (blocked at %d instead)", i)
			}
		}
	}
}

func TestSequenceBroadcastProceedsPastBlockingReceivers(t *testing.T) {
	testCases := [][]bool{
		// whether the receiver will block
		[]bool{true, false},
		[]bool{false, true, false, false, true, false},
		[]bool{false, false, true, true},
	}
	msgs := make([]interface{}, 1+sequenceBroadcastBufferSize)
	for i := range msgs {
		msgs[i] = i
	}
	for caseNr, receiversBlock := range testCases {
		sb := NewSequenceBroadcast(1)
		receivers := make([]<-chan interface{}, len(receiversBlock))
		for i := range receivers {
			receivers[i] = sb.Receive(1, 1+1+sequenceBroadcastBufferSize)
		}
		// fill the buffers
		for i := 0; i < sequenceBroadcastBufferSize; i++ {
			sb.Send(msgs[i])
		}
		// read one from the receivers who shouldn't block
		for i, r := range receivers {
			if !receiversBlock[i] {
				select {
				case got, ok := <-r:
					if !ok {
						t.Errorf("case %d: receiver %d closed prematurely", caseNr, i)
					}
					if got != msgs[0] {
						t.Errorf("case %d: receiver %d got wrong message", caseNr, i)
					}
				default:
					t.Errorf("case %d: receiver %d didn't get message", caseNr, i)
				}
			}
		}
		// send once more
		sb.Send(msgs[sequenceBroadcastBufferSize])
		// check that the blocking receivers are closed and the others have seen everything
		for i, r := range receivers {
			if receiversBlock[i] {
				// see that we got the first sequenceBroadcastBufferSize messages...
				for j := 0; j < sequenceBroadcastBufferSize; j++ {
					select {
					case got, ok := <-r:
						if !ok {
							t.Errorf("case %d: blocking receiver %d closed prematurely (%d)", caseNr, i, j)
						}
						if got != msgs[j] {
							t.Errorf("case %d: blocking receiver %d got wrong message (%d)", caseNr, i, j)
						}
					default:
						t.Errorf("case %d: blocking receiver %d didn't get message (%d)", caseNr, i, j)
					}
				}
				// ...and then got closed
				select {
				case _, ok := <-r:
					if ok {
						t.Errorf("case %d: blocking receiver %d was not booted", caseNr, i)
					}
				default:
					t.Errorf("case %d: blocking receiver %d was not booted, and didn't get message", caseNr, i)
				}
			} else {
				// see that we got the next sequenceBroadcastBufferSize messages
				for j := 1; j < 1+sequenceBroadcastBufferSize; j++ {
					select {
					case got, ok := <-r:
						if !ok {
							t.Errorf("case %d: non-blocked receiver %d closed prematurely (%d)", caseNr, i, j)
						}
						if got != msgs[j] {
							t.Errorf("case %d: non-blocked receiver %d got wrong message (%d)", caseNr, i, j)
						}
					default:
						t.Errorf("case %d: non-blocked receiver %d didn't get message (%d)", caseNr, i, j)
					}
				}
			}
		}
	}
}
