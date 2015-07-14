package server

import (
	"testing"

	"github.com/yahoo/coname/proto"
)

func TestVerifierBroadcastSendDoesntBlockButCloses(t *testing.T) {
	vmb := NewVerifierBroadcast(11)
	ch1 := vmb.Receive(11, 1<<40)
	// fill the buffer
	for i := 0; i < verifierBroadcastBufferSize; i++ {
		vmb.Send(nil)
	}
	// overfill the buffer
	vmb.Send(nil)
	// receive the filled values
	for i := 0; i < verifierBroadcastBufferSize; i++ {
		if _, ok := <-ch1; !ok {
			t.Errorf("verifierBroadcast.Send closed ch too early (%d < %d)", i, verifierBroadcastBufferSize)
		}
	}
	// underflow (because overflowed and discarded before)
	select {
	case _, ch1Open := <-ch1:
		if ch1Open {
			t.Errorf("verifierBroadcast.Send did not close ch even though it blocked (got a value instead)")
		}
	default:
		t.Errorf("verifierBroadcast.Send did not close ch even though it blocked (channel left open)")
	}
}

func TestVerifierBroadcastPastReceiveNil(t *testing.T) {
	vmb := NewVerifierBroadcast(13)
	ch := vmb.Receive(7, 1<<40)
	if ch != nil {
		t.Errorf("NewVerifierBroadcast(13).Receive(7, 1<<40) = %#v, expected nil", ch)
	}
}

func TestVerifierBroadcastFutureReceiveBlocks(t *testing.T) {
	vmb := NewVerifierBroadcast(7)
	ch := vmb.Receive(13, 1<<40)
	if ch == nil {
		t.Errorf("NewVerifierBroadcast(7).Receive(13, 1<<40) = nil, expected a channel", ch)
	}
	for i := 7; i < 13; i++ {
		vmb.Send(nil)
		select {
		case <-ch:
			t.Errorf("NewVerifierBroadcast(7).Receive(13, 1<<40) returned a value after send number %d", ch, i)
		default:
		}
	}
	vmb.Send(nil)
	if _, ok := <-ch; !ok {
		t.Errorf("NewVerifierBroadcast(7).Receive(13, 1<<40) did not return a value after send number 13", ch)
	}
}

func TestVerifierBroadcastRespectsLimits(t *testing.T) {
	vmb := NewVerifierBroadcast(5)
	ch := vmb.Receive(7, 13)
	msgs := make([]*proto.VerifierStep, 17)
	for i := 7; i < 13; i++ {
		msgs[i] = new(proto.VerifierStep)
	}
	for i := 5; i < 17; i++ {
		vmb.Send(msgs[i])
		select {
		case got, ok := <-ch:
			if i < 7 {
				if ok {
					t.Errorf("verifierBroadcast: got non-subscribed message %d", i)
				} else {
					t.Errorf("verifierBroadcast: closed before beginning of subscription %d", i)
				}
			}
			if 7 <= i && i < 13 {
				if !ok {
					t.Errorf("verifierBroadcast: closed instead of message %d", i)
				}
				if got != msgs[i] {
					t.Errorf("verifierBroadcast: got wrong message %d", i)
				}
			}
			if i >= 14 && ok {
				t.Errorf("verifierBroadcast: not closed after subscription end (got a value for %d instead)", i)
			}
		default:
			if 7 <= i && i < 13 {
				t.Errorf("verifierBroadcast: missed message %d", i)
			}
			if i >= 14 {
				t.Errorf("verifierBroadcast: not closed after subscription end (blocked at %d instead)", i)
			}
		}
	}
}
