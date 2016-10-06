package concurrent

import (
	"strconv"
	"testing"
)

func TestOneShotPubSubSameID(t *testing.T) {
	d := "hello"
	w := NewOneShotPubSub()
	ch := w.Wait(10)
	defer func() {
		if v, ok := <-ch; !ok {
			t.Fatal("OneShotPubSub.Notify did not return anything")
		} else {
			if got, want := v, d; got != want {
				t.Fatalf("OneShotPubSub.Notify() got %q, want %q", got, want)
			}
		}
	}()
	if !w.Notify(10, d) {
		t.Fatal("OneShotPubSub.Notify() got false, wanted true")
	}
}

func TestOneShotPubSubInvalidID(t *testing.T) {
	d := "hello"
	w := NewOneShotPubSub()
	w.Wait(10)
	if w.Notify(11, d) {
		t.Fatal("OneShotPubSub.Notify() got true, wanted false")
	}
}

func TestOneShotPubSubMultpleIDs(t *testing.T) {
	ids := []uint64{1, 2, 5, 20}
	w := NewOneShotPubSub()
	var ch [4]<-chan interface{}
	for i, id := range ids {
		ch[i] = w.Wait(id)

	}
	defer func() {
		for i, id := range ids {
			if v, ok := <-ch[i]; !ok {
				t.Fatal("OneShotPubSub.Notify did not return anything")
			} else {
				d := "hello" + strconv.Itoa(int(id))
				if got, want := v, d; got != want {
					t.Fatalf("OneShotPubSub.Notify() got %q, want %q", got, want)
				}
			}
		}
	}()
	for _, id := range ids {
		d := "hello" + strconv.Itoa(int(id))
		if !w.Notify(id, d) {
			t.Fatal("OneShotPubSub.Notify() got false, wanted true")
		}
	}
}
