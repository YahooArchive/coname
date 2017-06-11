package proto

import (
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	tm := time.Now()
	ts := Time(tm)
	if got, want := ts.Seconds, int64(tm.Unix()); got != want {
		t.Fatalf("Time to Timestamp got: %q, want %q", got, want)
	}
	if got, want := ts.Nanos, int32(tm.Nanosecond()); got != want {
		t.Fatalf("Time to Timestamp got: %q, want %q", got, want)
	}

}

func TestTime(t *testing.T) {
	t.Skip()	// causing an error for "tip"
	tm := time.Now()
	ts := Time(tm)
	if got, want := ts.Time(), tm; got != want {
		t.Fatalf("Timestamp to Time got %q, want %q", got, want)
	}

}
