package proto

import (
	"testing"
	"time"
)

func TestDurationstamp(t *testing.T) {
	d := 5*time.Second + 15*time.Nanosecond
	ds := DurationStamp(d)
	if got, want := ds.Seconds, int64(5); got != want {
		t.Fatalf("Duration to DurationStamp got: %q, want %q", got, want)
	}
	if got, want := ds.Nanos, int32(15); got != want {
		t.Fatalf("Duration to DurationStamp got: %q, want %q", got, want)
	}
}

func TestDuration(t *testing.T) {
	d := 5*time.Second + 15*time.Nanosecond
	ds := DurationStamp(d)
	if got, want := ds.Duration(), d; got != want {
		t.Fatalf("Timestamp to Time got %q, want %q", got, want)
	}

}
