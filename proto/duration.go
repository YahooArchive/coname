package proto

import "time"

func DurationStamp(d time.Duration) Duration {
	return Duration{Seconds: int64(d / 1e9), Nanos: int32(d % 1e9)}
}

func (dt *Duration) Duration() time.Duration {
	return time.Duration(dt.Seconds*1e9 + int64(dt.Nanos))
}
