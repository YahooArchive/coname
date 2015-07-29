package proto

import "time"

func Time(t time.Time) Timestamp {
	return Timestamp{Seconds: t.Unix(), Nanos: int32(t.UnixNano())}
}

func (tst *Timestamp) Time() time.Time {
	return time.Unix(tst.Seconds, int64(tst.Nanos))
}
