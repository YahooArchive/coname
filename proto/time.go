package proto

import "time"

type Time time.Time

func (t *Time) Unmarshal(data []byte) error {
	var tst Timestamp
	err := tst.Unmarshal(data)
	*(*time.Time)(t) = time.Unix(tst.Seconds, int64(tst.Nanos))
	return err
}

func (t *Time) tst() *Timestamp {
	return &Timestamp{Seconds: (*time.Time)(t).Unix(), Nanos: int32((*time.Time)(t).Nanosecond())}
}

func (t *Time) MarshalTo(data []byte) (int, error) {
	return t.tst().MarshalTo(data)
}

func (t *Time) Marshal() ([]byte, error) {
	return t.tst().Marshal()
}

func (t *Time) Size() int {
	return t.tst().Size()
}

func (t *Time) Time() time.Time {
	return *(*time.Time)(t)
}
