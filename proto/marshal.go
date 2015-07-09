package proto

// MustMarshal takes a marshalable and returns the []byte representation.  This
// function must be used exclusively when a marshaling error is fatal AND
// indicative of a programming bug.
func MustMarshal(m interface {
	Marshal() ([]byte, error)
}) []byte {
	ret, err := m.Marshal()
	if err != nil {
		panic(err)
	}
	return ret
}
