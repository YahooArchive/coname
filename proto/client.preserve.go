package proto

// this file implements encoding-preserving unmarshaling and marshaling for the
// types in client.proto. Hopefully we will be code-generating this some day.

type Entry_PreserveEncoding struct {
	Entry
	PreservedEncoding []byte
}

func (m *Entry_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.Entry.Marshal()
	return err
}

func (m *Entry_PreserveEncoding) Reset() {
	*m = Entry_PreserveEncoding{}
}

func (m *Entry_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *Entry_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *Entry_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *Entry_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.Entry.Unmarshal(data)
}

type SignedEntryUpdate_EntryUpdateT_PreserveEncoding struct {
	SignedEntryUpdate_EntryUpdateT
	PreservedEncoding []byte
}

func (m *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.SignedEntryUpdate_EntryUpdateT.Marshal()
	return err
}

func (m *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) Reset() {
	*m = SignedEntryUpdate_EntryUpdateT_PreserveEncoding{}
}

func (m *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.SignedEntryUpdate_EntryUpdateT.Unmarshal(data)
}

type SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding struct {
	SignedRatification_RatificationT_KeyserverStateSummary
	PreservedEncoding []byte
}

func (m *SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.SignedRatification_RatificationT_KeyserverStateSummary.Marshal()
	return err
}

func (m *SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding) Reset() {
	*m = SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding{}
}

func (m *SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *SignedRatification_RatificationT_KeyserverStateSummary_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.SignedRatification_RatificationT_KeyserverStateSummary.Unmarshal(data)
}

type SignedRatification_RatificationT_PreserveEncoding struct {
	SignedRatification_RatificationT
	PreservedEncoding []byte
}

func (m *SignedRatification_RatificationT_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.SignedRatification_RatificationT.Marshal()
	return err
}

func (m *SignedRatification_RatificationT_PreserveEncoding) Reset() {
	*m = SignedRatification_RatificationT_PreserveEncoding{}
}

func (m *SignedRatification_RatificationT_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *SignedRatification_RatificationT_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *SignedRatification_RatificationT_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *SignedRatification_RatificationT_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.SignedRatification_RatificationT.Unmarshal(data)
}
