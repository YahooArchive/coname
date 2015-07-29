// Copyright 2014-2015 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package proto

import "fmt"

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

func NewPopulatedSignedEntryUpdate_EntryUpdateT_PreserveEncoding(r randyClient, easy bool) *SignedEntryUpdate_EntryUpdateT_PreserveEncoding {
	this := &SignedEntryUpdate_EntryUpdateT_PreserveEncoding{SignedEntryUpdate_EntryUpdateT: *NewPopulatedSignedEntryUpdate_EntryUpdateT(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*SignedEntryUpdate_EntryUpdateT_PreserveEncoding); ok {
		return this.SignedEntryUpdate_EntryUpdateT.VerboseEqual(&thatP.SignedEntryUpdate_EntryUpdateT)
	}
	if thatP, ok := that.(SignedEntryUpdate_EntryUpdateT_PreserveEncoding); ok {
		return this.SignedEntryUpdate_EntryUpdateT.VerboseEqual(&thatP.SignedEntryUpdate_EntryUpdateT)
	}
	return fmt.Errorf("types don't match: %T != SignedEntryUpdate_EntryUpdateT_PreserveEncoding")
}

func (this *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) Equal(that interface{}) bool {
	if thatP, ok := that.(*SignedEntryUpdate_EntryUpdateT_PreserveEncoding); ok {
		return this.SignedEntryUpdate_EntryUpdateT.Equal(&thatP.SignedEntryUpdate_EntryUpdateT)
	}
	if thatP, ok := that.(SignedEntryUpdate_EntryUpdateT_PreserveEncoding); ok {
		return this.SignedEntryUpdate_EntryUpdateT.Equal(&thatP.SignedEntryUpdate_EntryUpdateT)
	}
	return false
}

func (this *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.SignedEntryUpdate_EntryUpdateT_PreserveEncoding{SignedEntryUpdate_EntryUpdateT: ` + this.SignedEntryUpdate_EntryUpdateT.GoString() + `, PreservedEncoding: ` + fmt.Sprintf("%#v", this.PreservedEncoding) + `}`
}

func (this *SignedEntryUpdate_EntryUpdateT_PreserveEncoding) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.SignedEntryUpdate_EntryUpdateT_PreserveEncoding{SignedEntryUpdate_EntryUpdateT: ` + this.SignedEntryUpdate_EntryUpdateT.String() + `, PreservedEncoding: ` + fmt.Sprintf("%v", this.PreservedEncoding) + `}`
}
