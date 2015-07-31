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

type PublicKey_PreserveEncoding struct {
	PublicKey
	PreservedEncoding []byte `json:"-"`
}

func (m *PublicKey_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.PublicKey.Marshal()
	return err
}

func (m *PublicKey_PreserveEncoding) Reset() {
	*m = PublicKey_PreserveEncoding{}
}

func (m *PublicKey_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *PublicKey_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *PublicKey_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *PublicKey_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.PublicKey.Unmarshal(data)
}

func NewPopulatedPublicKey_PreserveEncoding(r randyClient, easy bool) *PublicKey_PreserveEncoding {
	this := &PublicKey_PreserveEncoding{PublicKey: *NewPopulatedPublicKey(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *PublicKey_PreserveEncoding) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*PublicKey_PreserveEncoding); ok {
		return this.PublicKey.VerboseEqual(&thatP.PublicKey)
	}
	if thatP, ok := that.(PublicKey_PreserveEncoding); ok {
		return this.PublicKey.VerboseEqual(&thatP.PublicKey)
	}
	return fmt.Errorf("types don't match: %T != PublicKey_PreserveEncoding")
}

func (this *PublicKey_PreserveEncoding) Equal(that interface{}) bool {
	if thatP, ok := that.(*PublicKey_PreserveEncoding); ok {
		return this.PublicKey.Equal(&thatP.PublicKey)
	}
	if thatP, ok := that.(PublicKey_PreserveEncoding); ok {
		return this.PublicKey.Equal(&thatP.PublicKey)
	}
	return false
}

func (this *PublicKey_PreserveEncoding) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.PublicKey_PreserveEncoding{PublicKey: ` + this.PublicKey.GoString() + `, PreservedEncoding: ` + fmt.Sprintf("%#v", this.PreservedEncoding) + `}`
}

func (this *PublicKey_PreserveEncoding) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.PublicKey_PreserveEncoding{PublicKey: ` + this.PublicKey.String() + `, PreservedEncoding: ` + fmt.Sprintf("%v", this.PreservedEncoding) + `}`
}
