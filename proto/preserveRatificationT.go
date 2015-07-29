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

func NewPopulatedSignedRatification_RatificationT_PreserveEncoding(r randyClient, easy bool) *SignedRatification_RatificationT_PreserveEncoding {
	this := &SignedRatification_RatificationT_PreserveEncoding{SignedRatification_RatificationT: *NewPopulatedSignedRatification_RatificationT(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *SignedRatification_RatificationT_PreserveEncoding) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*SignedRatification_RatificationT_PreserveEncoding); ok {
		return this.SignedRatification_RatificationT.VerboseEqual(&thatP.SignedRatification_RatificationT)
	}
	if thatP, ok := that.(SignedRatification_RatificationT_PreserveEncoding); ok {
		return this.SignedRatification_RatificationT.VerboseEqual(&thatP.SignedRatification_RatificationT)
	}
	return fmt.Errorf("types don't match: %T != SignedRatification_RatificationT_PreserveEncoding")
}

func (this *SignedRatification_RatificationT_PreserveEncoding) Equal(that interface{}) bool {
	if thatP, ok := that.(*SignedRatification_RatificationT_PreserveEncoding); ok {
		return this.SignedRatification_RatificationT.Equal(&thatP.SignedRatification_RatificationT)
	}
	if thatP, ok := that.(SignedRatification_RatificationT_PreserveEncoding); ok {
		return this.SignedRatification_RatificationT.Equal(&thatP.SignedRatification_RatificationT)
	}
	return false
}

func (this *SignedRatification_RatificationT_PreserveEncoding) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.SignedRatification_RatificationT_PreserveEncoding{SignedRatification_RatificationT: ` + this.SignedRatification_RatificationT.GoString() + `, PreservedEncoding: ` + fmt.Sprintf("%#v", this.PreservedEncoding) + `}`
}

func (this *SignedRatification_RatificationT_PreserveEncoding) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.SignedRatification_RatificationT_PreserveEncoding{SignedRatification_RatificationT: ` + this.SignedRatification_RatificationT.String() + `, PreservedEncoding: ` + fmt.Sprintf("%v", this.PreservedEncoding) + `}`
}
