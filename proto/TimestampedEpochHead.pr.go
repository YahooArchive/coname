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

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type TimestampedEpochHead_PreserveEncoding struct {
	TimestampedEpochHead
	PreservedEncoding []byte `json:"-"`
}

func (m *TimestampedEpochHead_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.TimestampedEpochHead.Marshal()
	return err
}

func (m *TimestampedEpochHead_PreserveEncoding) Reset() {
	*m = TimestampedEpochHead_PreserveEncoding{}
}

func (m *TimestampedEpochHead_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *TimestampedEpochHead_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *TimestampedEpochHead_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *TimestampedEpochHead_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.TimestampedEpochHead.Unmarshal(data)
}

func NewPopulatedTimestampedEpochHead_PreserveEncoding(r randyClient, easy bool) *TimestampedEpochHead_PreserveEncoding {
	this := &TimestampedEpochHead_PreserveEncoding{TimestampedEpochHead: *NewPopulatedTimestampedEpochHead(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *TimestampedEpochHead_PreserveEncoding) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*TimestampedEpochHead_PreserveEncoding); ok {
		return this.TimestampedEpochHead.VerboseEqual(&thatP.TimestampedEpochHead)
	}
	if thatP, ok := that.(TimestampedEpochHead_PreserveEncoding); ok {
		return this.TimestampedEpochHead.VerboseEqual(&thatP.TimestampedEpochHead)
	}
	return fmt.Errorf("types don't match: %T != TimestampedEpochHead_PreserveEncoding")
}

func (this *TimestampedEpochHead_PreserveEncoding) Equal(that interface{}) bool {
	if thatP, ok := that.(*TimestampedEpochHead_PreserveEncoding); ok {
		return this.TimestampedEpochHead.Equal(&thatP.TimestampedEpochHead)
	}
	if thatP, ok := that.(TimestampedEpochHead_PreserveEncoding); ok {
		return this.TimestampedEpochHead.Equal(&thatP.TimestampedEpochHead)
	}
	return false
}

func (this *TimestampedEpochHead_PreserveEncoding) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.TimestampedEpochHead_PreserveEncoding{TimestampedEpochHead: ` + this.TimestampedEpochHead.GoString() + `, PreservedEncoding: ` + fmt.Sprintf("%#v", this.PreservedEncoding) + `}`
}

func (this *TimestampedEpochHead_PreserveEncoding) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.TimestampedEpochHead_PreserveEncoding{TimestampedEpochHead: ` + this.TimestampedEpochHead.String() + `, PreservedEncoding: ` + fmt.Sprintf("%v", this.PreservedEncoding) + `}`
}

func (this *TimestampedEpochHead_PreserveEncoding) MarshalJSON() ([]byte, error) {
	ret := make([]byte, base64.StdEncoding.EncodedLen(len(this.PreservedEncoding))+2)
	ret[0] = '"'
	base64.StdEncoding.Encode(ret[1:len(ret)-1], this.PreservedEncoding)
	ret[len(ret)-1] = '"'
	return ret, nil
}

func (this *TimestampedEpochHead_PreserveEncoding) UnmarshalJSON(s []byte) error {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("not a JSON quoted string: %q", s)
	}
	b := make([]byte, base64.StdEncoding.DecodedLen(len(s)-2))
	if _, err := base64.StdEncoding.Decode(b, s[1:len(s)-1]); err != nil {
		return err
	}
	this.PreservedEncoding = b
	err := this.TimestampedEpochHead.Unmarshal(b)
	if err != nil {println("UNMARSHAL FAILED"); println(err.Error())}
	return err
}

var _ json.Marshaler = (*TimestampedEpochHead_PreserveEncoding)(nil)
var _ json.Unmarshaler = (*TimestampedEpochHead_PreserveEncoding)(nil)
