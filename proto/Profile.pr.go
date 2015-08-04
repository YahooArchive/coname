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

type Profile_PreserveEncoding struct {
	Profile
	PreservedEncoding []byte `json:"-"`
}

func (m *Profile_PreserveEncoding) UpdateEncoding() (err error) {
	m.PreservedEncoding, err = m.Profile.Marshal()
	return err
}

func (m *Profile_PreserveEncoding) Reset() {
	*m = Profile_PreserveEncoding{}
}

func (m *Profile_PreserveEncoding) Size() int {
	return len(m.PreservedEncoding)
}

func (m *Profile_PreserveEncoding) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *Profile_PreserveEncoding) MarshalTo(data []byte) (int, error) {
	return copy(data, m.PreservedEncoding), nil
}

func (m *Profile_PreserveEncoding) Unmarshal(data []byte) error {
	m.PreservedEncoding = append([]byte{}, data...)
	return m.Profile.Unmarshal(data)
}

func NewPopulatedProfile_PreserveEncoding(r randyClient, easy bool) *Profile_PreserveEncoding {
	this := &Profile_PreserveEncoding{Profile: *NewPopulatedProfile(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *Profile_PreserveEncoding) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*Profile_PreserveEncoding); ok {
		return this.Profile.VerboseEqual(&thatP.Profile)
	}
	if thatP, ok := that.(Profile_PreserveEncoding); ok {
		return this.Profile.VerboseEqual(&thatP.Profile)
	}
	return fmt.Errorf("types don't match: %T != Profile_PreserveEncoding")
}

func (this *Profile_PreserveEncoding) Equal(that interface{}) bool {
	if thatP, ok := that.(*Profile_PreserveEncoding); ok {
		return this.Profile.Equal(&thatP.Profile)
	}
	if thatP, ok := that.(Profile_PreserveEncoding); ok {
		return this.Profile.Equal(&thatP.Profile)
	}
	return false
}

func (this *Profile_PreserveEncoding) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.Profile_PreserveEncoding{Profile: ` + this.Profile.GoString() + `, PreservedEncoding: ` + fmt.Sprintf("%#v", this.PreservedEncoding) + `}`
}

func (this *Profile_PreserveEncoding) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.Profile_PreserveEncoding{Profile: ` + this.Profile.String() + `, PreservedEncoding: ` + fmt.Sprintf("%v", this.PreservedEncoding) + `}`
}

func (this *Profile_PreserveEncoding) MarshalJSON() ([]byte, error) {
	ret := make([]byte, base64.StdEncoding.EncodedLen(len(this.PreservedEncoding))+2)
	ret[0] = '"'
	base64.StdEncoding.Encode(ret[1:len(ret)-1], this.PreservedEncoding)
	ret[len(ret)-1] = '"'
	return ret, nil
}

func (this *Profile_PreserveEncoding) UnmarshalJSON(s []byte) error {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("not a JSON quoted string: %q", s)
	}
	b := make([]byte, base64.StdEncoding.DecodedLen(len(s)-2))
	if _, err := base64.StdEncoding.Decode(b, s[1:len(s)-1]); err != nil {
		return err
	}
	this.PreservedEncoding = b
	err := this.Profile.Unmarshal(b)
	if err != nil {println("UNMARSHAL FAILED"); println(err.Error())}
	return err
}

var _ json.Marshaler = (*Profile_PreserveEncoding)(nil)
var _ json.Unmarshaler = (*Profile_PreserveEncoding)(nil)
