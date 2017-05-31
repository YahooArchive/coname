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
//	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_jsonpb "github.com/gogo/protobuf/jsonpb"
)

type EncodedProfile struct {
	Profile
	Encoding []byte `json:"omitempty"`
}

type EncodedProfileProto struct {
	Profile json.RawMessage
}

func (m *EncodedProfile) UpdateEncoding() {
	m.Encoding = MustMarshal(&m.Profile)
}

func (m *EncodedProfile) Reset() {
	*m = EncodedProfile{}
}

func (m *EncodedProfile) Size() int {
	return len(m.Encoding)
}

func (m *EncodedProfile) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *EncodedProfile) MarshalTo(data []byte) (int, error) {
	return copy(data, m.Encoding), nil
}

func (m *EncodedProfile) Unmarshal(data []byte) error {
	m.Encoding = append([]byte{}, data...)
	return proto.Unmarshal(data, &m.Profile)
}

func NewPopulatedEncodedProfile(r randyClient, easy bool) *EncodedProfile {
	this := &EncodedProfile{Profile: *NewPopulatedProfile(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *EncodedProfile) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*EncodedProfile); ok {
		return this.Profile.VerboseEqual(&thatP.Profile)
	}
	if thatP, ok := that.(EncodedProfile); ok {
		return this.Profile.VerboseEqual(&thatP.Profile)
	}
	return fmt.Errorf("types don't match: %T != EncodedProfile", that)
}

func (this *EncodedProfile) Equal(that interface{}) bool {
	if thatP, ok := that.(*EncodedProfile); ok {
		return this.Profile.Equal(&thatP.Profile)
	}
	if thatP, ok := that.(EncodedProfile); ok {
		return this.Profile.Equal(&thatP.Profile)
	}
	return false
}

func (this *EncodedProfile) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedProfile{Profile: ` + this.Profile.GoString() + `, Encoding: ` + fmt.Sprintf("%#v", this.Encoding) + `}`
}

func (this *EncodedProfile) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedProfile{Profile: ` + this.Profile.String() + `, Encoding: ` + fmt.Sprintf("%v", this.Encoding) + `}`
}

func (m *EncodedProfile) MarshalJSON() ([]byte, error) {
	marshaler := github_com_gogo_protobuf_jsonpb.Marshaler{}
	jsondata, err := marshaler.MarshalToString(&m.Profile)
	if err != nil {
		return nil, err
	}
	t := json.RawMessage(jsondata)
	c := struct {
		Profile *json.RawMessage
	}{Profile: &t}
	return json.Marshal(&c)
}

func (m *EncodedProfile) UnmarshalJSON(s []byte) error {
	var stuff EncodedProfileProto
	err := json.Unmarshal(s, &stuff)
	if err != nil {
		return err
	}
	err = github_com_gogo_protobuf_jsonpb.UnmarshalString(string(stuff.Profile), &m.Profile)
	if err != nil {
		return err
	}
	m.UpdateEncoding()
	return err
}

var _ json.Marshaler = (*EncodedProfile)(nil)
var _ json.Unmarshaler = (*EncodedProfile)(nil)
