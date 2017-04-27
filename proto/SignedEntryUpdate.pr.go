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

type EncodedSignedEntryUpdate struct {
	SignedEntryUpdate
	Encoding []byte
}

type EncodedSignedEntryUpdateProto struct {
	SignedEntryUpdate json.RawMessage
}

func (m *EncodedSignedEntryUpdate) UpdateEncoding() {
	m.Encoding = MustMarshal(&m.SignedEntryUpdate)
}

func (m *EncodedSignedEntryUpdate) Reset() {
	*m = EncodedSignedEntryUpdate{}
}

func (m *EncodedSignedEntryUpdate) Size() int {
	return len(m.Encoding)
}

func (m *EncodedSignedEntryUpdate) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *EncodedSignedEntryUpdate) MarshalTo(data []byte) (int, error) {
	return copy(data, m.Encoding), nil
}

func (m *EncodedSignedEntryUpdate) Unmarshal(data []byte) error {
	m.Encoding = append([]byte{}, data...)
	return proto.Unmarshal(data, &m.SignedEntryUpdate)
}

func NewPopulatedEncodedSignedEntryUpdate(r randyClient, easy bool) *EncodedSignedEntryUpdate {
	this := &EncodedSignedEntryUpdate{SignedEntryUpdate: *NewPopulatedSignedEntryUpdate(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *EncodedSignedEntryUpdate) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*EncodedSignedEntryUpdate); ok {
		return this.SignedEntryUpdate.VerboseEqual(&thatP.SignedEntryUpdate)
	}
	if thatP, ok := that.(EncodedSignedEntryUpdate); ok {
		return this.SignedEntryUpdate.VerboseEqual(&thatP.SignedEntryUpdate)
	}
	return fmt.Errorf("types don't match: %T != EncodedSignedEntryUpdate", that)
}

func (this *EncodedSignedEntryUpdate) Equal(that interface{}) bool {
	if thatP, ok := that.(*EncodedSignedEntryUpdate); ok {
		return this.SignedEntryUpdate.Equal(&thatP.SignedEntryUpdate)
	}
	if thatP, ok := that.(EncodedSignedEntryUpdate); ok {
		return this.SignedEntryUpdate.Equal(&thatP.SignedEntryUpdate)
	}
	return false
}

func (this *EncodedSignedEntryUpdate) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedSignedEntryUpdate{SignedEntryUpdate: ` + this.SignedEntryUpdate.GoString() + `, Encoding: ` + fmt.Sprintf("%#v", this.Encoding) + `}`
}

func (this *EncodedSignedEntryUpdate) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedSignedEntryUpdate{SignedEntryUpdate: ` + this.SignedEntryUpdate.String() + `, Encoding: ` + fmt.Sprintf("%v", this.Encoding) + `}`
}

func (m *EncodedSignedEntryUpdate) MarshalJSON() ([]byte, error) {
	marshaler := github_com_gogo_protobuf_jsonpb.Marshaler{}
	jsondata, err := marshaler.MarshalToString(&m.SignedEntryUpdate)
	if err != nil {
		return nil, err
	}
	t := json.RawMessage(jsondata)
	c := struct {
		SignedEntryUpdate *json.RawMessage
	}{SignedEntryUpdate: &t}
	return json.Marshal(&c)
}

func (m *EncodedSignedEntryUpdate) UnmarshalJSON(s []byte) error {
	var stuff EncodedSignedEntryUpdateProto
	err := json.Unmarshal(s, &stuff)
	if err != nil {
		return err
	}
	err = github_com_gogo_protobuf_jsonpb.UnmarshalString(string(stuff.SignedEntryUpdate), &m.SignedEntryUpdate)
	if err != nil {
		return err
	}
	m.UpdateEncoding()
	return err
}

var _ json.Marshaler = (*EncodedSignedEntryUpdate)(nil)
var _ json.Unmarshaler = (*EncodedSignedEntryUpdate)(nil)
