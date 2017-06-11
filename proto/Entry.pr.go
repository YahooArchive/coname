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

type EncodedEntry struct {
	Entry
	Encoding []byte `json:"omitempty"`
}

type EncodedEntryProto struct {
	Entry json.RawMessage
}

func (m *EncodedEntry) UpdateEncoding() {
	m.Encoding = MustMarshal(&m.Entry)
}

func (m *EncodedEntry) Reset() {
	*m = EncodedEntry{}
}

func (m *EncodedEntry) Size() int {
	return len(m.Encoding)
}

func (m *EncodedEntry) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *EncodedEntry) MarshalTo(data []byte) (int, error) {
	return copy(data, m.Encoding), nil
}

func (m *EncodedEntry) Unmarshal(data []byte) error {
	m.Encoding = append([]byte{}, data...)
	return proto.Unmarshal(data, &m.Entry)
}

func NewPopulatedEncodedEntry(r randyClient, easy bool) *EncodedEntry {
	this := &EncodedEntry{Entry: *NewPopulatedEntry(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *EncodedEntry) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*EncodedEntry); ok {
		return this.Entry.VerboseEqual(&thatP.Entry)
	}
	if thatP, ok := that.(EncodedEntry); ok {
		return this.Entry.VerboseEqual(&thatP.Entry)
	}
	return fmt.Errorf("types don't match: %T != EncodedEntry", that)
}

func (this *EncodedEntry) Equal(that interface{}) bool {
	if thatP, ok := that.(*EncodedEntry); ok {
		return this.Entry.Equal(&thatP.Entry)
	}
	if thatP, ok := that.(EncodedEntry); ok {
		return this.Entry.Equal(&thatP.Entry)
	}
	return false
}

func (this *EncodedEntry) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedEntry{Entry: ` + this.Entry.GoString() + `, Encoding: ` + fmt.Sprintf("%#v", this.Encoding) + `}`
}

func (this *EncodedEntry) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedEntry{Entry: ` + this.Entry.String() + `, Encoding: ` + fmt.Sprintf("%v", this.Encoding) + `}`
}

func (m *EncodedEntry) MarshalJSON() ([]byte, error) {
	marshaler := github_com_gogo_protobuf_jsonpb.Marshaler{}
	jsondata, err := marshaler.MarshalToString(&m.Entry)
	if err != nil {
		return nil, err
	}
	t := json.RawMessage(jsondata)
	c := struct {
		Entry *json.RawMessage
	}{Entry: &t}
	return json.Marshal(&c)
}

func (m *EncodedEntry) UnmarshalJSON(s []byte) error {
	var stuff EncodedEntryProto
	err := json.Unmarshal(s, &stuff)
	if err != nil {
		return err
	}
	err = github_com_gogo_protobuf_jsonpb.UnmarshalString(string(stuff.Entry), &m.Entry)
	if err != nil {
		return err
	}
	m.UpdateEncoding()
	return err
}

var _ json.Marshaler = (*EncodedEntry)(nil)
var _ json.Unmarshaler = (*EncodedEntry)(nil)
