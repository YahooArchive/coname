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

type EncodedEpochHead struct {
	EpochHead
	Encoding []byte
}

type EncodedEpochHeadProto struct {
	EpochHead json.RawMessage
}

func (m *EncodedEpochHead) UpdateEncoding() {
	m.Encoding = MustMarshal(&m.EpochHead)
}

func (m *EncodedEpochHead) Reset() {
	*m = EncodedEpochHead{}
}

func (m *EncodedEpochHead) Size() int {
	return len(m.Encoding)
}

func (m *EncodedEpochHead) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *EncodedEpochHead) MarshalTo(data []byte) (int, error) {
	return copy(data, m.Encoding), nil
}

func (m *EncodedEpochHead) Unmarshal(data []byte) error {
	m.Encoding = append([]byte{}, data...)
	return proto.Unmarshal(data, &m.EpochHead)
}

func NewPopulatedEncodedEpochHead(r randyClient, easy bool) *EncodedEpochHead {
	this := &EncodedEpochHead{EpochHead: *NewPopulatedEpochHead(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *EncodedEpochHead) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*EncodedEpochHead); ok {
		return this.EpochHead.VerboseEqual(&thatP.EpochHead)
	}
	if thatP, ok := that.(EncodedEpochHead); ok {
		return this.EpochHead.VerboseEqual(&thatP.EpochHead)
	}
	return fmt.Errorf("types don't match: %T != EncodedEpochHead", that)
}

func (this *EncodedEpochHead) Equal(that interface{}) bool {
	if thatP, ok := that.(*EncodedEpochHead); ok {
		return this.EpochHead.Equal(&thatP.EpochHead)
	}
	if thatP, ok := that.(EncodedEpochHead); ok {
		return this.EpochHead.Equal(&thatP.EpochHead)
	}
	return false
}

func (this *EncodedEpochHead) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedEpochHead{EpochHead: ` + this.EpochHead.GoString() + `, Encoding: ` + fmt.Sprintf("%#v", this.Encoding) + `}`
}

func (this *EncodedEpochHead) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedEpochHead{EpochHead: ` + this.EpochHead.String() + `, Encoding: ` + fmt.Sprintf("%v", this.Encoding) + `}`
}

func (m *EncodedEpochHead) MarshalJSON() ([]byte, error) {
	marshaler := github_com_gogo_protobuf_jsonpb.Marshaler{}
	jsondata, err := marshaler.MarshalToString(&m.EpochHead)
	if err != nil {
		return nil, err
	}
	t := json.RawMessage(jsondata)
	c := struct {
		EpochHead *json.RawMessage
	}{EpochHead: &t}
	return json.Marshal(&c)
}

func (m *EncodedEpochHead) UnmarshalJSON(s []byte) error {
	var stuff EncodedEpochHeadProto
	err := json.Unmarshal(s, &stuff)
	if err != nil {
		return err
	}
	err = github_com_gogo_protobuf_jsonpb.UnmarshalString(string(stuff.EpochHead), &m.EpochHead)
	if err != nil {
		return err
	}
	m.UpdateEncoding()
	return err
}

var _ json.Marshaler = (*EncodedEpochHead)(nil)
var _ json.Unmarshaler = (*EncodedEpochHead)(nil)
