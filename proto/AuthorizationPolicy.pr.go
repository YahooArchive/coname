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
	"github.com/andres-erbsen/protobuf/proto"
)

type EncodedAuthorizationPolicy struct {
	AuthorizationPolicy
	Encoding []byte
}

func (m *EncodedAuthorizationPolicy) UpdateEncoding() {
	m.Encoding = MustMarshal(&m.AuthorizationPolicy)
}

func (m *EncodedAuthorizationPolicy) Reset() {
	*m = EncodedAuthorizationPolicy{}
}

func (m *EncodedAuthorizationPolicy) Size() int {
	return len(m.Encoding)
}

func (m *EncodedAuthorizationPolicy) Marshal() ([]byte, error) {
	size := m.Size()
	data := make([]byte, size)
	n, err := m.MarshalTo(data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (m *EncodedAuthorizationPolicy) MarshalTo(data []byte) (int, error) {
	return copy(data, m.Encoding), nil
}

func (m *EncodedAuthorizationPolicy) Unmarshal(data []byte) error {
	m.Encoding = append([]byte{}, data...)
	return proto.Unmarshal(data, &m.AuthorizationPolicy)
}

func NewPopulatedEncodedAuthorizationPolicy(r randyClient, easy bool) *EncodedAuthorizationPolicy {
	this := &EncodedAuthorizationPolicy{AuthorizationPolicy: *NewPopulatedAuthorizationPolicy(r, easy)}
	this.UpdateEncoding()
	return this
}

func (this *EncodedAuthorizationPolicy) VerboseEqual(that interface{}) error {
	if thatP, ok := that.(*EncodedAuthorizationPolicy); ok {
		return this.AuthorizationPolicy.VerboseEqual(&thatP.AuthorizationPolicy)
	}
	if thatP, ok := that.(EncodedAuthorizationPolicy); ok {
		return this.AuthorizationPolicy.VerboseEqual(&thatP.AuthorizationPolicy)
	}
	return fmt.Errorf("types don't match: %T != EncodedAuthorizationPolicy", that)
}

func (this *EncodedAuthorizationPolicy) Equal(that interface{}) bool {
	if thatP, ok := that.(*EncodedAuthorizationPolicy); ok {
		return this.AuthorizationPolicy.Equal(&thatP.AuthorizationPolicy)
	}
	if thatP, ok := that.(EncodedAuthorizationPolicy); ok {
		return this.AuthorizationPolicy.Equal(&thatP.AuthorizationPolicy)
	}
	return false
}

func (this *EncodedAuthorizationPolicy) GoString() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedAuthorizationPolicy{AuthorizationPolicy: ` + this.AuthorizationPolicy.GoString() + `, Encoding: ` + fmt.Sprintf("%#v", this.Encoding) + `}`
}

func (this *EncodedAuthorizationPolicy) String() string {
	if this == nil {
		return "nil"
	}
	return `proto.EncodedAuthorizationPolicy{AuthorizationPolicy: ` + this.AuthorizationPolicy.String() + `, Encoding: ` + fmt.Sprintf("%v", this.Encoding) + `}`
}

func (m *EncodedAuthorizationPolicy) MarshalJSON() ([]byte, error) {
	ret := make([]byte, base64.StdEncoding.EncodedLen(len(m.Encoding))+2)
	ret[0] = '"'
	base64.StdEncoding.Encode(ret[1:len(ret)-1], m.Encoding)
	ret[len(ret)-1] = '"'
	return ret, nil
}

func (m *EncodedAuthorizationPolicy) UnmarshalJSON(s []byte) error {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("not a JSON quoted string: %q", s)
	}
	b := make([]byte, base64.StdEncoding.DecodedLen(len(s)-2))
	n, err := base64.StdEncoding.Decode(b, s[1:len(s)-1])
	if err != nil {
		return err
	}
	return m.Unmarshal(b[:n])
}

var _ json.Marshaler = (*EncodedAuthorizationPolicy)(nil)
var _ json.Unmarshaler = (*EncodedAuthorizationPolicy)(nil)
