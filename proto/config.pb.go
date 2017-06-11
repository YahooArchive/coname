// Code generated by protoc-gen-gogo.
// source: config.proto
// DO NOT EDIT!

package proto

import proto1 "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"

import bytes "bytes"

import strings "strings"
import reflect "reflect"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto1.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type Config struct {
	Realms []*RealmConfig `protobuf:"bytes,1,rep,name=realms" json:"realms,omitempty"`
}

func (m *Config) Reset()                    { *m = Config{} }
func (*Config) ProtoMessage()               {}
func (*Config) Descriptor() ([]byte, []int) { return fileDescriptorConfig, []int{0} }

func (m *Config) GetRealms() []*RealmConfig {
	if m != nil {
		return m.Realms
	}
	return nil
}

type RealmConfig struct {
	// RealmName is the canonical name of the realm. It is signed by the
	// verifiers as a part of the epoch head.
	RealmName string `protobuf:"bytes,1,opt,name=RealmName,proto3" json:"RealmName,omitempty"`
	// Domains specifies a list of domains that belong to this realm.
	// Configuring one domain to belong to multiple realms is considered an
	// error.
	// TODO: support TLS-style wildcards.
	Domains []string `protobuf:"bytes,2,rep,name=domains" json:"domains,omitempty"`
	// Addr is the TCP (host:port) address of the keyserver GRPC interface.
	Addr string `protobuf:"bytes,3,opt,name=addr,proto3" json:"addr,omitempty"`
	// URL is the location of the secondary, HTTP-based interface to the
	// keyserver. It is not necessarily on the same host as addr.
	URL string `protobuf:"bytes,4,opt,name=URL,proto3" json:"URL,omitempty"`
	// VRFPublic is the public key of the verifiable random function used for
	// user id privacy. Here it is used to check that the anti-spam obfuscation
	// layer is properly used as a one-to-one mapping between real and
	// obfuscated usernames.
	VRFPublic []byte `protobuf:"bytes,5,opt,name=VRFPublic,proto3" json:"VRFPublic,omitempty"`
	// VerificationPolicy specifies the conditions on how a lookup must be
	// verified for it to be accepted. Each verifier in VerificationPolicy MUST
	// have a NoOlderThan entry.
	VerificationPolicy *AuthorizationPolicy `protobuf:"bytes,6,opt,name=verification_policy,json=verificationPolicy" json:"verification_policy,omitempty"`
	// EpochTimeToLive specifies the duration for which an epoch is valid after
	// it has been issued. A client that has access to a clock MUST NOT accept
	// epoch heads with IssueTime more than EpochTimeToLive in the past.
	EpochTimeToLive Duration `protobuf:"bytes,7,opt,name=epoch_time_to_live,json=epochTimeToLive" json:"epoch_time_to_live"`
	// TreeNonce is the global nonce that is hashed into the Merkle tree nodes.
	TreeNonce []byte     `protobuf:"bytes,8,opt,name=tree_nonce,json=treeNonce,proto3" json:"tree_nonce,omitempty"`
	ClientTLS *TLSConfig `protobuf:"bytes,9,opt,name=client_tls,json=clientTls" json:"client_tls,omitempty"`
}

func (m *RealmConfig) Reset()                    { *m = RealmConfig{} }
func (*RealmConfig) ProtoMessage()               {}
func (*RealmConfig) Descriptor() ([]byte, []int) { return fileDescriptorConfig, []int{1} }

func (m *RealmConfig) GetRealmName() string {
	if m != nil {
		return m.RealmName
	}
	return ""
}

func (m *RealmConfig) GetDomains() []string {
	if m != nil {
		return m.Domains
	}
	return nil
}

func (m *RealmConfig) GetAddr() string {
	if m != nil {
		return m.Addr
	}
	return ""
}

func (m *RealmConfig) GetURL() string {
	if m != nil {
		return m.URL
	}
	return ""
}

func (m *RealmConfig) GetVRFPublic() []byte {
	if m != nil {
		return m.VRFPublic
	}
	return nil
}

func (m *RealmConfig) GetVerificationPolicy() *AuthorizationPolicy {
	if m != nil {
		return m.VerificationPolicy
	}
	return nil
}

func (m *RealmConfig) GetEpochTimeToLive() Duration {
	if m != nil {
		return m.EpochTimeToLive
	}
	return Duration{}
}

func (m *RealmConfig) GetTreeNonce() []byte {
	if m != nil {
		return m.TreeNonce
	}
	return nil
}

func (m *RealmConfig) GetClientTLS() *TLSConfig {
	if m != nil {
		return m.ClientTLS
	}
	return nil
}

func init() {
	proto1.RegisterType((*Config)(nil), "proto.Config")
	proto1.RegisterType((*RealmConfig)(nil), "proto.RealmConfig")
}
func (this *Config) VerboseEqual(that interface{}) error {
	if that == nil {
		if this == nil {
			return nil
		}
		return fmt.Errorf("that == nil && this != nil")
	}

	that1, ok := that.(*Config)
	if !ok {
		that2, ok := that.(Config)
		if ok {
			that1 = &that2
		} else {
			return fmt.Errorf("that is not of type *Config")
		}
	}
	if that1 == nil {
		if this == nil {
			return nil
		}
		return fmt.Errorf("that is type *Config but is nil && this != nil")
	} else if this == nil {
		return fmt.Errorf("that is type *Config but is not nil && this == nil")
	}
	if len(this.Realms) != len(that1.Realms) {
		return fmt.Errorf("Realms this(%v) Not Equal that(%v)", len(this.Realms), len(that1.Realms))
	}
	for i := range this.Realms {
		if !this.Realms[i].Equal(that1.Realms[i]) {
			return fmt.Errorf("Realms this[%v](%v) Not Equal that[%v](%v)", i, this.Realms[i], i, that1.Realms[i])
		}
	}
	return nil
}
func (this *Config) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*Config)
	if !ok {
		that2, ok := that.(Config)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	if len(this.Realms) != len(that1.Realms) {
		return false
	}
	for i := range this.Realms {
		if !this.Realms[i].Equal(that1.Realms[i]) {
			return false
		}
	}
	return true
}
func (this *RealmConfig) VerboseEqual(that interface{}) error {
	if that == nil {
		if this == nil {
			return nil
		}
		return fmt.Errorf("that == nil && this != nil")
	}

	that1, ok := that.(*RealmConfig)
	if !ok {
		that2, ok := that.(RealmConfig)
		if ok {
			that1 = &that2
		} else {
			return fmt.Errorf("that is not of type *RealmConfig")
		}
	}
	if that1 == nil {
		if this == nil {
			return nil
		}
		return fmt.Errorf("that is type *RealmConfig but is nil && this != nil")
	} else if this == nil {
		return fmt.Errorf("that is type *RealmConfig but is not nil && this == nil")
	}
	if this.RealmName != that1.RealmName {
		return fmt.Errorf("RealmName this(%v) Not Equal that(%v)", this.RealmName, that1.RealmName)
	}
	if len(this.Domains) != len(that1.Domains) {
		return fmt.Errorf("Domains this(%v) Not Equal that(%v)", len(this.Domains), len(that1.Domains))
	}
	for i := range this.Domains {
		if this.Domains[i] != that1.Domains[i] {
			return fmt.Errorf("Domains this[%v](%v) Not Equal that[%v](%v)", i, this.Domains[i], i, that1.Domains[i])
		}
	}
	if this.Addr != that1.Addr {
		return fmt.Errorf("Addr this(%v) Not Equal that(%v)", this.Addr, that1.Addr)
	}
	if this.URL != that1.URL {
		return fmt.Errorf("URL this(%v) Not Equal that(%v)", this.URL, that1.URL)
	}
	if !bytes.Equal(this.VRFPublic, that1.VRFPublic) {
		return fmt.Errorf("VRFPublic this(%v) Not Equal that(%v)", this.VRFPublic, that1.VRFPublic)
	}
	if !this.VerificationPolicy.Equal(that1.VerificationPolicy) {
		return fmt.Errorf("VerificationPolicy this(%v) Not Equal that(%v)", this.VerificationPolicy, that1.VerificationPolicy)
	}
	if !this.EpochTimeToLive.Equal(&that1.EpochTimeToLive) {
		return fmt.Errorf("EpochTimeToLive this(%v) Not Equal that(%v)", this.EpochTimeToLive, that1.EpochTimeToLive)
	}
	if !bytes.Equal(this.TreeNonce, that1.TreeNonce) {
		return fmt.Errorf("TreeNonce this(%v) Not Equal that(%v)", this.TreeNonce, that1.TreeNonce)
	}
	if !this.ClientTLS.Equal(that1.ClientTLS) {
		return fmt.Errorf("ClientTLS this(%v) Not Equal that(%v)", this.ClientTLS, that1.ClientTLS)
	}
	return nil
}
func (this *RealmConfig) Equal(that interface{}) bool {
	if that == nil {
		if this == nil {
			return true
		}
		return false
	}

	that1, ok := that.(*RealmConfig)
	if !ok {
		that2, ok := that.(RealmConfig)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		if this == nil {
			return true
		}
		return false
	} else if this == nil {
		return false
	}
	if this.RealmName != that1.RealmName {
		return false
	}
	if len(this.Domains) != len(that1.Domains) {
		return false
	}
	for i := range this.Domains {
		if this.Domains[i] != that1.Domains[i] {
			return false
		}
	}
	if this.Addr != that1.Addr {
		return false
	}
	if this.URL != that1.URL {
		return false
	}
	if !bytes.Equal(this.VRFPublic, that1.VRFPublic) {
		return false
	}
	if !this.VerificationPolicy.Equal(that1.VerificationPolicy) {
		return false
	}
	if !this.EpochTimeToLive.Equal(&that1.EpochTimeToLive) {
		return false
	}
	if !bytes.Equal(this.TreeNonce, that1.TreeNonce) {
		return false
	}
	if !this.ClientTLS.Equal(that1.ClientTLS) {
		return false
	}
	return true
}
func (this *Config) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&proto.Config{")
	if this.Realms != nil {
		s = append(s, "Realms: "+fmt.Sprintf("%#v", this.Realms)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *RealmConfig) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 13)
	s = append(s, "&proto.RealmConfig{")
	s = append(s, "RealmName: "+fmt.Sprintf("%#v", this.RealmName)+",\n")
	s = append(s, "Domains: "+fmt.Sprintf("%#v", this.Domains)+",\n")
	s = append(s, "Addr: "+fmt.Sprintf("%#v", this.Addr)+",\n")
	s = append(s, "URL: "+fmt.Sprintf("%#v", this.URL)+",\n")
	s = append(s, "VRFPublic: "+fmt.Sprintf("%#v", this.VRFPublic)+",\n")
	if this.VerificationPolicy != nil {
		s = append(s, "VerificationPolicy: "+fmt.Sprintf("%#v", this.VerificationPolicy)+",\n")
	}
	s = append(s, "EpochTimeToLive: "+strings.Replace(this.EpochTimeToLive.GoString(), `&`, ``, 1)+",\n")
	s = append(s, "TreeNonce: "+fmt.Sprintf("%#v", this.TreeNonce)+",\n")
	if this.ClientTLS != nil {
		s = append(s, "ClientTLS: "+fmt.Sprintf("%#v", this.ClientTLS)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringConfig(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *Config) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Config) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Realms) > 0 {
		for _, msg := range m.Realms {
			dAtA[i] = 0xa
			i++
			i = encodeVarintConfig(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func (m *RealmConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RealmConfig) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.RealmName) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.RealmName)))
		i += copy(dAtA[i:], m.RealmName)
	}
	if len(m.Domains) > 0 {
		for _, s := range m.Domains {
			dAtA[i] = 0x12
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if len(m.Addr) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.Addr)))
		i += copy(dAtA[i:], m.Addr)
	}
	if len(m.URL) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.URL)))
		i += copy(dAtA[i:], m.URL)
	}
	if len(m.VRFPublic) > 0 {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.VRFPublic)))
		i += copy(dAtA[i:], m.VRFPublic)
	}
	if m.VerificationPolicy != nil {
		dAtA[i] = 0x32
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.VerificationPolicy.Size()))
		n1, err := m.VerificationPolicy.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	dAtA[i] = 0x3a
	i++
	i = encodeVarintConfig(dAtA, i, uint64(m.EpochTimeToLive.Size()))
	n2, err := m.EpochTimeToLive.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
	if len(m.TreeNonce) > 0 {
		dAtA[i] = 0x42
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.TreeNonce)))
		i += copy(dAtA[i:], m.TreeNonce)
	}
	if m.ClientTLS != nil {
		dAtA[i] = 0x4a
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.ClientTLS.Size()))
		n3, err := m.ClientTLS.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	return i, nil
}

func encodeFixed64Config(dAtA []byte, offset int, v uint64) int {
	dAtA[offset] = uint8(v)
	dAtA[offset+1] = uint8(v >> 8)
	dAtA[offset+2] = uint8(v >> 16)
	dAtA[offset+3] = uint8(v >> 24)
	dAtA[offset+4] = uint8(v >> 32)
	dAtA[offset+5] = uint8(v >> 40)
	dAtA[offset+6] = uint8(v >> 48)
	dAtA[offset+7] = uint8(v >> 56)
	return offset + 8
}
func encodeFixed32Config(dAtA []byte, offset int, v uint32) int {
	dAtA[offset] = uint8(v)
	dAtA[offset+1] = uint8(v >> 8)
	dAtA[offset+2] = uint8(v >> 16)
	dAtA[offset+3] = uint8(v >> 24)
	return offset + 4
}
func encodeVarintConfig(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func NewPopulatedConfig(r randyConfig, easy bool) *Config {
	this := &Config{}
	if r.Intn(10) == 0 {
		v1 := r.Intn(5)
		this.Realms = make([]*RealmConfig, v1)
		for i := 0; i < v1; i++ {
			this.Realms[i] = NewPopulatedRealmConfig(r, easy)
		}
	}
	if !easy && r.Intn(10) != 0 {
	}
	return this
}

func NewPopulatedRealmConfig(r randyConfig, easy bool) *RealmConfig {
	this := &RealmConfig{}
	this.RealmName = string(randStringConfig(r))
	v2 := r.Intn(10)
	this.Domains = make([]string, v2)
	for i := 0; i < v2; i++ {
		this.Domains[i] = string(randStringConfig(r))
	}
	this.Addr = string(randStringConfig(r))
	this.URL = string(randStringConfig(r))
	v3 := r.Intn(100)
	this.VRFPublic = make([]byte, v3)
	for i := 0; i < v3; i++ {
		this.VRFPublic[i] = byte(r.Intn(256))
	}
	if r.Intn(10) == 0 {
		this.VerificationPolicy = NewPopulatedAuthorizationPolicy(r, easy)
	}
	v4 := NewPopulatedDuration(r, easy)
	this.EpochTimeToLive = *v4
	v5 := r.Intn(100)
	this.TreeNonce = make([]byte, v5)
	for i := 0; i < v5; i++ {
		this.TreeNonce[i] = byte(r.Intn(256))
	}
	if r.Intn(10) != 0 {
		this.ClientTLS = NewPopulatedTLSConfig(r, easy)
	}
	if !easy && r.Intn(10) != 0 {
	}
	return this
}

type randyConfig interface {
	Float32() float32
	Float64() float64
	Int63() int64
	Int31() int32
	Uint32() uint32
	Intn(n int) int
}

func randUTF8RuneConfig(r randyConfig) rune {
	ru := r.Intn(62)
	if ru < 10 {
		return rune(ru + 48)
	} else if ru < 36 {
		return rune(ru + 55)
	}
	return rune(ru + 61)
}
func randStringConfig(r randyConfig) string {
	v6 := r.Intn(100)
	tmps := make([]rune, v6)
	for i := 0; i < v6; i++ {
		tmps[i] = randUTF8RuneConfig(r)
	}
	return string(tmps)
}
func randUnrecognizedConfig(r randyConfig, maxFieldNumber int) (dAtA []byte) {
	l := r.Intn(5)
	for i := 0; i < l; i++ {
		wire := r.Intn(4)
		if wire == 3 {
			wire = 5
		}
		fieldNumber := maxFieldNumber + r.Intn(100)
		dAtA = randFieldConfig(dAtA, r, fieldNumber, wire)
	}
	return dAtA
}
func randFieldConfig(dAtA []byte, r randyConfig, fieldNumber int, wire int) []byte {
	key := uint32(fieldNumber)<<3 | uint32(wire)
	switch wire {
	case 0:
		dAtA = encodeVarintPopulateConfig(dAtA, uint64(key))
		v7 := r.Int63()
		if r.Intn(2) == 0 {
			v7 *= -1
		}
		dAtA = encodeVarintPopulateConfig(dAtA, uint64(v7))
	case 1:
		dAtA = encodeVarintPopulateConfig(dAtA, uint64(key))
		dAtA = append(dAtA, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)))
	case 2:
		dAtA = encodeVarintPopulateConfig(dAtA, uint64(key))
		ll := r.Intn(100)
		dAtA = encodeVarintPopulateConfig(dAtA, uint64(ll))
		for j := 0; j < ll; j++ {
			dAtA = append(dAtA, byte(r.Intn(256)))
		}
	default:
		dAtA = encodeVarintPopulateConfig(dAtA, uint64(key))
		dAtA = append(dAtA, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)))
	}
	return dAtA
}
func encodeVarintPopulateConfig(dAtA []byte, v uint64) []byte {
	for v >= 1<<7 {
		dAtA = append(dAtA, uint8(uint64(v)&0x7f|0x80))
		v >>= 7
	}
	dAtA = append(dAtA, uint8(v))
	return dAtA
}
func (m *Config) Size() (n int) {
	var l int
	_ = l
	if len(m.Realms) > 0 {
		for _, e := range m.Realms {
			l = e.Size()
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	return n
}

func (m *RealmConfig) Size() (n int) {
	var l int
	_ = l
	l = len(m.RealmName)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if len(m.Domains) > 0 {
		for _, s := range m.Domains {
			l = len(s)
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	l = len(m.Addr)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	l = len(m.URL)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	l = len(m.VRFPublic)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.VerificationPolicy != nil {
		l = m.VerificationPolicy.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	l = m.EpochTimeToLive.Size()
	n += 1 + l + sovConfig(uint64(l))
	l = len(m.TreeNonce)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.ClientTLS != nil {
		l = m.ClientTLS.Size()
		n += 1 + l + sovConfig(uint64(l))
	}
	return n
}

func sovConfig(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozConfig(x uint64) (n int) {
	return sovConfig(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Config) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Config{`,
		`Realms:` + strings.Replace(fmt.Sprintf("%v", this.Realms), "RealmConfig", "RealmConfig", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *RealmConfig) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&RealmConfig{`,
		`RealmName:` + fmt.Sprintf("%v", this.RealmName) + `,`,
		`Domains:` + fmt.Sprintf("%v", this.Domains) + `,`,
		`Addr:` + fmt.Sprintf("%v", this.Addr) + `,`,
		`URL:` + fmt.Sprintf("%v", this.URL) + `,`,
		`VRFPublic:` + fmt.Sprintf("%v", this.VRFPublic) + `,`,
		`VerificationPolicy:` + strings.Replace(fmt.Sprintf("%v", this.VerificationPolicy), "AuthorizationPolicy", "AuthorizationPolicy", 1) + `,`,
		`EpochTimeToLive:` + strings.Replace(strings.Replace(this.EpochTimeToLive.String(), "Duration", "Duration", 1), `&`, ``, 1) + `,`,
		`TreeNonce:` + fmt.Sprintf("%v", this.TreeNonce) + `,`,
		`ClientTLS:` + strings.Replace(fmt.Sprintf("%v", this.ClientTLS), "TLSConfig", "TLSConfig", 1) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringConfig(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *Config) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Config: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Config: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Realms", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Realms = append(m.Realms, &RealmConfig{})
			if err := m.Realms[len(m.Realms)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *RealmConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: RealmConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RealmConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RealmName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.RealmName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Domains", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Domains = append(m.Domains, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addr", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Addr = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field URL", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.URL = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VRFPublic", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.VRFPublic = append(m.VRFPublic[:0], dAtA[iNdEx:postIndex]...)
			if m.VRFPublic == nil {
				m.VRFPublic = []byte{}
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VerificationPolicy", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.VerificationPolicy == nil {
				m.VerificationPolicy = &AuthorizationPolicy{}
			}
			if err := m.VerificationPolicy.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EpochTimeToLive", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.EpochTimeToLive.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field TreeNonce", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + byteLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.TreeNonce = append(m.TreeNonce[:0], dAtA[iNdEx:postIndex]...)
			if m.TreeNonce == nil {
				m.TreeNonce = []byte{}
			}
			iNdEx = postIndex
		case 9:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClientTLS", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ClientTLS == nil {
				m.ClientTLS = &TLSConfig{}
			}
			if err := m.ClientTLS.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipConfig(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthConfig
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowConfig
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipConfig(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthConfig = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig   = fmt.Errorf("proto: integer overflow")
)

func init() { proto1.RegisterFile("config.proto", fileDescriptorConfig) }

var fileDescriptorConfig = []byte{
	// 433 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x4c, 0x91, 0xb1, 0x6f, 0xd3, 0x40,
	0x14, 0xc6, 0xf3, 0x9a, 0x34, 0xc5, 0x97, 0x40, 0xaa, 0x63, 0x39, 0x45, 0x70, 0xb5, 0x3a, 0x59,
	0x48, 0xa4, 0x52, 0x61, 0x60, 0x42, 0x22, 0x45, 0x2c, 0x44, 0x55, 0x75, 0x35, 0xac, 0x96, 0xe3,
	0x5c, 0x92, 0x93, 0x6c, 0x5f, 0x64, 0x9f, 0x23, 0xc1, 0xc4, 0x9f, 0xc3, 0x9f, 0xc0, 0xc8, 0xd8,
	0xb1, 0x23, 0x53, 0x55, 0xdf, 0xc4, 0xd8, 0x11, 0x36, 0xe4, 0x77, 0x46, 0xc9, 0xe4, 0xf7, 0xfd,
	0xf4, 0x7d, 0xdf, 0xf9, 0xde, 0x91, 0x61, 0xa2, 0xf3, 0xa5, 0x5a, 0x4d, 0x36, 0x85, 0x36, 0x9a,
	0x1e, 0xe2, 0x67, 0xfc, 0x72, 0xa5, 0xcc, 0xba, 0x9a, 0x4f, 0x12, 0x9d, 0x9d, 0xad, 0xf4, 0x4a,
	0x9f, 0x21, 0x9e, 0x57, 0x4b, 0x54, 0x28, 0x70, 0x72, 0xa9, 0xf1, 0x30, 0x49, 0x95, 0xcc, 0x4d,
	0xab, 0x9e, 0x2c, 0xaa, 0x22, 0x36, 0x4a, 0xe7, 0xad, 0x1e, 0x99, 0xb4, 0xdc, 0x3f, 0xe4, 0xf4,
	0x35, 0xe9, 0x5f, 0xa0, 0xa6, 0x2f, 0x48, 0xbf, 0x90, 0x71, 0x9a, 0x95, 0x0c, 0xfc, 0x6e, 0x30,
	0x38, 0xa7, 0xce, 0x31, 0x11, 0x0d, 0x74, 0x1e, 0xd1, 0x3a, 0x4e, 0xff, 0x1e, 0x90, 0xc1, 0x1e,
	0xa7, 0xcf, 0x88, 0x87, 0xf2, 0x32, 0xce, 0x24, 0x03, 0x1f, 0x02, 0x4f, 0xec, 0x00, 0x65, 0xe4,
	0x68, 0xa1, 0xb3, 0x58, 0xe5, 0x25, 0x3b, 0xf0, 0xbb, 0x81, 0x27, 0xfe, 0x4b, 0x4a, 0x49, 0x2f,
	0x5e, 0x2c, 0x0a, 0xd6, 0xc5, 0x08, 0xce, 0xf4, 0x98, 0x74, 0x3f, 0x89, 0x19, 0xeb, 0x21, 0x6a,
	0xc6, 0xa6, 0xfd, 0xb3, 0xf8, 0x70, 0x55, 0xcd, 0x53, 0x95, 0xb0, 0x43, 0x1f, 0x82, 0xa1, 0xd8,
	0x01, 0xfa, 0x91, 0x3c, 0xdd, 0xca, 0x42, 0x2d, 0x55, 0x82, 0x17, 0x8d, 0x36, 0x3a, 0x55, 0xc9,
	0x17, 0xd6, 0xf7, 0x21, 0x18, 0x9c, 0x8f, 0xdb, 0x4b, 0xbc, 0xab, 0xcc, 0x5a, 0x17, 0xea, 0x2b,
	0x5a, 0xae, 0xd0, 0x21, 0xe8, 0x7e, 0xcc, 0x31, 0x3a, 0x25, 0x54, 0x6e, 0x74, 0xb2, 0x8e, 0x8c,
	0xca, 0x64, 0x64, 0x74, 0x94, 0xaa, 0xad, 0x64, 0x47, 0xd8, 0x35, 0x6a, 0xbb, 0xde, 0xb7, 0x2b,
	0x9d, 0xf6, 0x6e, 0xee, 0x4e, 0x3a, 0x62, 0x84, 0x81, 0x50, 0x65, 0x32, 0xd4, 0x33, 0xb5, 0x95,
	0xf4, 0x39, 0x21, 0xa6, 0x90, 0x32, 0xca, 0x75, 0x9e, 0x48, 0xf6, 0xc8, 0xfd, 0x6f, 0x43, 0x2e,
	0x1b, 0x40, 0xdf, 0x12, 0xe2, 0x9e, 0x28, 0x32, 0x69, 0xc9, 0x3c, 0xac, 0x3e, 0x6e, 0xab, 0xc3,
	0xd9, 0xb5, 0xdb, 0xe8, 0xf4, 0xb1, 0xbd, 0x3b, 0xf1, 0x2e, 0xd0, 0x17, 0xce, 0xae, 0x85, 0xe7,
	0x22, 0x61, 0x5a, 0x4e, 0xdf, 0xdc, 0xd6, 0xbc, 0xf3, 0xab, 0xe6, 0x9d, 0xfb, 0x9a, 0xc3, 0x43,
	0xcd, 0xe1, 0x4f, 0xcd, 0xe1, 0x9b, 0xe5, 0xf0, 0xdd, 0x72, 0xf8, 0x61, 0x39, 0xfc, 0xb4, 0x1c,
	0x6e, 0x2c, 0x87, 0x5b, 0xcb, 0xe1, 0xde, 0x72, 0xf8, 0x6d, 0x79, 0xe7, 0xc1, 0x72, 0x98, 0xf7,
	0xf1, 0x90, 0x57, 0xff, 0x02, 0x00, 0x00, 0xff, 0xff, 0xe6, 0xb9, 0x73, 0x88, 0x67, 0x02, 0x00,
	0x00,
}
