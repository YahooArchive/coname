package common

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/yahoo/coname/proto"
)

// RatifierID computes the ID of a retifier by the hash-of-public-key convention.
func RatifierID(sv *proto.SignatureVerifier) uint64 {
	return binary.LittleEndian.Uint64(sha256.New().Sum(proto.MustMarshal(sv))[:8])
}
