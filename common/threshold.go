package common

import "github.com/yahoo/coname/proto"

// MergeThresholdSignatures merges into ret all unique from signatures.
func MergeThresholdSignatures(ret *proto.ThresholdSignature, signatures ...*proto.ThresholdSignature) {
	has := make(map[uint32]struct{})
	for i := 0; i < len(ret.Signature) && i < len(ret.KeyIndex); i++ {
		has[ret.KeyIndex[i]] = struct{}{}
	}
	for _, sig := range signatures {
		for i := 0; i < len(sig.Signature) && i < len(sig.KeyIndex); i++ {
			idx := sig.KeyIndex[i]
			if _, already := has[idx]; already {
				continue
			}
			ret.KeyIndex = append(ret.KeyIndex, idx)
			ret.Signature = append(ret.Signature, sig.Signature[i])
			has[idx] = struct{}{}
		}
	}
}
