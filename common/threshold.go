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
