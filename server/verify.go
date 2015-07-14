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

package server

import (
	"fmt"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"golang.org/x/net/context"
)

func (ks *Keyserver) VerifierStream(rq *proto.VerifierStreamRequest, ret proto.E2EKSVerification_VerifierStreamServer) error {
	return fmt.Errorf("VerifierStream not implemented")
}

func (ks *Keyserver) PushRatification(ctx context.Context, r *proto.SignedRatification) (*proto.Nothing, error) {
	return nil, fmt.Errorf("PushRatification not implemented")
}

var _ (proto.E2EKSVerificationServer) = (*Keyserver)(nil)

// verifierLogAppend censors an entry and prepares the commands to:
// 1) store it to local persistent storage
// 2) mark the log entry as used
// 3) share the new log entry with verifiers
func (ks *Keyserver) verifierLogAppend(m *proto.VerifierStep, rs *proto.ReplicaState, wb kv.Batch) func() {
	if m.EntryChanged != nil {
		m.EntryChanged.Profile = nil
	}
	wb.Put(tableVerifierLog(rs.NextIndexVerifier), proto.MustMarshal(m))
	rs.NextIndexVerifier++
	return func() {
		ks.vmb.Send(m)
	}
}
