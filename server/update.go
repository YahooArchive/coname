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
	"github.com/yahoo/coname/proto"
	"golang.org/x/net/context"
)

// Update implements proto.E2EKS.UpdateServer
func (ks *Keyserver) Update(ctx context.Context, req *proto.UpdateRequest) (*proto.LookupProof, error) {
	// TODO: ask for username and verify index (and more validation)
	uid := genUID()
	ch := ks.wr.Wait(uid)
	ks.log.Propose(ctx, proto.MustMarshal(&proto.KeyserverStep{
		UID:    uid,
		Update: req,
	}))
	select {
	case <-ctx.Done():
		ks.wr.Notify(uid, nil)
		return nil, ctx.Err()
	case v := <-ch:
		if err, ok := v.(error); ok {
			return nil, err
		}
		return ks.Lookup(ctx, req.LookupParameters)
	}
}
