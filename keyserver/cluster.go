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

package keyserver

import (
	"sort"

	"github.com/yahoo/coname/proto"
	"golang.org/x/net/context"
)

// AcceptClusterChange can be used to tell this replica to accept any potential
// cluster membership change to replicas.
func (ks *Keyserver) AcceptClusterChange(ctx context.Context, replicas []*proto.Replica) error {
	uid := genUID()
	ch := ks.wr.Wait(uid)

	ks.setOurAcceptableClusterChange <- replicas
	ks.log.Propose(ctx, proto.MustMarshal(&proto.KeyserverStep{
		UID: uid, Type: &proto.KeyserverStep_AcceptableClusterChange{AcceptableClusterChange: &proto.AcceptableClusterChange{Replica: ks.replicaID, Cluster: replicas}}}))

	select {
	case <-ctx.Done():
		ks.wr.Notify(uid, nil)
		return ctx.Err()
	case v := <-ch:
		if v == nil {
			return nil
		}
		return v.(error)
	}
}

func replicaSetCanonical(s []*proto.Replica) (ret []*proto.Replica) {
	ret = append(ret, s...)
	sort.Sort(replicasByID(ret))
	for _, r := range ret {
		sort.Sort(pubkeysByID(r.PublicKeys))
	}
	return ret
}

type pubkeysByID []*proto.PublicKey

func (s pubkeysByID) Len() int           { return len(s) }
func (s pubkeysByID) Less(i, j int) bool { return proto.KeyID(s[i]) < proto.KeyID(s[j]) }
func (s pubkeysByID) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type replicasByID []*proto.Replica

func (s replicasByID) Len() int           { return len(s) }
func (s replicasByID) Less(i, j int) bool { return s[i].ID < s[j].ID }
func (s replicasByID) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func replicaSetsEquivalent(a, b []*proto.Replica) bool {
	if len(a) != len(b) {
		return false
	}
	aa := replicaSetCanonical(a)
	bb := replicaSetCanonical(b)
	for i := range aa {
		if !aa[i].Equal(bb[i]) {
			return false
		}
	}
	return true
}

func majority(nReplicas int) int {
	return nReplicas/2 + 1
}

// replicaSetMajorityPolicy deterministically generates the minimal
// representation of the proto.AuthorizationPolicy for a cluster of replicas.
func replicaSetMajorityPolicy(s []*proto.Replica) *proto.AuthorizationPolicy {
	s = replicaSetCanonical(s)
	quorum := proto.QuorumExpr{Threshold: uint32(majority(len(s)))}
	pubkeys := make(map[uint64]*proto.PublicKey)
	ret := &proto.AuthorizationPolicy{
		PublicKeys: pubkeys,
		PolicyType: &proto.AuthorizationPolicy_Quorum{Quorum: &quorum},
	}

	for _, r := range s {
		oneOfThisReplica := &proto.QuorumExpr{Threshold: 1}
		for _, pk := range r.PublicKeys {
			id := proto.KeyID(pk)
			oneOfThisReplica.Candidates = append(oneOfThisReplica.Candidates, id)

			if _, already := pubkeys[id]; already {
				panic("key id collision between trusted keys")
			}
			pubkeys[id] = pk
		}
		if len(oneOfThisReplica.Candidates) == 1 {
			quorum.Candidates = append(quorum.Candidates, oneOfThisReplica.Candidates[0])
		} else {
			quorum.Subexpressions = append(quorum.Subexpressions, oneOfThisReplica)
		}
	}
	return ret
}
