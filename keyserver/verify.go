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
	"encoding/binary"
	"fmt"
	"log"
	"math"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/keyserver/kv"
	"golang.org/x/net/context"
)

// VerifierStream implements the interfaceE2EKSVerification interface from proto/verifier.proto
func (ks *Keyserver) VerifierStream(rq *proto.VerifierStreamRequest, stream proto.E2EKSVerification_VerifierStreamServer) error {
	var step proto.VerifierStep // stack-allocate db read buffer
	for start, limit := rq.Start, saturatingAdd(rq.Start, rq.PageSize); start < limit; {
		// Try a kv.Range range scan first because it is the fastest. If this
		// does not satisfy the entire request (because the future entries have
		// not been generated yet), use ks.vmb to wait for new entries, falling
		// back to range scans when this thread fails to meet the timing
		// constraints of ks.vmb. Both methods of accessing verifier log
		// entries are surfaced here due to flow control and memory allocation
		// constraints: we cannot allow allocation of an unbounded queue.
		iter := ks.db.NewIterator(&kv.Range{Start: tableVerifierLog(start), Limit: tableVerifierLog(limit)})
		for ; iter.Next() && start < limit; start++ {
			select {
			case <-stream.Context().Done():
				iter.Release()
				return stream.Context().Err()
			default:
			}
			dbIdx := binary.BigEndian.Uint64(iter.Key()[1:])
			if dbIdx != start {
				log.Printf("ERROR: non-consecutive entries in verifier log (wanted %d, got %d)", start, dbIdx)
				iter.Release()
				return fmt.Errorf("internal error")
			}
			if err := step.Unmarshal(iter.Value()); err != nil {
				log.Printf("ERROR: invalid protobuf entry in verifier log (index %d)", start)
				iter.Release()
				return fmt.Errorf("internal error")
			}
			if err := stream.Send(&step); err != nil {
				iter.Release()
				return err
			}
			step.Reset()
		}
		iter.Release()
		if err := iter.Error(); err != nil {
			log.Printf("ERROR: range [tableVerifierLog(%d), tableVerifierLog(%d)) ended at %d (not included) with error %s", rq.Start, limit, start, err)
			return fmt.Errorf("internal error")
		}

		// the requested entries are not in the db yet, so let's try to collect
		// them from the vmb. ch=nil -> the desired log entry was sent after we
		// did the db range scan but before we called Receive -> it's in db now.
	vmbLoop:
		for ch := ks.vmb.Receive(start, limit); ch != nil && start < limit; start++ {
			select {
			case <-stream.Context().Done():
				return stream.Context().Err()
			case vmbStep, ok := <-ch: // declares new variable, a &const
				if !ok {
					// vmb closed the connection. This must be because this
					// client was slow and vmb does not wait for laggards.
					// This is okay though: if vmb does not have the step
					// anymore, the db must: let's get it from there.
					break vmbLoop
				}
				if err := stream.Send(vmbStep); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// PushRatification implements the interfaceE2EKSVerification interface from proto/verifier.proto
func (ks *Keyserver) PushRatification(ctx context.Context, r *proto.SignedEpochHead) (*proto.Nothing, error) {
	// FIXME: verify the ratifier signature (tricky: where do we keep verifier pk-s?)
	uid := genUID()
	ch := ks.wr.Wait(uid)
	ks.log.Propose(ctx, proto.MustMarshal(&proto.KeyserverStep{
		UID:            uid,
		VerifierSigned: r,
	}))
	select {
	case <-ctx.Done():
		ks.wr.Notify(uid, nil)
		return nil, ctx.Err()
	case <-ch:
		return nil, nil
	}
}

// verifierLogAppend censors an entry and prepares the commands to:
// 1) store it to local persistent storage
// 2) mark the log entry as used
// 3) share the new log entry with verifiers
// called from step: no io
func (ks *Keyserver) verifierLogAppend(m *proto.VerifierStep, rs *proto.ReplicaState, wb kv.Batch) func() {
	// m : *mut // RECURSIVE transfer of ownership
	// ks : &const // read-only
	// rs, wb : &mut
	wb.Put(tableVerifierLog(rs.NextIndexVerifier), proto.MustMarshal(m))
	rs.NextIndexVerifier++
	return func() {
		ks.vmb.Send(m)
	}
}

func saturatingAdd(a, b uint64) uint64 {
	ret := a + b
	if ret < a || ret < b {
		return math.MaxUint64
	}
	return ret
}
