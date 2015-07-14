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
	"encoding/binary"
	"fmt"
	"log"

	"github.com/yahoo/coname/proto"
	"github.com/yahoo/coname/server/kv"
	"golang.org/x/net/context"
)

// VerifierStream implements the interfaceE@EKSVerification interface from proto/verifier.proto
func (ks *Keyserver) VerifierStream(rq *proto.VerifierStreamRequest, stream proto.E2EKSVerification_VerifierStreamServer) error {
	// Try a kv.Range range scan first, because it is the fastest. If this does
	// not satisfy the entire request (because the future entries have not been
	// generated yet), use ks.vmb to wait for new entries, falling back to raw
	// kv.Get operations when this thread fails to meet the timing constraints
	// of ks.vmb. All three methods of accessing verifier log entries are
	// surfaced here due to flow control and memory allocation constraints: we
	// cannot allow allocation of an unbounded queue.
	idx, limit := rq.Start, rq.Limit
	rq = nil
	rnge := kv.Range{Start: tableVerifierLog(idx), Limit: tableVerifierLog(limit)}
	iter := ks.db.NewIterator(&rnge)
	var step proto.VerifierStep
	for ; iter.Next(); idx++ {
		select {
		case <-stream.Context().Done():
			return nil // TODO: what to do with context.Err()?
		default:
		}
		dbIdx := binary.BigEndian.Uint64(iter.Key()[1:])
		if dbIdx != idx {
			log.Printf("ERROR: non-consecutive entries in verifier log (index %d)", idx)
			return fmt.Errorf("internal error")
		}
		if err := step.Unmarshal(iter.Value()); err != nil {
			log.Printf("ERROR: invalid protobuf entry in verifier log (index %d)", idx)
			return fmt.Errorf("internal error")
		}
		if err := stream.Send(&step); err != nil {
			return nil // TODO: return err?
		}
		step.Reset()
	}
	iter.Release()
	if err := iter.Error(); err != nil && err != ks.db.ErrNotFound() {
		return err
	}

	// range scan exhausted: the log has not been created yet
subscribe_again:
	for idx < limit {
		select {
		case <-stream.Context().Done():
			return nil // TODO: what to do with context.Err()?
		default:
		}
		ch := ks.vmb.Receive(idx, limit)
	get_from_db:
		if ch == nil {
			stepBytes, err := ks.db.Get(tableVerifierLog(idx))
			if err != nil { // vmb has already handled idx -> idx must be in db
				log.Printf("ERROR: db read dailed: tableVerifierLog(%d)", idx)
				return fmt.Errorf("internal error")
			}
			if err := step.Unmarshal(stepBytes); err != nil {
				log.Printf("ERROR: invalid protobuf entry in verifier log (index %d)", idx)
				return fmt.Errorf("internal error")
			}
			if err := stream.Send(&step); err != nil {
				return nil // TODO: return err?
			}
			idx++
			step.Reset()
			continue subscribe_again
		}
		for {
			select {
			case <-stream.Context().Done():
				return nil // TODO: what to do with context.Err()?
			case vmbStep, ok := <-ch: // declares new variable, a &const
				if idx < limit && !ok {
					// This client was slow and vmb does not wait for laggards
					// This is okay though: if vmb does not have the step
					// anymore, the db must: let's get it from there
					ch = nil
					goto get_from_db
				}
				if err := stream.Send(vmbStep); err != nil {
					return nil // TODO: return err?
				}
				idx++
			}
		}
	}
	return nil
}

// PushRatification implements the interfaceE@EKSVerification interface from proto/verifier.proto
func (ks *Keyserver) PushRatification(ctx context.Context, r *proto.SignedRatification) (*proto.Nothing, error) {
	return nil, fmt.Errorf("PushRatification not implemented")
}

var _ (proto.E2EKSVerificationServer) = (*Keyserver)(nil)

// verifierLogAppend censors an entry and prepares the commands to:
// 1) store it to local persistent storage
// 2) mark the log entry as used
// 3) share the new log entry with verifiers
// called from step: no io
func (ks *Keyserver) verifierLogAppend(m *proto.VerifierStep, rs *proto.ReplicaState, wb kv.Batch) func() {
	// m : *mut // RECURSIVE transfer of ownership
	// ks : &const // read-only
	// rs, wb : &mut
	if m.EntryChanged != nil {
		m.EntryChanged.Profile = nil
	}
	wb.Put(tableVerifierLog(rs.NextIndexVerifier), proto.MustMarshal(m))
	rs.NextIndexVerifier++
	return func() {
		ks.vmb.Send(m)
	}
}
